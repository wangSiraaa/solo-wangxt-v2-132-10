#![cfg(feature = "test-support")]

mod common;

use common::*;
use range_cache_proxy::package;
use range_cache_proxy::support;
use tempfile::TempDir;

async fn proxy_get(proxy: &str, path: &str, headers: &[(&str, &str)]) -> reqwest::Response {
    let mut rb = reqwest::Client::new().get(format!("{proxy}{path}"));
    for (k, v) in headers {
        rb = rb.header(*k, *v);
    }
    rb.send().await.unwrap()
}

fn read_package(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

fn manifest_len(pkg: &[u8]) -> usize {
    u64::from_le_bytes(pkg[8..16].try_into().unwrap()) as usize
}

fn flip_at(path: &std::path::Path, offset: usize) {
    let mut bytes = std::fs::read(path).unwrap();
    bytes[offset] ^= 0xff;
    std::fs::write(path, bytes).unwrap();
}

fn version_count(cache: &std::path::Path) -> usize {
    let conn = rusqlite::Connection::open(cache.join("range-cache.sqlite3")).unwrap();
    conn.query_row("SELECT COUNT(*) FROM versions", [], |r| r.get::<_, i64>(0))
        .unwrap() as usize
}

fn blob_digests(cache: &std::path::Path) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(cache.join("blobs")).unwrap() {
        let entry = entry.unwrap();
        let bytes = std::fs::read(entry.path()).unwrap();
        out.insert(entry.file_name().to_string_lossy().into_owned(), sha256_hex(&bytes));
    }
    out
}

#[tokio::test]
async fn empty_cache_imports_package_and_revalidates_before_and_after_upstream_change() {
    let source = spawn_env().await;
    let len = 120_000usize;
    reset_stats(&source).await;

    let warm = proxy_get(&source.proxy, "/obj/mutable", &[]).await;
    assert_eq!(warm.status(), 200);
    let pkg = source.cache_dir.path().join("mutable-v0.rcpkg");
    package::export_version(
        source.cache_dir.path(),
        "/obj/mutable",
        Some("mutable-v0"),
        &pkg,
    )
    .await
    .unwrap();

    let destination = TempDir::new().unwrap();
    assert_eq!(
        package::import_package(destination.path(), &pkg).await.unwrap(),
        package::ImportOutcome::Imported { version_id: 1 }
    );
    // Re-importing the exact version is idempotent and never replaces bytes.
    assert_eq!(
        package::import_package(destination.path(), &pkg).await.unwrap(),
        package::ImportOutcome::SameVersionAlreadyPresent
    );

    let dst_proxy = spawn_proxy(&source.upstream_base, destination.path()).await;
    reset_stats(&source).await;

    let v0 = support::mutable_bytes(0, len);
    let resp = proxy_get(&dst_proxy, "/obj/mutable", &[("Range", "bytes=100-199")]).await;
    assert_eq!(resp.status(), 206);
    assert_eq!(hdr(&resp, "etag"), Some("\"mutable-v0\""));
    let body = resp.bytes().await.unwrap();
    assert_eq!(sha256_hex(&body), sha256_hex(&v0[100..200]));
    // The import is history only: a 304 still confirms the current upstream
    // version, and that confirmation transfers no object bytes.
    let st = stats_for(&source, "mutable").await;
    assert_eq!(st["bytes_sent"], 0);
    assert_eq!(st["requests"], 1);

    let roll = source
        .client
        .post(format!("{}/obj/mutable", source.upstream))
        .send()
        .await
        .unwrap();
    assert_eq!(roll.status(), 200);
    let v1 = support::mutable_bytes(1, len);

    let resp = proxy_get(&dst_proxy, "/obj/mutable", &[("Range", "bytes=100-199")]).await;
    assert_eq!(resp.status(), 206);
    assert_eq!(
        hdr(&resp, "etag"),
        Some("\"mutable-v1\""),
        "upstream change must not be answered with imported old bytes"
    );
    let body = resp.bytes().await.unwrap();
    assert_eq!(sha256_hex(&body), sha256_hex(&v1[100..200]));
    assert_ne!(sha256_hex(&body), sha256_hex(&v0[100..200]));

    // Once the current version exists locally, importing the old package
    // cannot replace or shadow it.
    assert!(matches!(
        package::import_package(destination.path(), &pkg).await,
        Err(package::PackageError::DifferentVersionExists)
    ));
    let resp = proxy_get(&dst_proxy, "/obj/mutable", &[("Range", "bytes=0-9")]).await;
    assert_eq!(hdr(&resp, "etag"), Some("\"mutable-v1\""));
}

#[tokio::test]
async fn tampered_payload_or_manifest_rejects_entire_package_without_changing_cache() {
    let source = spawn_env().await;
    let warm = proxy_get(&source.proxy, "/obj/alpha", &[]).await;
    assert_eq!(warm.status(), 200);
    let valid_pkg = source.cache_dir.path().join("alpha.rcpkg");
    package::export_version(
        source.cache_dir.path(),
        "/obj/alpha",
        Some("alpha-v1"),
        &valid_pkg,
    )
    .await
    .unwrap();
    let valid = read_package(&valid_pkg);
    let mlen = manifest_len(&valid);

    let byte_pkg_dir = TempDir::new().unwrap();
    let byte_pkg = byte_pkg_dir.path().join("bytes.rcpkg");
    std::fs::copy(&valid_pkg, &byte_pkg).unwrap();
    let tiny_proxy = spawn_proxy(&source.upstream_base, byte_pkg_dir.path()).await;
    let tiny = proxy_get(&tiny_proxy, "/obj/tiny", &[]).await;
    assert_eq!(tiny.status(), 200);
    let before_versions = version_count(byte_pkg_dir.path());
    let before_blobs = blob_digests(byte_pkg_dir.path());
    // First byte of the first payload: 16-byte fixed header + manifest + 8.
    flip_at(&byte_pkg, 16 + mlen + 8);
    assert!(package::import_package(byte_pkg_dir.path(), &byte_pkg)
        .await
        .is_err());
    assert_eq!(version_count(byte_pkg_dir.path()), before_versions);
    assert_eq!(blob_digests(byte_pkg_dir.path()), before_blobs);

    let meta_pkg_dir = TempDir::new().unwrap();
    let meta_pkg = meta_pkg_dir.path().join("meta.rcpkg");
    std::fs::copy(&valid_pkg, &meta_pkg).unwrap();
    let alpha_proxy = spawn_proxy(&source.upstream_base, meta_pkg_dir.path()).await;
    let alpha = proxy_get(&alpha_proxy, "/obj/alpha", &[]).await;
    assert_eq!(alpha.status(), 200);
    let before_versions = version_count(meta_pkg_dir.path());
    let before_blobs = blob_digests(meta_pkg_dir.path());
    let mut manifest_package = read_package(&meta_pkg);
    let format_pos = manifest_package
        .windows(b"\"format\":1".len())
        .position(|w| w == b"\"format\":1")
        .unwrap();
    manifest_package[format_pos + b"\"format\":".len()] = b'2';
    std::fs::write(&meta_pkg, manifest_package).unwrap();
    assert!(package::import_package(meta_pkg_dir.path(), &meta_pkg)
        .await
        .is_err());
    assert_eq!(version_count(meta_pkg_dir.path()), before_versions);
    assert_eq!(blob_digests(meta_pkg_dir.path()), before_blobs);
}

#[tokio::test]
async fn partial_segment_package_preserves_offsets_and_digest() {
    let source = spawn_env().await;
    let expected = support::object_bytes("alpha-v1", 300_000);
    reset_stats(&source).await;

    let warm = proxy_get(&source.proxy, "/obj/alpha", &[("Range", "bytes=1000-1999")]).await;
    assert_eq!(warm.status(), 206);
    let pkg = source.cache_dir.path().join("alpha-partial.rcpkg");
    package::export_version(source.cache_dir.path(), "/obj/alpha", None, &pkg)
        .await
        .unwrap();

    let destination = TempDir::new().unwrap();
    package::import_package(destination.path(), &pkg)
        .await
        .unwrap();
    let proxy = spawn_proxy(&source.upstream_base, destination.path()).await;
    let resp = proxy_get(&proxy, "/obj/alpha", &[("Range", "bytes=1000-1999")]).await;
    assert_eq!(resp.status(), 206);
    assert_eq!(hdr(&resp, "etag"), Some("\"alpha-v1\""));
    let body = resp.bytes().await.unwrap();
    assert_eq!(sha256_hex(&body), sha256_hex(&expected[1000..2000]));
}

#[tokio::test]
async fn traversal_paths_in_package_manifest_are_rejected() {
    for bad in [
        "../etc/passwd",
        "/../etc/passwd",
        "/obj/%2e%2e/x",
        "/obj/..\\x",
        "/obj/x\0y",
    ] {
        assert!(package::validate_object_path(bad).is_err(), "{bad}");
    }
    for good in ["/obj/alpha", "/obj/a?x=../y", "/obj/%61lpha", "/a/b/c"] {
        assert!(package::validate_object_path(good).is_ok(), "{good}");
    }
}
