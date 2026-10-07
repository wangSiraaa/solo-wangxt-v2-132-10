//! Offline export/import of already verified cache entries.
//!
//! A package is a small, explicit container rather than an archive with
//! filesystem names: the manifest contains object keys, strong validators,
//! segment boundaries and SHA-256 digests; payload records are addressed only
//! by their digest. Import verifies every length, boundary and digest before
//! opening a database transaction. Imported versions use private negative IDs,
//! so they cannot replace a version established on this machine and normal
//! upstream validation remains the only way to make bytes current.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use percent_encoding::percent_decode_str;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"RCPKG001";
const MANIFEST_DESC_LEN: usize = 36; // length(4) + digest(32)
const IO_CHUNK: usize = 64 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
/// Keep imported IDs in the SQLite i64 range and safely away from i64::MIN.
const MAX_IMPORTED_VERSIONS: i64 = 1_000_000_000;

#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("invalid cache package: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, PackError>;

fn invalid(message: impl Into<String>) -> PackError {
    PackError::Invalid(message.into())
}

fn checked_i64(value: u64, what: &str) -> Result<i64> {
    i64::try_from(value).map_err(|_| invalid(format!("{what} does not fit in SQLite integer")))
}

/// Reject the same unsafe raw/decoded path forms the proxy rejects. Package
/// paths are database keys, never extracted as paths, but accepting traversal
/// would still let a package describe objects outside the configured URL
/// namespace.
pub fn validate_object_path(path: &str) -> Result<()> {
    if !path.starts_with('/') || path.is_empty() {
        return Err(invalid("object path must be absolute"));
    }
    if path.contains('\0') {
        return Err(invalid("object path contains NUL"));
    }
    let path_before_query = path.split('?').next().unwrap_or(path);
    for raw in path_before_query.split('/') {
        if matches!(raw, ".." | ".") {
            return Err(invalid("traversal segment in object path"));
        }
        let decoded = percent_decode_str(raw).decode_utf8_lossy();
        if decoded == ".."
            || decoded == "."
            || decoded.contains('\\')
            || decoded.contains('\0')
            || decoded.chars().any(|c| c.is_control())
        {
            return Err(invalid("traversal or unsafe segment in object path"));
        }
    }
    Ok(())
}

fn validate_strong_etag(tag: &str) -> Result<()> {
    if tag.is_empty() {
        return Err(invalid("invalid strong ETag"));
    }
    let wire = format!("\"{tag}\"");
    let parsed = crate::etag::ETag::parse(&wire).ok_or_else(|| invalid("invalid strong ETag"))?;
    if parsed.weak || parsed.raw_tag != tag {
        return Err(invalid("invalid strong ETag"));
    }
    Ok(())
}

fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentManifest {
    pub start: u64,
    pub end: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionManifest {
    pub etag: String,
    pub last_modified: Option<i64>,
    pub total_length: Option<u64>,
    pub content_type: Option<String>,
    pub created_at: i64,
    pub blob_length: u64,
    pub segments: Vec<SegmentManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectManifest {
    pub path: String,
    pub versions: Vec<VersionManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    pub format: String,
    pub created_at: i64,
    pub objects: Vec<ObjectManifest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportAction {
    Imported,
    SkippedExisting,
}

#[derive(Debug, Clone)]
pub struct ImportedVersion {
    pub path: String,
    pub etag: String,
    pub version_id: i64,
    pub action: ImportAction,
}

#[derive(Debug, Clone, Default)]
pub struct ImportReport {
    pub versions: Vec<ImportedVersion>,
}

impl ImportReport {
    pub fn imported(&self) -> usize {
        self.versions
            .iter()
            .filter(|v| v.action == ImportAction::Imported)
            .count()
    }

    pub fn skipped(&self) -> usize {
        self.versions
            .iter()
            .filter(|v| v.action == ImportAction::SkippedExisting)
            .count()
    }
}

#[derive(Debug, Clone)]
struct StoredVersion {
    id: i64,
    etag: String,
    last_modified: Option<i64>,
    total_length: Option<u64>,
    content_type: Option<String>,
    created_at: i64,
}

#[derive(Debug, Clone)]
struct BlobSource {
    version_id: i64,
    start: u64,
    end: u64,
}

#[derive(Debug)]
struct PayloadForExport {
    length: u64,
    source: BlobSource,
}

fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn hash_file_range(path: &Path, start: u64, end: u64) -> Result<(String, u64)> {
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(start))?;
    let mut limited = (&mut f).take(end - start);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; IO_CHUNK];
    let mut copied = 0u64;
    loop {
        let n = limited.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        copied += n as u64;
    }
    if copied != end - start {
        return Err(invalid("blob ended before recorded segment"));
    }
    Ok((hex_encode(&hasher.finalize()), copied))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex_decode(value: &str) -> Result<[u8; 32]> {
    if !is_hex_sha256(value) {
        return Err(invalid("payload digest is not a SHA-256 hex string"));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| invalid("invalid hex digest"))?;
    }
    Ok(out)
}

fn db_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("range-cache.sqlite3")
}

fn blobs_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("blobs")
}

fn tmp_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("tmp")
}

fn blob_path(cache_dir: &Path, version_id: i64) -> PathBuf {
    blobs_path(cache_dir).join(format!("v{version_id}.bin"))
}

fn stored_versions(conn: &Connection, object_path: &str) -> Result<Vec<StoredVersion>> {
    let mut stmt = conn.prepare(
        "SELECT v.id, v.etag_tag, v.last_modified, v.total_length, v.content_type, v.created_at
         FROM versions v JOIN objects o ON o.id = v.object_id
         WHERE o.path = ?1 AND v.weak = 0 ORDER BY v.id",
    )?;
    let rows = stmt.query_map(params![object_path], |r| {
        let total: Option<i64> = r.get(3)?;
        Ok(StoredVersion {
            id: r.get(0)?,
            etag: r.get(1)?,
            last_modified: r.get(2)?,
            total_length: total.map(|v| v as u64),
            content_type: r.get(4)?,
            created_at: r.get(5)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Export all strong cached versions of the named objects. Weak validators are
/// never stored and therefore cannot be exported.
pub fn export_objects(cache_dir: &Path, output: &Path, object_paths: &[String]) -> Result<()> {
    if object_paths.is_empty() {
        return Err(invalid("export requires at least one object path"));
    }
    for path in object_paths {
        validate_object_path(path)?;
    }
    let mut requested_objects: Vec<&String> = object_paths.iter().collect();
    requested_objects.sort();
    requested_objects.dedup();

    let mut conn = crate::db::open(&db_path(cache_dir))?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let mut objects = Vec::new();
    let mut payloads: BTreeMap<String, PayloadForExport> = BTreeMap::new();

    for object_path in &requested_objects {
        let versions = stored_versions(&tx, object_path)?;
        if versions.is_empty() {
            return Err(invalid(format!(
                "no strong cached version for object {object_path}"
            )));
        }
        let mut manifest_versions = Vec::new();
        for version in &versions {
            validate_strong_etag(&version.etag)?;
            let segments_db = crate::db::covered_segments(&tx, version.id)?;
            if segments_db.windows(2).any(|w| segments_overlap(w[0], w[1])) {
                return Err(invalid("database contains overlapping segment metadata"));
            }

            let mut segments = Vec::new();
            let mut blob_length = 0u64;
            for &(start, end) in &segments_db {
                checked_i64(start, "segment start")?;
                checked_i64(end, "segment end")?;
                let (digest, length) =
                    hash_file_range(&blob_path(cache_dir, version.id), start, end)?;
                debug_assert_eq!(length, end - start);
                if let Some(existing) = payloads.get(&digest) {
                    if existing.length != length {
                        return Err(invalid("identical digests with different lengths"));
                    }
                } else {
                    payloads.insert(
                        digest.clone(),
                        PayloadForExport {
                            length,
                            source: BlobSource {
                                version_id: version.id,
                                start,
                                end,
                            },
                        },
                    );
                }
                blob_length = blob_length.max(end);
                segments.push(SegmentManifest {
                    start,
                    end,
                    sha256: digest,
                });
            }
            if let Some(total) = version.total_length {
                checked_i64(total, "total length")?;
                if blob_length > total {
                    return Err(invalid("segment extends past total length"));
                }
            }
            manifest_versions.push(VersionManifest {
                etag: version.etag.clone(),
                last_modified: version.last_modified,
                total_length: version.total_length,
                content_type: version.content_type.clone(),
                created_at: version.created_at,
                blob_length,
                segments,
            });
        }
        objects.push(ObjectManifest {
            path: object_path.as_str().to_string(),
            versions: manifest_versions,
        });
    }
    let manifest = PackageManifest {
        format: "range-cache-v1".into(),
        created_at: now_unix_seconds(),
        objects,
    };
    write_package(cache_dir, output, &manifest, &payloads)?;
    tx.commit()?;
    Ok(())
}

fn segments_overlap(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

fn write_package(
    cache_dir: &Path,
    output: &Path,
    manifest: &PackageManifest,
    payloads: &BTreeMap<String, PayloadForExport>,
) -> Result<()> {
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let tmp_name = format!(
        ".export-{}-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        payloads.len(),
    );
    let tmp_path = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(tmp_name);
    let result = write_package_inner(cache_dir, &tmp_path, output, manifest, payloads);
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

fn write_package_inner(
    cache_dir: &Path,
    tmp_path: &Path,
    output: &Path,
    manifest: &PackageManifest,
    payloads: &BTreeMap<String, PayloadForExport>,
) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp_path)?;
    let mut writer = BufWriter::new(file);
    writer.write_all(MAGIC)?;
    // Placeholder; rewritten after serializing the manifest.
    writer.write_all(&[0u8; MANIFEST_DESC_LEN])?;

    let manifest_bytes = serde_json::to_vec(manifest)?;
    if manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(invalid("manifest too large"));
    }
    let mut manifest_hasher = Sha256::new();
    manifest_hasher.update(&manifest_bytes);
    let manifest_digest: [u8; 32] = manifest_hasher.finalize().into();
    writer.write_all(&manifest_bytes)?;

    for (digest_hex, payload) in payloads {
        let digest = hex_decode(digest_hex)?;
        writer.write_all(&payload.length.to_le_bytes())?;
        writer.write_all(&digest)?;

        let mut input = File::open(blob_path(cache_dir, payload.source.version_id))?;
        input.seek(SeekFrom::Start(payload.source.start))?;
        let mut limited = (&mut input).take(payload.source.end - payload.source.start);
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; IO_CHUNK];
        let mut copied = 0u64;
        loop {
            let n = limited.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            writer.write_all(&buf[..n])?;
            copied += n as u64;
        }
        if copied != payload.length || hex_encode(&hasher.finalize()) != *digest_hex {
            return Err(invalid("cached bytes changed while exporting"));
        }
    }
    writer.flush()?;
    let mut f = writer
        .into_inner()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    f.sync_all()?;
    f.seek(SeekFrom::Start(0))?;
    f.seek(SeekFrom::Start(MAGIC.len() as u64))?;
    f.write_all(&(manifest_bytes.len() as u32).to_le_bytes())?;
    f.write_all(&manifest_digest)?;
    f.sync_all()?;
    drop(f);
    fs::rename(tmp_path, output)?;
    Ok(())
}

#[derive(Debug)]
struct VerifiedPackage {
    manifest: PackageManifest,
    /// Sorted digest -> staged payload path and exact length.
    payloads: BTreeMap<String, (PathBuf, u64)>,
    staging: StagingDir,
}

#[derive(Debug)]
struct StagingDir {
    path: PathBuf,
}

impl StagingDir {
    fn new(parent: &Path) -> Result<Self> {
        fs::create_dir_all(parent)?;
        for _ in 0..16 {
            let path = parent.join(format!(
                "import-staging-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(invalid("could not create unique import staging directory"))
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn validate_manifest(manifest: &PackageManifest) -> Result<BTreeMap<String, u64>> {
    if manifest.format != "range-cache-v1" {
        return Err(invalid("unsupported package format"));
    }
    if manifest.objects.is_empty() {
        return Err(invalid("package contains no objects"));
    }

    let mut payload_lengths: BTreeMap<String, u64> = BTreeMap::new();
    let mut seen_objects = HashMap::new();
    let mut seen_versions = HashMap::new();

    for object in &manifest.objects {
        validate_object_path(&object.path)?;
        if object.versions.is_empty() {
            return Err(invalid("package object has no versions"));
        }
        if seen_objects.insert(object.path.clone(), ()).is_some() {
            return Err(invalid("duplicate object in manifest"));
        }

        for version in &object.versions {
            validate_strong_etag(&version.etag)?;
            let key = (object.path.clone(), version.etag.clone());
            if seen_versions.insert(key, ()).is_some() {
                return Err(invalid("duplicate object version in manifest"));
            }
            checked_i64(version.blob_length, "blob length")?;
            if version.blob_length == 0 {
                return Err(invalid("exported blob has zero length"));
            }
            if let Some(content_type) = &version.content_type {
                if content_type.is_empty()
                    || http::HeaderValue::from_str(content_type).is_err()
                {
                    return Err(invalid("invalid content type in manifest"));
                }
            }
            let mut previous_end = 0u64;
            for segment in &version.segments {
                checked_i64(segment.start, "segment start")?;
                checked_i64(segment.end, "segment end")?;
                if segment.start >= segment.end {
                    return Err(invalid("empty or backwards segment"));
                }
                if segment.start < previous_end {
                    return Err(invalid("overlapping or unsorted segments"));
                }
                if segment.end > version.blob_length {
                    return Err(invalid("segment extends past blob length"));
                }
                if let Some(total) = version.total_length {
                    checked_i64(total, "total length")?;
                    if segment.end > total {
                        return Err(invalid("segment extends past total length"));
                    }
                }
                if !is_hex_sha256(&segment.sha256) {
                    return Err(invalid("segment digest is not SHA-256 hex"));
                }
                previous_end = segment.end;
            }
            if version.segments.is_empty() {
                return Err(invalid("version contains no verified segments"));
            }
            for segment in &version.segments {
                let len = segment.end - segment.start;
                if let Some(existing) = payload_lengths.get(&segment.sha256) {
                    if *existing != len {
                        return Err(invalid("same digest declared with different lengths"));
                    }
                } else {
                    payload_lengths.insert(segment.sha256.clone(), len);
                }
            }
        }
    }
    Ok(payload_lengths)
}

fn read_exact_digest(file: &mut File) -> Result<[u8; 32]> {
    let mut digest = [0u8; 32];
    file.read_exact(&mut digest)?;
    Ok(digest)
}

fn stage_package(package: &Path, cache_dir: &Path) -> Result<VerifiedPackage> {
    let mut file = File::open(package)?;
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(invalid("bad package magic"));
    }
    let mut len_bytes = [0u8; 4];
    file.read_exact(&mut len_bytes)?;
    let manifest_len = u64::from(u32::from_le_bytes(len_bytes));
    if manifest_len == 0 || manifest_len > MAX_MANIFEST_BYTES {
        return Err(invalid("bad manifest length"));
    }
    let expected_manifest_digest = read_exact_digest(&mut file)?;

    let mut manifest_bytes = vec![0u8; manifest_len as usize];
    file.read_exact(&mut manifest_bytes)?;
    let mut hasher = Sha256::new();
    hasher.update(&manifest_bytes);
    if hasher.finalize().as_slice() != expected_manifest_digest {
        return Err(invalid("manifest digest mismatch"));
    }
    let manifest: PackageManifest = serde_json::from_slice(&manifest_bytes)?;
    let expected_payloads = validate_manifest(&manifest)?;

    let staging = StagingDir::new(&tmp_path(cache_dir))?;
    let mut staged = BTreeMap::new();
    let mut last_digest: Option<String> = None;

    for (digest_hex, length) in &expected_payloads {
        let mut record_len = [0u8; 8];
        file.read_exact(&mut record_len)?;
        let record_len = u64::from_le_bytes(record_len);
        if record_len != *length {
            return Err(invalid("payload length disagrees with manifest"));
        }
        let record_digest = read_exact_digest(&mut file)?;
        if hex_encode(&record_digest) != *digest_hex {
            return Err(invalid("payload records are missing or out of order"));
        }
        if let Some(previous) = &last_digest {
            if previous >= digest_hex {
                return Err(invalid("payload records are not sorted"));
            }
        }
        last_digest = Some(digest_hex.clone());

        let stage_path = staging.path.join(format!("{digest_hex}.part"));
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stage_path)?;
        let mut source: &File = &file;
        let mut remaining = *length;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; IO_CHUNK];
        while remaining > 0 {
            let want = remaining.min(IO_CHUNK as u64) as usize;
            let n = source.read(&mut buf[..want])?;
            if n == 0 {
                return Err(invalid("payload ended early"));
            }
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        out.sync_all()?;
        drop(out);
        if hex_encode(&hasher.finalize()) != *digest_hex {
            return Err(invalid("payload digest mismatch"));
        }
        staged.insert(digest_hex.clone(), (stage_path, *length));
    }

    let mut trailing = [0u8];
    match file.read(&mut trailing)? {
        0 => {}
        _ => return Err(invalid("unexpected trailing package bytes")),
    }
    Ok(VerifiedPackage {
        manifest,
        payloads: staged,
        staging,
    })
}

#[derive(Debug)]
struct ExistingVersion {
    id: i64,
    last_modified: Option<i64>,
    total_length: Option<u64>,
    content_type: Option<String>,
    segments: Vec<(u64, u64)>,
}

fn existing_version(
    conn: &Connection,
    object_path: &str,
    etag: &str,
) -> Result<Option<ExistingVersion>> {
    let row = conn
        .query_row(
            "SELECT v.id, v.last_modified, v.total_length, v.content_type
             FROM versions v JOIN objects o ON o.id = v.object_id
             WHERE o.path = ?1 AND v.etag_tag = ?2",
            params![object_path, etag],
            |r| {
                let total: Option<i64> = r.get(2)?;
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    total.map(|v| v as u64),
                    r.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((id, last_modified, total_length, content_type)) = row else {
        return Ok(None);
    };
    Ok(Some(ExistingVersion {
        id,
        last_modified,
        total_length,
        content_type,
        segments: crate::db::covered_segments(conn, id)?,
    }))
}

fn same_existing_version(existing: &ExistingVersion, wanted: &VersionManifest) -> bool {
    let segments: Vec<(u64, u64)> = wanted.segments.iter().map(|s| (s.start, s.end)).collect();
    existing.last_modified == wanted.last_modified
        && existing.total_length == wanted.total_length
        && existing.content_type == wanted.content_type
        && existing.segments == segments
}

fn allocate_negative_id(conn: &Connection) -> Result<i64> {
    conn.execute(
        "INSERT INTO import_id_sequence(name, next) VALUES ('version', 0)
         ON CONFLICT(name) DO NOTHING",
        [],
    )?;
    conn.execute(
        "UPDATE import_id_sequence SET next = next + 1 WHERE name = 'version'",
        [],
    )?;
    let sequence: i64 = conn.query_row(
        "SELECT next FROM import_id_sequence WHERE name = 'version'",
        [],
        |r| r.get(0),
    )?;
    if sequence > MAX_IMPORTED_VERSIONS {
        return Err(invalid("imported version limit exceeded"));
    }
    Ok(i64::MIN + sequence)
}

struct PreparedBlob {
    tmp: PathBuf,
    dst: PathBuf,
}

fn copy_verified_segment(
    stage: &Path,
    out: &mut File,
    start: u64,
    length: u64,
    expected: &str,
) -> Result<()> {
    out.seek(SeekFrom::Start(start))?;
    let mut input = BufReader::new(File::open(stage)?);
    let mut limited = (&mut input).take(length);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; IO_CHUNK];
    let mut copied = 0u64;
    while copied < length {
        let n = limited.read(&mut buf)?;
        if n == 0 {
            return Err(invalid("staged payload ended early"));
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n])?;
        copied += n as u64;
    }
    if hex_encode(&hasher.finalize()) != expected {
        return Err(invalid("staged payload digest changed before commit"));
    }
    Ok(())
}

fn prepare_blob(
    cache_dir: &Path,
    verified: &VerifiedPackage,
    version_id: i64,
    version: &VersionManifest,
) -> Result<PreparedBlob> {
    let dst = blob_path(cache_dir, version_id);
    if dst.try_exists()? {
        return Err(invalid("refusing to overwrite existing version blob"));
    }
    let tmp = blobs_path(cache_dir).join(format!(
        "import-v{version_id}-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .open(&tmp)?;
    for segment in &version.segments {
        let (stage, length) = verified
            .payloads
            .get(&segment.sha256)
            .ok_or_else(|| invalid("manifest references missing payload"))?;
        if *length != segment.end - segment.start {
            return Err(invalid("payload length disagrees with segment boundary"));
        }
        copy_verified_segment(stage, &mut file, segment.start, *length, &segment.sha256)?;
    }
    file.sync_all()?;
    let metadata = file.metadata()?;
    drop(file);
    if metadata.len() != version.blob_length {
        return Err(invalid("temporary blob length does not match metadata"));
    }
    Ok(PreparedBlob { tmp, dst })
}

fn insert_version(
    conn: &Connection,
    object_id: i64,
    version_id: i64,
    version: &VersionManifest,
) -> Result<()> {
    let total_length = version
        .total_length
        .map(|total| checked_i64(total, "total length"))
        .transpose()?;
    conn.execute(
        "INSERT INTO versions
             (id, object_id, etag_tag, weak, last_modified, total_length, content_type, created_at)
         VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?7)",
        params![
            version_id,
            object_id,
            version.etag,
            version.last_modified,
            total_length,
            version.content_type,
            version.created_at,
        ],
    )?;
    let mut stmt = conn.prepare("INSERT INTO segments(version_id,start,end) VALUES (?1,?2,?3)")?;
    for segment in &version.segments {
        stmt.execute(params![
            version_id,
            checked_i64(segment.start, "segment start")?,
            checked_i64(segment.end, "segment end")?,
        ])?;
    }
    Ok(())
}

fn cleanup_new_versions(conn: &Connection, ids: &[i64]) {
    for id in ids {
        let _ = conn.execute("DELETE FROM versions WHERE id = ?1", params![id]);
    }
}

/// Verify and import a package. Verification and staging happen before any
/// database row is inserted. Existing exact versions are skipped; a package
/// whose version of an object differs from a local version with the same
/// strong ETag makes the entire import fail without changing the local cache.
pub fn import_package(cache_dir: &Path, package: &Path) -> Result<ImportReport> {
    fs::create_dir_all(blobs_path(cache_dir))?;
    fs::create_dir_all(tmp_path(cache_dir))?;
    let mut conn = crate::db::open(&db_path(cache_dir))?;
    let verified = stage_package(package, cache_dir)?;

    let mut prepared = Vec::new();
    let mut new_ids = Vec::new();
    let mut report = ImportReport::default();

    let commit_result: Result<()> = (|| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for object in &verified.manifest.objects {
            tx.execute(
                "INSERT INTO objects(path) VALUES (?1) ON CONFLICT(path) DO NOTHING",
                params![object.path],
            )?;
            let object_id: i64 = tx.query_row(
                "SELECT id FROM objects WHERE path = ?1",
                params![object.path],
                |r| r.get(0),
            )?;

            // All imported rows get private IDs below i64::MIN+limit; they
            // are never confused with locally fetched positive IDs.
            let mut to_import = Vec::new();
            for version in &object.versions {
                match existing_version(&tx, &object.path, &version.etag)? {
                    Some(existing) => {
                        if !same_existing_version(&existing, version) {
                            return Err(invalid(format!(
                                "refusing to overwrite different local version {} {}",
                                object.path, version.etag
                            )));
                        }
                        report.versions.push(ImportedVersion {
                            path: object.path.clone(),
                            etag: version.etag.clone(),
                            version_id: existing.id,
                            action: ImportAction::SkippedExisting,
                        });
                    }
                    None => to_import.push(version),
                }
            }

            let mut ids_for_new = Vec::new();
            for _ in &to_import {
                ids_for_new.push(allocate_negative_id(&tx)?);
            }

            for (version, version_id) in to_import.into_iter().zip(ids_for_new) {
                insert_version(&tx, object_id, version_id, version)?;
                let ready = prepare_blob(cache_dir, &verified, version_id, version)?;
                prepared.push(ready);
                new_ids.push(version_id);
                report.versions.push(ImportedVersion {
                    path: object.path.clone(),
                    etag: version.etag.clone(),
                    version_id,
                    action: ImportAction::Imported,
                });
            }
        }
        tx.commit()?;
        Ok(())
    })();

    if let Err(err) = commit_result {
        for ready in &prepared {
            let _ = fs::remove_file(&ready.tmp);
        }
        return Err(err);
    }

    // Metadata is committed first. Publishing independent new blob files is
    // the only remaining step. If that fails, remove just the newly imported
    // rows; pre-existing rows and blobs were never touched.
    if let Err(err) = publish_blobs(&conn, &prepared, &new_ids) {
        for ready in &prepared {
            let _ = fs::remove_file(&ready.tmp);
            let _ = fs::remove_file(&ready.dst);
        }
        return Err(err);
    }
    drop(verified.staging);
    Ok(report)
}

fn publish_blobs(conn: &Connection, prepared: &[PreparedBlob], new_ids: &[i64]) -> Result<()> {
    for ready in prepared {
        if ready.dst.try_exists()? {
            cleanup_new_versions(conn, new_ids);
            return Err(invalid("refusing to overwrite existing version blob"));
        }
        if let Err(e) = fs::rename(&ready.tmp, &ready.dst) {
            cleanup_new_versions(conn, new_ids);
            return Err(e.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_and_backslash_paths() {
        assert!(validate_object_path("/obj/alpha").is_ok());
        assert!(validate_object_path("/obj/../etc/passwd").is_err());
        assert!(validate_object_path("/obj/%2e%2e/etc").is_err());
        assert!(validate_object_path("/obj/a%5Cb").is_err());
        assert!(validate_object_path("../obj/alpha").is_err());
        assert!(validate_object_path("/obj/alpha?q=x..y").is_ok());
    }

    #[test]
    fn accepts_only_strong_etag_tags() {
        assert!(validate_strong_etag("alpha-v1").is_ok());
        assert!(validate_strong_etag("").is_err());
        assert!(validate_strong_etag("a\"b").is_err());
    }
}
