//! Offline cache packages for moving verified historical representations
//! between isolated test machines.
//!
//! A package contains exactly one strong-ETag version of one object. Its
//! manifest records the object key, strong validator, representation metadata,
//! sorted half-open segments and the SHA-256 digest of every segment. The
//! payload bytes are concatenated after the manifest. A root SHA-256 over the
//! header, manifest and every payload is kept in the fixed trailer; changing
//! either metadata or bytes therefore invalidates the package.
//!
//! Import is conservative. Package data is first streamed to a temporary
//! sparse blob while both segment and root digests are checked. Only then is
//! metadata inserted in SQLite and the temp blob renamed into place. Imported
//! rows are marked historical and are never allowed to replace a different
//! local version of the same object.

use std::path::{Path, PathBuf};

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::store::BlobStore;

const MAGIC: &[u8; 8] = b"RCPKG001";
const TRAILER_MAGIC: &[u8; 8] = b"RCPKEND1";
const TRAILER_LEN: u64 = 48;
const IO_CHUNK: usize = 1024 * 1024;
const MAX_MANIFEST: u64 = 64 * 1024 * 1024;

/// Result of importing one package into a cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportOutcome {
    /// Metadata and blob were committed as a new historical version.
    Imported { version_id: i64 },
    /// The same object and exact strong ETag already existed locally. Nothing
    /// was overwritten.
    SameVersionAlreadyPresent,
}

/// Failure while exporting or validating/importing an offline package.
#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    #[error("package I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("metadata store failure: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("invalid package manifest: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid package: {0}")]
    Invalid(String),
    #[error("no cached strong version matches the requested object")]
    NotFound,
    #[error("object already has a local version with a different ETag")]
    DifferentVersionExists,
}

impl PackageError {
    fn invalid(msg: impl Into<String>) -> Self {
        PackageError::Invalid(msg.into())
    }
}

/// Manifest metadata and segment map. Only strong versions can be packaged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    pub format: u32,
    pub path: String,
    /// ETag tag without surrounding quotes.
    pub etag_tag: String,
    pub last_modified: Option<i64>,
    pub total_length: Option<u64>,
    pub content_type: Option<String>,
    /// Export-time version timestamp; preserved only as history ordering.
    pub created_at: i64,
    pub segments: Vec<PackageSegment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageSegment {
    pub start: u64,
    pub end: u64,
    /// Lower-case hex SHA-256 of exactly `[start, end)`.
    pub sha256: String,
}

/// Validate the object key embedded in a package. The key uses the same form
/// as proxy metadata: an absolute path with an optional `?query`.
pub fn validate_object_path(path: &str) -> Result<(), String> {
    if path.is_empty() || !path.starts_with('/') {
        return Err("object path must be absolute".into());
    }
    if path.len() > 4096
        || path.chars().any(|c| c.is_control())
        || path.contains('\\')
    {
        return Err("object path is too long or contains a control character".into());
    }
    let path_part = path.split_once('?').map(|(p, _)| p).unwrap_or(path);
    for segment in path_part.split('/') {
        if matches!(segment, ".." | ".") {
            return Err("traversal segment in object path".into());
        }
        let decoded = percent_decode_str(segment).decode_utf8_lossy();
        if decoded == ".." || decoded == "." || decoded.contains('\\') || decoded.contains('\0') {
            return Err("decoded traversal or separator in object path".into());
        }
    }
    Ok(())
}

fn valid_strong_tag(tag: &str) -> bool {
    let wire = format!("\"{tag}\"");
    matches!(crate::etag::ETag::parse(&wire), Some(t) if !t.weak && t.raw_tag == tag)
        && !tag.contains(['\\', '"'])
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate_manifest(m: &PackageManifest) -> Result<(), PackageError> {
    if m.format != 1 {
        return Err(PackageError::invalid("unsupported package format"));
    }
    validate_object_path(&m.path).map_err(PackageError::invalid)?;
    if !valid_strong_tag(&m.etag_tag) {
        return Err(PackageError::invalid("manifest ETag is not a strong validator"));
    }
    if m.created_at < 0 {
        return Err(PackageError::invalid("negative created_at"));
    }
    if let Some(v) = m.last_modified {
        if v < 0 {
            return Err(PackageError::invalid("negative Last-Modified timestamp"));
        }
    }
    if let Some(ct) = &m.content_type {
        if ct.contains('\0') {
            return Err(PackageError::invalid("NUL in Content-Type"));
        }
    }
    if m.segments.is_empty() {
        return Err(PackageError::invalid("package contains no segments"));
    }

    let mut previous_end = 0u64;
    for (i, seg) in m.segments.iter().enumerate() {
        if seg.start >= seg.end {
            return Err(PackageError::invalid(format!("segment {i} has empty/inverted bounds")));
        }
        if i > 0 && seg.start < previous_end {
            // Adjacent segments (start == previous_end) are allowed.
            return Err(PackageError::invalid(format!("segment {i} overlaps an earlier segment")));
        }
        if seg.end > i64::MAX as u64 {
            return Err(PackageError::invalid(format!("segment {i} exceeds database offset range")));
        }
        if let Some(total) = m.total_length {
            if seg.end > total {
                return Err(PackageError::invalid(format!("segment {i} exceeds total_length")));
            }
        }
        if !is_sha256_hex(&seg.sha256) {
            return Err(PackageError::invalid(format!("segment {i} digest is not SHA-256 hex")));
        }
        previous_end = seg.end;
    }
    Ok(())
}

async fn read_u64<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<u64> {
    let mut bytes = [0u8; 8];
    r.read_exact(&mut bytes).await?;
    Ok(u64::from_le_bytes(bytes))
}

fn hash_u64(hash: &mut Sha256, value: u64) {
    hash.update(value.to_le_bytes());
}

/// Export one cached strong version into `output`.
///
/// `etag_tag` identifies an exact tag. If absent, the latest strong version
/// of `object_path` is exported. Every referenced interval is read from the
/// local blob and hashed while packaging, so a damaged source cache cannot be
/// exported as if it were verified.
pub async fn export_version(
    cache_dir: &Path,
    object_path: &str,
    etag_tag: Option<&str>,
    output: &Path,
) -> Result<(), PackageError> {
    validate_object_path(object_path).map_err(PackageError::invalid)?;
    let conn = crate::db::open(&cache_dir.join("range-cache.sqlite3"))?;
    let version = match etag_tag {
        Some(tag) => crate::db::find_version(&conn, object_path, tag)?,
        None => crate::db::latest_strong_version(&conn, object_path)?,
    }
    .ok_or(PackageError::NotFound)?;
    if version.weak {
        return Err(PackageError::invalid("stored validator is not strong"));
    }
    let segments = crate::db::covered_segments(&conn, version.id)?;
    if segments.is_empty() {
        return Err(PackageError::NotFound);
    }

    // Manifest segments are validated before hashing the source blob.
    let mut packaged_segments = Vec::with_capacity(segments.len());
    let mut payload_total = 0u64;
    for (start, end) in &segments {
        if *end > i64::MAX as u64 || start >= end {
            return Err(PackageError::invalid("local segment has invalid bounds"));
        }
        if let Some(total) = version.total_length {
            if *end > total {
                return Err(PackageError::invalid("local segment exceeds total_length"));
            }
        }
        payload_total = payload_total
            .checked_add(end - start)
            .ok_or_else(|| PackageError::invalid("package payload is too large"))?;
        packaged_segments.push(PackageSegment {
            start: *start,
            end: *end,
            // Replaced with the actual digest while streaming below.
            sha256: String::new(),
        });
    }

    let store = BlobStore::new(cache_dir).await?;
    let blob_path = store.blob_path_for(version.id);
    let metadata = fs::metadata(&blob_path).await?;
    if !metadata.is_file() {
        return Err(PackageError::invalid("source blob path is not a regular file"));
    }
    let max_end = segments.last().map(|(_, end)| *end).unwrap_or(0);
    if metadata.len() < max_end {
        return Err(PackageError::invalid("source blob shorter than segment metadata"));
    }

    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).await?;
    let temp_path = unique_temp_path(parent, "export").await?;
    let mut output_file = OutputTempFile::create(&temp_path).await?;
    let result = async {
        let mut root = Sha256::new();
        output_file.file.write_all(MAGIC).await?;
        root.update(MAGIC);

        // Manifest bytes are written after source verification. Build the
        // final manifest by reading and hashing every segment first.
        let mut blob = fs::File::open(&blob_path).await?;
        let mut chunk = vec![0u8; IO_CHUNK];
        for (idx, (start, end)) in segments.iter().copied().enumerate() {
            blob.seek(std::io::SeekFrom::Start(start)).await?;
            let mut remaining = end - start;
            let mut digest = Sha256::new();
            while remaining > 0 {
                let take = std::cmp::min(IO_CHUNK as u64, remaining) as usize;
                blob.read_exact(&mut chunk[..take]).await?;
                digest.update(&chunk[..take]);
                remaining -= take as u64;
            }
            packaged_segments[idx].sha256 = hex_lower(digest.finalize());
        }
        drop(blob);

        let manifest = PackageManifest {
            format: 1,
            path: object_path.to_string(),
            etag_tag: version.etag_tag.clone(),
            last_modified: version.last_modified,
            total_length: version.total_length,
            content_type: version.content_type.clone(),
            created_at: version.created_at,
            segments: packaged_segments,
        };
        validate_manifest(&manifest)?;
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        if manifest_bytes.len() as u64 > MAX_MANIFEST {
            return Err(PackageError::invalid("manifest is too large"));
        }

        let manifest_len = manifest_bytes.len() as u64;
        output_file.write_u64(manifest_len).await?;
        hash_u64(&mut root, manifest_len);
        output_file.file.write_all(&manifest_bytes).await?;
        root.update(&manifest_bytes);

        let mut blob = fs::File::open(&blob_path).await?;
        let mut declared_total = 0u64;
        for (start, end) in segments.iter().copied() {
            let len = end - start;
            blob.seek(std::io::SeekFrom::Start(start)).await?;
            output_file.write_u64(len).await?;
            hash_u64(&mut root, len);

            let mut remaining = len;
            while remaining > 0 {
                let take = std::cmp::min(IO_CHUNK as u64, remaining) as usize;
                blob.read_exact(&mut chunk[..take]).await?;
                output_file.file.write_all(&chunk[..take]).await?;
                root.update(&chunk[..take]);
                remaining -= take as u64;
            }
            declared_total = declared_total
                .checked_add(len)
                .ok_or_else(|| PackageError::invalid("package payload overflow"))?;
        }
        if declared_total != payload_total {
            return Err(PackageError::invalid("payload length changed during export"));
        }

        let root_digest = root.finalize();
        output_file.file.write_all(&root_digest).await?;
        output_file.write_u64(payload_total).await?;
        output_file.file.write_all(TRAILER_MAGIC).await?;
        output_file.persist(output).await?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            output_file.cleanup().await;
            Err(e)
        }
    }
}

/// Validate and import a package into `cache_dir`.
///
/// The entire item is rejected if any digest, manifest field, boundary or
/// payload length is wrong. On success, metadata is committed together with a
/// blob placed through a temporary file and final rename.
pub async fn import_package(
    cache_dir: &Path,
    package_path: &Path,
) -> Result<ImportOutcome, PackageError> {
    let store = BlobStore::new(cache_dir).await?;
    let staged = verify_to_staging(cache_dir, package_path).await?;
    let manifest = staged.manifest.clone();

    let mut conn = crate::db::open(&cache_dir.join("range-cache.sqlite3"))?;
    let mut tx = conn.transaction()?;
    if crate::db::find_version(&mut tx, &manifest.path, &manifest.etag_tag)?.is_some() {
        // Exactly the same strong version is already known. Treat import as
        // idempotent but never replace its potentially locally acquired blob.
        rollback(tx);
        staged.discard().await;
        return Ok(ImportOutcome::SameVersionAlreadyPresent);
    }
    if crate::db::find_observed_version(&mut tx, &manifest.path)?.is_some() {
        rollback(tx);
        staged.discard().await;
        return Err(PackageError::DifferentVersionExists);
    }

    let intervals: Vec<(u64, u64)> = manifest
        .segments
        .iter()
        .map(|s| (s.start, s.end))
        .collect();
    let version_id = crate::db::insert_historical_version(
        &mut tx,
        &manifest.path,
        &manifest.etag_tag,
        manifest.last_modified,
        manifest.total_length,
        manifest.content_type.as_deref(),
        manifest.created_at,
        &intervals,
    )?;
    let final_path = store.blob_path_for(version_id);
    if fs::metadata(&final_path).await.is_ok() {
        rollback(tx);
        staged.discard().await;
        return Err(PackageError::invalid("target blob path already exists"));
    }
    if let Err(e) = staged.persist(&final_path).await {
        let _ = fs::remove_file(&final_path).await;
        rollback(tx);
        return Err(e);
    }
    if let Err(e) = tx.commit() {
        let _ = fs::remove_file(&final_path).await;
        return Err(PackageError::Db(e));
    }
    Ok(ImportOutcome::Imported { version_id })
}

fn rollback(tx: rusqlite::Transaction<'_>) {
    let _ = tx.rollback();
}

struct VerifiedStaging {
    manifest: PackageManifest,
    file: Option<StagingFile>,
}

impl VerifiedStaging {
    async fn discard(self) {
        if let Some(file) = self.file {
            file.cleanup().await;
        }
    }

    async fn persist(mut self, dst: &Path) -> std::io::Result<()> {
        let file = self.file.take().unwrap();
        file.persist(dst).await?;
        Ok(())
    }
}

impl Drop for VerifiedStaging {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = std::fs::remove_file(&file.path);
        }
    }
}

async fn verify_to_staging(
    cache_dir: &Path,
    package_path: &Path,
) -> Result<VerifiedStaging, PackageError> {
    let mut pkg = fs::File::open(package_path).await?;
    let file_len = pkg.metadata().await?.len();
    if file_len < 16 + TRAILER_LEN + 17 {
        return Err(PackageError::invalid("file shorter than header/manifest/trailer"));
    }

    let mut magic = [0u8; 8];
    pkg.read_exact(&mut magic).await?;
    if &magic != MAGIC {
        return Err(PackageError::invalid("bad package magic"));
    }
    let manifest_len_raw = read_u64(&mut pkg).await?;
    let manifest_len = usize::try_from(manifest_len_raw)
        .map_err(|_| PackageError::invalid("manifest length exceeds platform range"))?;
    if manifest_len == 0 || manifest_len_raw > MAX_MANIFEST {
        return Err(PackageError::invalid("manifest length out of range"));
    }
    let payload_area = file_len
        .checked_sub(16 + manifest_len as u64 + TRAILER_LEN)
        .ok_or_else(|| PackageError::invalid("manifest length exceeds file"))?;

    let mut manifest_bytes = vec![0u8; manifest_len];
    pkg.read_exact(&mut manifest_bytes).await?;
    let manifest: PackageManifest = serde_json::from_slice(&manifest_bytes)?;
    validate_manifest(&manifest)?;

    let mut trailer = [0u8; TRAILER_LEN as usize];
    pkg.seek(std::io::SeekFrom::Start(file_len - TRAILER_LEN))
        .await?;
    pkg.read_exact(&mut trailer).await?;
    let stored_root: [u8; 32] = trailer[0..32].try_into().unwrap();
    let stored_payload_total = u64::from_le_bytes(trailer[32..40].try_into().unwrap());
    if &trailer[40..48] != TRAILER_MAGIC {
        return Err(PackageError::invalid("bad trailer magic"));
    }

    let declared_payload: u64 = manifest
        .segments
        .iter()
        .map(|s| s.end - s.start)
        .fold(Some(0u64), |acc, len| {
            acc.and_then(|v| v.checked_add(len))
        })
        .ok_or_else(|| PackageError::invalid("payload length overflow"))?;
    let segment_count = u64::try_from(manifest.segments.len()).map_err(|_| {
        PackageError::invalid("too many segments")
    })?;
    let framing_area = declared_payload
        .checked_add(
            segment_count
                .checked_mul(8)
                .ok_or_else(|| PackageError::invalid("payload framing length overflow"))?,
        )
        .ok_or_else(|| PackageError::invalid("payload framing length overflow"))?;
    if stored_payload_total != declared_payload || payload_area != framing_area {
        return Err(PackageError::invalid(
            "payload length does not match manifest, trailer and file boundaries",
        ));
    }

    let tmp_dir = cache_dir.join("tmp");
    fs::create_dir_all(&tmp_dir).await?;
    let temp_path = unique_temp_path(&tmp_dir, "import").await?;
    let staging_path = temp_path.clone();
    let mut staging = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&temp_path)
        .await?;
    let blob_end = manifest.segments.last().map(|s| s.end).unwrap_or(0);

    let result: Result<(), PackageError> = async {
        staging.set_len(blob_end).await?;
        let mut root = Sha256::new();
        root.update(MAGIC);
        hash_u64(&mut root, manifest_len as u64);
        root.update(&manifest_bytes);

        let mut chunk = vec![0u8; IO_CHUNK];
        for seg in &manifest.segments {
            let len = seg.end - seg.start;
            let actual_payload_len = read_u64(&mut pkg).await?;
            if actual_payload_len != len {
                return Err(PackageError::invalid(format!(
                    "payload length for [{},{}) is not its segment length",
                    seg.start, seg.end
                )));
            }
            hash_u64(&mut root, len);

            staging
                .seek(std::io::SeekFrom::Start(seg.start))
                .await?;
            let mut digest = Sha256::new();
            let mut remaining = len;
            while remaining > 0 {
                let take = std::cmp::min(IO_CHUNK as u64, remaining) as usize;
                pkg.read_exact(&mut chunk[..take]).await?;
                staging.write_all(&chunk[..take]).await?;
                digest.update(&chunk[..take]);
                root.update(&chunk[..take]);
                remaining -= take as u64;
            }
            let actual = hex_lower(&digest.finalize());
            if actual != seg.sha256 {
                return Err(PackageError::invalid(format!(
                    "digest mismatch for segment [{},{})",
                    seg.start, seg.end
                )));
            }
        }

        let mut next_byte = [0u8; 1];
        match pkg.read(&mut next_byte).await {
            Ok(0) => {}
            _ => return Err(PackageError::invalid("unexpected bytes after payloads")),
        }
        if root.finalize().as_slice() != stored_root {
            return Err(PackageError::invalid("root digest mismatch"));
        }
        staging.flush().await?;
        staging.sync_all().await?;
        drop(staging);
        Ok(())
    }
    .await;

    if let Err(e) = result {
        let _ = fs::remove_file(&staging_path).await;
        return Err(e);
    }

    Ok(VerifiedStaging {
        manifest,
        file: Some(StagingFile {
            path: staging_path,
        }),
    })
}

struct StagingFile {
    path: PathBuf,
}

impl StagingFile {
    async fn cleanup(self) {
        let _ = fs::remove_file(&self.path).await;
    }

    async fn persist(self, dst: &Path) -> std::io::Result<()> {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::rename(&self.path, dst).await
    }
}

impl Drop for StagingFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct OutputTempFile {
    path: PathBuf,
    file: fs::File,
}

impl OutputTempFile {
    async fn create(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .read(true)
            .open(path)
            .await?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    async fn write_u64(&mut self, value: u64) -> std::io::Result<()> {
        self.file.write_all(&value.to_le_bytes()).await
    }

    async fn persist(&mut self, dst: &Path) -> std::io::Result<()> {
        self.file.flush().await?;
        self.file.sync_all().await?;
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::rename(&self.path, dst).await
    }

    async fn cleanup(self) {
        drop(self.file);
        let _ = fs::remove_file(&self.path).await;
    }
}

async fn unique_temp_path(dir: &Path, prefix: &str) -> std::io::Result<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(dir.join(format!(
        "{prefix}-{}-{}-{n}.tmp",
        std::process::id(),
        nanos
    )))
}

fn hex_lower(bytes: impl AsRef<[u8]>) -> String {
    let mut s = String::with_capacity(bytes.as_ref().len() * 2);
    for b in bytes.as_ref() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_requires_sorted_nonoverlapping_segments() {
        let digest = "0".repeat(64);
        let mut manifest = PackageManifest {
            format: 1,
            path: "/obj/alpha".into(),
            etag_tag: "alpha-v1".into(),
            last_modified: None,
            total_length: Some(100),
            content_type: None,
            created_at: 1,
            segments: vec![
                PackageSegment {
                    start: 0,
                    end: 20,
                    sha256: digest.clone(),
                },
                PackageSegment {
                    start: 10,
                    end: 30,
                    sha256: digest.clone(),
                },
            ],
        };
        assert!(validate_manifest(&manifest).is_err());

        manifest.segments[1].start = 20;
        assert!(validate_manifest(&manifest).is_ok(), "adjacent segments are valid");

        manifest.segments[1].start = 30;
        assert!(validate_manifest(&manifest).is_ok(), "gapped segments are valid");
    }

    #[test]
    fn malformed_etag_is_rejected() {
        let mut manifest = PackageManifest {
            format: 1,
            path: "/obj/weak".into(),
            etag_tag: "weak".into(),
            last_modified: None,
            total_length: None,
            content_type: None,
            created_at: 1,
            segments: vec![PackageSegment {
                start: 0,
                end: 1,
                sha256: "0".repeat(64),
            }],
        };
        assert!(validate_manifest(&manifest).is_ok());
        manifest.etag_tag = "bad\"tag".into();
        assert!(validate_manifest(&manifest).is_err());
    }
}
