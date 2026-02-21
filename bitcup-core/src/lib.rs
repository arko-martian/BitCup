use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};

const MAGIC: [u8; 4] = *b"BCUP";
pub const ENVELOPE_VERSION: u16 = 1;
pub const BLOB_SCHEMA_VERSION: u16 = 1;
pub const TREE_SCHEMA_VERSION: u16 = 1;
pub const COMMIT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectKind {
    Blob = 1,
    Tree = 2,
    Commit = 3,
    Tag = 4,
}

impl TryFrom<u8> for ObjectKind {
    type Error = EnvelopeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Blob),
            2 => Ok(Self::Tree),
            3 => Ok(Self::Commit),
            4 => Ok(Self::Tag),
            _ => Err(EnvelopeError::UnknownObjectKind(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectEnvelope {
    pub kind: ObjectKind,
    pub payload_schema_version: u16,
    pub payload: Vec<u8>,
}

impl ObjectEnvelope {
    pub fn new(kind: ObjectKind, payload_schema_version: u16, payload: Vec<u8>) -> Self {
        Self {
            kind,
            payload_schema_version,
            payload,
        }
    }

    pub fn encode_canonical(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u64;
        let mut out = Vec::with_capacity(4 + 2 + 1 + 2 + 8 + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        out.push(self.kind as u8);
        out.extend_from_slice(&self.payload_schema_version.to_be_bytes());
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        const HEADER_LEN: usize = 4 + 2 + 1 + 2 + 8;

        if bytes.len() < HEADER_LEN {
            return Err(EnvelopeError::Truncated {
                expected_at_least: HEADER_LEN,
                actual: bytes.len(),
            });
        }

        if bytes[0..4] != MAGIC {
            return Err(EnvelopeError::InvalidMagic);
        }

        let envelope_version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if envelope_version != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedEnvelopeVersion(envelope_version));
        }

        let kind = ObjectKind::try_from(bytes[6])?;
        let payload_schema_version = u16::from_be_bytes([bytes[7], bytes[8]]);
        let payload_len = u64::from_be_bytes([
            bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15], bytes[16],
        ]) as usize;

        let expected_total = HEADER_LEN + payload_len;
        if bytes.len() != expected_total {
            return Err(EnvelopeError::InvalidLength {
                expected: expected_total,
                actual: bytes.len(),
            });
        }

        let payload = bytes[HEADER_LEN..].to_vec();
        Ok(Self {
            kind,
            payload_schema_version,
            payload,
        })
    }

    pub fn object_id(&self) -> ObjectId {
        derive_object_id(&self.encode_canonical())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId([u8; 32]);

impl ObjectId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

pub fn derive_object_id(canonical_envelope_bytes: &[u8]) -> ObjectId {
    let hash = blake3::hash(canonical_envelope_bytes);
    ObjectId(*hash.as_bytes())
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlobPayload {
    pub bytes: Vec<u8>,
}

pub fn encode_blob(content: &[u8]) -> Result<ObjectEnvelope, BlobError> {
    let archived = BlobPayload {
        bytes: content.to_vec(),
    };
    let payload = rkyv::to_bytes::<rkyv::rancor::Error>(&archived)
        .map_err(|err| BlobError::Serialize(err.to_string()))?;
    Ok(ObjectEnvelope::new(
        ObjectKind::Blob,
        BLOB_SCHEMA_VERSION,
        payload.into_vec(),
    ))
}

pub fn decode_blob(envelope: &ObjectEnvelope) -> Result<Vec<u8>, BlobError> {
    if envelope.kind != ObjectKind::Blob {
        return Err(BlobError::WrongObjectKind(envelope.kind));
    }
    if envelope.payload_schema_version != BLOB_SCHEMA_VERSION {
        return Err(BlobError::UnsupportedSchemaVersion(
            envelope.payload_schema_version,
        ));
    }

    let archived = rkyv::access::<ArchivedBlobPayload, rkyv::rancor::Error>(&envelope.payload)
        .map_err(|err| BlobError::Deserialize(err.to_string()))?;
    let blob = rkyv::deserialize::<BlobPayload, rkyv::rancor::Error>(archived)
        .map_err(|err| BlobError::Deserialize(err.to_string()))?;
    Ok(blob.bytes)
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct TreeEntryPayload {
    pub path: String,
    pub mode: u32,
    pub blob_oid_hex: String,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct TreePayload {
    pub entries: Vec<TreeEntryPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotBlobObject {
    pub id: ObjectId,
    pub envelope: ObjectEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotResult {
    pub tree: ObjectEnvelope,
    pub blobs: Vec<SnapshotBlobObject>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    Walk(String),
    Io { path: PathBuf, message: String },
    SerializeTree(String),
    DeserializeTree(String),
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Walk(msg) => write!(f, "snapshot walk failed: {msg}"),
            Self::Io { path, message } => {
                write!(f, "snapshot io failed at {}: {message}", path.display())
            }
            Self::SerializeTree(msg) => write!(f, "tree serialization failed: {msg}"),
            Self::DeserializeTree(msg) => write!(f, "tree deserialization failed: {msg}"),
        }
    }
}

impl std::error::Error for SnapshotError {}

pub fn snapshot_tree(root: &Path) -> Result<SnapshotResult, SnapshotError> {
    let mut files = Vec::new();
    let walker = ignore::WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .require_git(false)
        .build();

    for entry in walker {
        let entry = entry.map_err(|e| SnapshotError::Walk(e.to_string()))?;
        let path = entry.path();

        if path == root.join(".bitcup") || path.starts_with(root.join(".bitcup")) {
            continue;
        }

        if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            continue;
        }

        files.push(path.to_path_buf());
    }

    files.sort_by(|a, b| normalize_rel_path(root, a).cmp(&normalize_rel_path(root, b)));

    let mut tree_entries = Vec::with_capacity(files.len());
    let mut blob_objects = Vec::with_capacity(files.len());

    for file in files {
        let rel_path = normalize_rel_path(root, &file);
        let bytes = fs::read(&file).map_err(|e| SnapshotError::Io {
            path: file.clone(),
            message: e.to_string(),
        })?;

        let blob_envelope =
            encode_blob(&bytes).map_err(|e| SnapshotError::SerializeTree(e.to_string()))?;
        let blob_oid = blob_envelope.object_id();
        let mode = detect_file_mode(&file)?;

        tree_entries.push(TreeEntryPayload {
            path: rel_path,
            mode,
            blob_oid_hex: blob_oid.to_string(),
        });
        blob_objects.push(SnapshotBlobObject {
            id: blob_oid,
            envelope: blob_envelope,
        });
    }

    let payload = TreePayload {
        entries: tree_entries,
    };
    let archived = rkyv::to_bytes::<rkyv::rancor::Error>(&payload)
        .map_err(|e| SnapshotError::SerializeTree(e.to_string()))?;
    let tree_envelope =
        ObjectEnvelope::new(ObjectKind::Tree, TREE_SCHEMA_VERSION, archived.into_vec());

    Ok(SnapshotResult {
        tree: tree_envelope,
        blobs: blob_objects,
    })
}

pub fn decode_tree(envelope: &ObjectEnvelope) -> Result<TreePayload, SnapshotError> {
    if envelope.kind != ObjectKind::Tree {
        return Err(SnapshotError::DeserializeTree(format!(
            "expected tree kind, got {:?}",
            envelope.kind
        )));
    }
    if envelope.payload_schema_version != TREE_SCHEMA_VERSION {
        return Err(SnapshotError::DeserializeTree(format!(
            "unsupported tree schema version: {}",
            envelope.payload_schema_version
        )));
    }

    let archived = rkyv::access::<ArchivedTreePayload, rkyv::rancor::Error>(&envelope.payload)
        .map_err(|e| SnapshotError::DeserializeTree(e.to_string()))?;
    rkyv::deserialize::<TreePayload, rkyv::rancor::Error>(archived)
        .map_err(|e| SnapshotError::DeserializeTree(e.to_string()))
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommitPayload {
    pub tree_oid_hex: String,
    pub parent_oids_hex: Vec<String>,
    pub author: String,
    pub committer: String,
    pub message: String,
    pub timestamp_unix_secs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitError {
    InvalidTreeOid,
    InvalidParentOid,
    Serialize(String),
    Deserialize(String),
    WrongObjectKind(ObjectKind),
    UnsupportedSchemaVersion(u16),
}

impl fmt::Display for CommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTreeOid => write!(f, "invalid tree oid hex"),
            Self::InvalidParentOid => write!(f, "invalid parent oid hex"),
            Self::Serialize(msg) => write!(f, "commit serialization failed: {msg}"),
            Self::Deserialize(msg) => write!(f, "commit deserialization failed: {msg}"),
            Self::WrongObjectKind(kind) => write!(f, "expected commit kind, got {:?}", kind),
            Self::UnsupportedSchemaVersion(version) => {
                write!(f, "unsupported commit schema version: {version}")
            }
        }
    }
}

impl std::error::Error for CommitError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitSignature {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningError {
    InvalidOid,
    InvalidPublicKey,
    InvalidSignature,
    VerificationFailed,
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOid => write!(f, "invalid oid hex"),
            Self::InvalidPublicKey => write!(f, "invalid public key bytes"),
            Self::InvalidSignature => write!(f, "invalid signature bytes"),
            Self::VerificationFailed => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for SigningError {}

pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn sign_commit_oid(oid_hex: &str, key: &SigningKey) -> Result<CommitSignature, SigningError> {
    if !is_valid_oid_hex(oid_hex) {
        return Err(SigningError::InvalidOid);
    }
    let signature: Signature = key.sign(oid_hex.as_bytes());
    Ok(CommitSignature {
        public_key: key.verifying_key().to_bytes(),
        signature: signature.to_bytes(),
    })
}

pub fn verify_commit_oid_signature(
    oid_hex: &str,
    signature: &CommitSignature,
) -> Result<(), SigningError> {
    if !is_valid_oid_hex(oid_hex) {
        return Err(SigningError::InvalidOid);
    }
    let verifying_key = VerifyingKey::from_bytes(&signature.public_key)
        .map_err(|_| SigningError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(&signature.signature);
    verifying_key
        .verify(oid_hex.as_bytes(), &signature)
        .map_err(|_| SigningError::VerificationFailed)
}

pub fn create_commit(
    tree_oid_hex: &str,
    parent_oids_hex: &[String],
    author: &str,
    committer: &str,
    message: &str,
    timestamp_unix_secs: i64,
) -> Result<ObjectEnvelope, CommitError> {
    if !is_valid_oid_hex(tree_oid_hex) {
        return Err(CommitError::InvalidTreeOid);
    }
    if !parent_oids_hex.iter().all(|p| is_valid_oid_hex(p)) {
        return Err(CommitError::InvalidParentOid);
    }

    let payload = CommitPayload {
        tree_oid_hex: tree_oid_hex.to_string(),
        parent_oids_hex: parent_oids_hex.to_vec(),
        author: author.to_string(),
        committer: committer.to_string(),
        message: message.to_string(),
        timestamp_unix_secs,
    };
    let archived = rkyv::to_bytes::<rkyv::rancor::Error>(&payload)
        .map_err(|e| CommitError::Serialize(e.to_string()))?;

    Ok(ObjectEnvelope::new(
        ObjectKind::Commit,
        COMMIT_SCHEMA_VERSION,
        archived.into_vec(),
    ))
}

pub fn decode_commit(envelope: &ObjectEnvelope) -> Result<CommitPayload, CommitError> {
    if envelope.kind != ObjectKind::Commit {
        return Err(CommitError::WrongObjectKind(envelope.kind));
    }
    if envelope.payload_schema_version != COMMIT_SCHEMA_VERSION {
        return Err(CommitError::UnsupportedSchemaVersion(
            envelope.payload_schema_version,
        ));
    }

    let archived = rkyv::access::<ArchivedCommitPayload, rkyv::rancor::Error>(&envelope.payload)
        .map_err(|e| CommitError::Deserialize(e.to_string()))?;
    let payload = rkyv::deserialize::<CommitPayload, rkyv::rancor::Error>(archived)
        .map_err(|e| CommitError::Deserialize(e.to_string()))?;

    if !is_valid_oid_hex(&payload.tree_oid_hex) {
        return Err(CommitError::InvalidTreeOid);
    }
    if !payload.parent_oids_hex.iter().all(|p| is_valid_oid_hex(p)) {
        return Err(CommitError::InvalidParentOid);
    }

    Ok(payload)
}

fn normalize_rel_path(root: &Path, file: &Path) -> String {
    let rel = file.strip_prefix(root).unwrap_or(file);
    rel.to_string_lossy().replace('\\', "/")
}

fn detect_file_mode(path: &Path) -> Result<u32, SnapshotError> {
    let metadata = fs::metadata(path).map_err(|e| SnapshotError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        return Ok(if mode & 0o111 != 0 {
            0o100755
        } else {
            0o100644
        });
    }

    #[cfg(not(unix))]
    {
        let _ = metadata;
        Ok(0o100644)
    }
}

fn is_valid_oid_hex(input: &str) -> bool {
    input.len() == 64 && input.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    InvalidMagic,
    UnsupportedEnvelopeVersion(u16),
    UnknownObjectKind(u8),
    Truncated {
        expected_at_least: usize,
        actual: usize,
    },
    InvalidLength {
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid envelope magic"),
            Self::UnsupportedEnvelopeVersion(v) => {
                write!(f, "unsupported envelope version: {v}")
            }
            Self::UnknownObjectKind(k) => write!(f, "unknown object kind: {k}"),
            Self::Truncated {
                expected_at_least,
                actual,
            } => write!(
                f,
                "truncated envelope: expected at least {expected_at_least} bytes, got {actual}"
            ),
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid envelope length: expected {expected} bytes, got {actual}"
                )
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobError {
    WrongObjectKind(ObjectKind),
    UnsupportedSchemaVersion(u16),
    Serialize(String),
    Deserialize(String),
}

impl fmt::Display for BlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongObjectKind(kind) => {
                write!(f, "expected blob object, got kind {:?}", kind)
            }
            Self::UnsupportedSchemaVersion(version) => {
                write!(f, "unsupported blob schema version: {version}")
            }
            Self::Serialize(msg) => write!(f, "failed to serialize blob payload: {msg}"),
            Self::Deserialize(msg) => write!(f, "failed to deserialize blob payload: {msg}"),
        }
    }
}

impl std::error::Error for BlobError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_encoding_layout_is_stable() {
        let env = ObjectEnvelope::new(ObjectKind::Blob, 7, vec![0xaa, 0xbb]);
        let encoded = env.encode_canonical();

        let expected = vec![
            b'B', b'C', b'U', b'P', // magic
            0x00, 0x01, // envelope version (u16 be)
            0x01, // kind blob
            0x00, 0x07, // payload schema version (u16 be)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // payload len (u64 be)
            0xaa, 0xbb, // payload
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn oid_is_deterministic_and_sensitive_to_change() {
        let a = ObjectEnvelope::new(ObjectKind::Blob, 1, b"hello".to_vec());
        let b = ObjectEnvelope::new(ObjectKind::Blob, 1, b"hello".to_vec());
        let c = ObjectEnvelope::new(ObjectKind::Blob, 2, b"hello".to_vec());

        assert_eq!(a.object_id(), b.object_id());
        assert_ne!(a.object_id(), c.object_id());
    }

    #[test]
    fn decode_roundtrip_succeeds() {
        let original = ObjectEnvelope::new(ObjectKind::Commit, 3, b"payload".to_vec());
        let encoded = original.encode_canonical();
        let decoded = ObjectEnvelope::decode_canonical(&encoded).expect("must decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_rejects_invalid_magic() {
        let mut encoded =
            ObjectEnvelope::new(ObjectKind::Blob, 1, vec![1, 2, 3]).encode_canonical();
        encoded[0] = b'X';
        let err = ObjectEnvelope::decode_canonical(&encoded).expect_err("must fail");
        assert_eq!(err, EnvelopeError::InvalidMagic);
    }

    #[test]
    fn decode_rejects_invalid_length() {
        let mut encoded =
            ObjectEnvelope::new(ObjectKind::Tree, 1, vec![1, 2, 3]).encode_canonical();
        encoded.pop();
        let err = ObjectEnvelope::decode_canonical(&encoded).expect_err("must fail");
        assert!(matches!(err, EnvelopeError::InvalidLength { .. }));
    }

    #[test]
    fn object_id_display_is_hex() {
        let env = ObjectEnvelope::new(ObjectKind::Blob, 1, b"abc".to_vec());
        let oid = env.object_id().to_string();
        assert_eq!(oid.len(), 64);
        assert!(oid.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn blob_rkyv_roundtrip_succeeds() {
        let original = b"bitcup-blob-data";
        let envelope = encode_blob(original).expect("encode must succeed");
        assert_eq!(envelope.kind, ObjectKind::Blob);
        assert_eq!(envelope.payload_schema_version, BLOB_SCHEMA_VERSION);

        let decoded = decode_blob(&envelope).expect("decode must succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn blob_roundtrip_survives_canonical_encode_decode() {
        let original = b"canonical-path";
        let envelope = encode_blob(original).expect("encode must succeed");
        let canonical = envelope.encode_canonical();
        let parsed = ObjectEnvelope::decode_canonical(&canonical).expect("must decode envelope");
        let decoded = decode_blob(&parsed).expect("must decode blob");
        assert_eq!(decoded, original);
    }

    #[test]
    fn blob_decode_rejects_wrong_object_kind() {
        let envelope = ObjectEnvelope::new(ObjectKind::Tree, BLOB_SCHEMA_VERSION, vec![1, 2, 3]);
        let err = decode_blob(&envelope).expect_err("must fail");
        assert!(matches!(err, BlobError::WrongObjectKind(ObjectKind::Tree)));
    }

    #[test]
    fn blob_decode_rejects_schema_version_mismatch() {
        let mut envelope = encode_blob(b"abc").expect("encode must succeed");
        envelope.payload_schema_version = BLOB_SCHEMA_VERSION + 1;
        let err = decode_blob(&envelope).expect_err("must fail");
        assert!(matches!(err, BlobError::UnsupportedSchemaVersion(_)));
    }

    #[test]
    fn blob_decode_rejects_truncated_payload() {
        let mut envelope = encode_blob(b"truncate-me").expect("encode must succeed");
        envelope.payload.pop();
        let err = decode_blob(&envelope).expect_err("must fail");
        assert!(matches!(err, BlobError::Deserialize(_)));
    }

    #[test]
    fn snapshot_tree_is_deterministic_and_sorted() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path();
        std::fs::create_dir_all(root.join("src")).expect("mkdir src");
        std::fs::write(root.join("src").join("z.txt"), b"z").expect("write z");
        std::fs::write(root.join("src").join("a.txt"), b"a").expect("write a");
        std::fs::write(root.join("root.txt"), b"r").expect("write root");

        let first = snapshot_tree(root).expect("snapshot first");
        let second = snapshot_tree(root).expect("snapshot second");
        assert_eq!(first.tree.object_id(), second.tree.object_id());

        let tree = decode_tree(&first.tree).expect("decode tree");
        let paths: Vec<_> = tree.entries.into_iter().map(|e| e.path).collect();
        assert_eq!(paths, vec!["root.txt", "src/a.txt", "src/z.txt"]);
    }

    #[test]
    fn snapshot_tree_respects_gitignore_and_skips_bitcup_dir() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path();
        std::fs::write(root.join(".gitignore"), "*.log\n").expect("write gitignore");
        std::fs::write(root.join("keep.txt"), b"ok").expect("write keep");
        std::fs::write(root.join("drop.log"), b"no").expect("write drop");
        std::fs::create_dir_all(root.join(".bitcup")).expect("mkdir .bitcup");
        std::fs::write(root.join(".bitcup").join("internal"), b"x").expect("write internal");

        let snapshot = snapshot_tree(root).expect("snapshot");
        let tree = decode_tree(&snapshot.tree).expect("decode tree");
        let paths: Vec<_> = tree.entries.into_iter().map(|e| e.path).collect();
        assert_eq!(paths, vec![".gitignore", "keep.txt"]);
    }

    #[test]
    fn commit_creation_and_decode_with_parent_linkage() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path();
        std::fs::write(root.join("a.txt"), b"hello").expect("write file");
        let snapshot = snapshot_tree(root).expect("snapshot");
        let tree_oid = snapshot.tree.object_id().to_string();

        let root_commit = create_commit(
            &tree_oid,
            &[],
            "Alice <alice@example.com>",
            "Alice <alice@example.com>",
            "initial",
            1_700_000_000,
        )
        .expect("create root commit");
        let root_oid = root_commit.object_id().to_string();

        let second_commit = create_commit(
            &tree_oid,
            std::slice::from_ref(&root_oid),
            "Alice <alice@example.com>",
            "Alice <alice@example.com>",
            "second",
            1_700_000_010,
        )
        .expect("create second commit");
        let decoded = decode_commit(&second_commit).expect("decode commit");
        assert_eq!(decoded.parent_oids_hex, vec![root_oid]);
        assert_eq!(decoded.tree_oid_hex, tree_oid);
    }

    #[test]
    fn commit_object_id_changes_when_parent_changes() {
        let fake_tree = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let parent_a =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
        let parent_b =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string();

        let commit_a = create_commit(
            fake_tree,
            std::slice::from_ref(&parent_a),
            "Alice",
            "Alice",
            "msg",
            1,
        )
        .expect("create commit a");
        let commit_b = create_commit(
            fake_tree,
            std::slice::from_ref(&parent_b),
            "Alice",
            "Alice",
            "msg",
            1,
        )
        .expect("create commit b");

        assert_ne!(commit_a.object_id(), commit_b.object_id());
    }

    #[test]
    fn commit_signature_sign_and_verify_roundtrip() {
        let oid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = generate_signing_key();
        let sig = sign_commit_oid(oid, &key).expect("sign");
        verify_commit_oid_signature(oid, &sig).expect("verify");
    }

    #[test]
    fn commit_signature_rejects_tampered_oid() {
        let oid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let key = generate_signing_key();
        let sig = sign_commit_oid(oid, &key).expect("sign");
        let tampered = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let err = verify_commit_oid_signature(tampered, &sig).expect_err("must fail");
        assert_eq!(err, SigningError::VerificationFailed);
    }

    #[test]
    fn commit_signature_rejects_invalid_oid_input() {
        let key = generate_signing_key();
        let err = sign_commit_oid("not-oid", &key).expect_err("must fail");
        assert_eq!(err, SigningError::InvalidOid);
    }
}
