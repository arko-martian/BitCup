use std::fmt;

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};

const MAGIC: [u8; 4] = *b"BCUP";
pub const ENVELOPE_VERSION: u16 = 1;
pub const BLOB_SCHEMA_VERSION: u16 = 1;

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
}
