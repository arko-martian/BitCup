use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use bitcup_core::{CommitSignature, ObjectEnvelope, ObjectId, verify_commit_oid_signature};
use fd_lock::RwLock;
use redb::{Database, TableDefinition};
use tempfile::NamedTempFile;
use thiserror::Error;

pub const BITCUP_DIR: &str = ".bitcup";

#[derive(Debug, Clone)]
pub struct RepoLayout {
    pub root: PathBuf,
    pub bitcup_dir: PathBuf,
    pub objects_dir: PathBuf,
    pub objects_tmp_dir: PathBuf,
    pub refs_heads_dir: PathBuf,
    pub index_dir: PathBuf,
    pub locks_dir: PathBuf,
    pub head_file: PathBuf,
    pub config_file: PathBuf,
}

#[derive(Debug, Error)]
pub enum InitRepoError {
    #[error("repository root does not exist: {0}")]
    MissingRoot(PathBuf),
    #[error("repository already initialized: {0}")]
    AlreadyInitialized(PathBuf),
    #[error("io error while initializing repository at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Error)]
pub enum OpenRepoError {
    #[error("repository root does not exist: {0}")]
    MissingRoot(PathBuf),
    #[error("not a bitcup repository (missing .bitcup): {0}")]
    MissingBitcupDir(PathBuf),
}

const REF_CACHE_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("refs_cache");
const COMMIT_GRAPH_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("commit_graph");

pub struct MetadataStore {
    db: Database,
}

#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("metadata backend error during {op}: {message}")]
    Backend { op: &'static str, message: String },
}

#[derive(Debug, Error)]
pub enum RefUpdateError {
    #[error("invalid reference name: {0}")]
    InvalidRefName(String),
    #[error("invalid oid hex")]
    InvalidOid,
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("lock error: {0}")]
    Lock(String),
    #[error("signature required by policy")]
    SignatureRequired,
    #[error("invalid ref signature: {0}")]
    InvalidSignature(String),
}

#[derive(Debug, Error)]
pub enum ObjectStoreError {
    #[error("invalid oid hex")]
    InvalidOid,
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("decode error: {0}")]
    Decode(String),
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions {
    pub rebuild_index: bool,
    pub require_signed_refs: bool,
}

#[derive(Debug, Default, Clone)]
pub struct VerifyReport {
    pub object_count: usize,
    pub ref_count: usize,
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid object filename at {path}")]
    InvalidObjectPath { path: PathBuf },
    #[error("invalid object id format: {0}")]
    InvalidOid(String),
    #[error("object decode failed for {oid}: {message}")]
    Decode { oid: String, message: String },
    #[error("object id mismatch for {path}: expected {expected}, got {actual}")]
    OidMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error("invalid ref contents in {path}")]
    InvalidRef { path: PathBuf },
    #[error("missing object referenced by ref {ref_name}: {oid}")]
    MissingRefObject { ref_name: String, oid: String },
    #[error("metadata error: {0}")]
    Metadata(String),
    #[error("missing signature for ref {ref_name}")]
    MissingRefSignature { ref_name: String },
    #[error("invalid signature for ref {ref_name}: {message}")]
    InvalidRefSignature { ref_name: String, message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefSignaturePolicy {
    Optional,
    RequireValidSignature,
}

pub fn init_repo(root: impl AsRef<Path>) -> Result<RepoLayout, InitRepoError> {
    let root = root.as_ref();
    if !root.exists() {
        return Err(InitRepoError::MissingRoot(root.to_path_buf()));
    }

    let bitcup_dir = root.join(BITCUP_DIR);
    if bitcup_dir.exists() {
        return Err(InitRepoError::AlreadyInitialized(bitcup_dir));
    }

    let objects_dir = bitcup_dir.join("objects");
    let objects_tmp_dir = objects_dir.join("tmp");
    let refs_heads_dir = bitcup_dir.join("refs").join("heads");
    let refs_signatures_dir = bitcup_dir.join("refs-signatures");
    let index_dir = bitcup_dir.join("index");
    let locks_dir = bitcup_dir.join("locks");
    let head_file = bitcup_dir.join("HEAD");
    let config_file = bitcup_dir.join("config.toml");

    create_dir(&bitcup_dir)?;
    create_dir(&objects_dir)?;
    create_dir(&objects_tmp_dir)?;
    create_dir(&refs_heads_dir)?;
    create_dir(&refs_signatures_dir)?;
    create_dir(&index_dir)?;
    create_dir(&locks_dir)?;

    write_new_file(&head_file, b"ref: refs/heads/main\n")?;
    write_new_file(
        &config_file,
        b"format_version = 1\ndefault_branch = \"main\"\n",
    )?;

    Ok(RepoLayout {
        root: root.to_path_buf(),
        bitcup_dir,
        objects_dir,
        objects_tmp_dir,
        refs_heads_dir,
        index_dir,
        locks_dir,
        head_file,
        config_file,
    })
}

pub fn open_repo(root: impl AsRef<Path>) -> Result<RepoLayout, OpenRepoError> {
    let root = root.as_ref();
    if !root.exists() {
        return Err(OpenRepoError::MissingRoot(root.to_path_buf()));
    }
    let bitcup_dir = root.join(BITCUP_DIR);
    if !bitcup_dir.is_dir() {
        return Err(OpenRepoError::MissingBitcupDir(bitcup_dir));
    }

    Ok(RepoLayout {
        root: root.to_path_buf(),
        objects_dir: bitcup_dir.join("objects"),
        objects_tmp_dir: bitcup_dir.join("objects").join("tmp"),
        refs_heads_dir: bitcup_dir.join("refs").join("heads"),
        index_dir: bitcup_dir.join("index"),
        locks_dir: bitcup_dir.join("locks"),
        head_file: bitcup_dir.join("HEAD"),
        config_file: bitcup_dir.join("config.toml"),
        bitcup_dir,
    })
}

impl MetadataStore {
    pub fn open(layout: &RepoLayout) -> Result<Self, MetadataError> {
        fs::create_dir_all(&layout.index_dir).map_err(|source| MetadataError::Io {
            path: layout.index_dir.clone(),
            source,
        })?;
        let db_path = layout.index_dir.join("metadata.redb");

        let db = if db_path.exists() {
            Database::open(&db_path).map_err(|err| MetadataError::Backend {
                op: "open_database",
                message: err.to_string(),
            })?
        } else {
            Database::create(&db_path).map_err(|err| MetadataError::Backend {
                op: "create_database",
                message: err.to_string(),
            })?
        };

        let write_txn = db.begin_write().map_err(|err| MetadataError::Backend {
            op: "begin_write",
            message: err.to_string(),
        })?;
        {
            write_txn
                .open_table(REF_CACHE_TABLE)
                .map_err(|err| MetadataError::Backend {
                    op: "open_ref_table",
                    message: err.to_string(),
                })?;
            write_txn
                .open_table(COMMIT_GRAPH_TABLE)
                .map_err(|err| MetadataError::Backend {
                    op: "open_commit_graph_table",
                    message: err.to_string(),
                })?;
        }
        write_txn.commit().map_err(|err| MetadataError::Backend {
            op: "commit_table_creation",
            message: err.to_string(),
        })?;

        Ok(Self { db })
    }

    pub fn set_ref_cache(&self, ref_name: &str, oid_hex: &str) -> Result<(), MetadataError> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|err| MetadataError::Backend {
                op: "begin_write_ref_set",
                message: err.to_string(),
            })?;
        {
            let mut table =
                write_txn
                    .open_table(REF_CACHE_TABLE)
                    .map_err(|err| MetadataError::Backend {
                        op: "open_ref_table_write",
                        message: err.to_string(),
                    })?;
            table
                .insert(ref_name.as_bytes(), oid_hex.as_bytes())
                .map_err(|err| MetadataError::Backend {
                    op: "insert_ref_cache",
                    message: err.to_string(),
                })?;
        }
        write_txn.commit().map_err(|err| MetadataError::Backend {
            op: "commit_ref_set",
            message: err.to_string(),
        })?;
        Ok(())
    }

    pub fn get_ref_cache(&self, ref_name: &str) -> Result<Option<String>, MetadataError> {
        let read_txn = self.db.begin_read().map_err(|err| MetadataError::Backend {
            op: "begin_read_ref_get",
            message: err.to_string(),
        })?;
        let table = read_txn
            .open_table(REF_CACHE_TABLE)
            .map_err(|err| MetadataError::Backend {
                op: "open_ref_table_read",
                message: err.to_string(),
            })?;
        let value = table
            .get(ref_name.as_bytes())
            .map_err(|err| MetadataError::Backend {
                op: "get_ref_cache",
                message: err.to_string(),
            })?;

        value
            .map(|v| String::from_utf8(v.value().to_vec()))
            .transpose()
            .map_err(|e| MetadataError::Backend {
                op: "decode_ref_cache_utf8",
                message: e.to_string(),
            })
    }

    pub fn set_commit_parents(
        &self,
        commit_oid: &str,
        parent_oids: &[String],
    ) -> Result<(), MetadataError> {
        let encoded = parent_oids.join(" ");
        let write_txn = self
            .db
            .begin_write()
            .map_err(|err| MetadataError::Backend {
                op: "begin_write_commit_set",
                message: err.to_string(),
            })?;
        {
            let mut table =
                write_txn
                    .open_table(COMMIT_GRAPH_TABLE)
                    .map_err(|err| MetadataError::Backend {
                        op: "open_commit_graph_table_write",
                        message: err.to_string(),
                    })?;
            table
                .insert(commit_oid.as_bytes(), encoded.as_bytes())
                .map_err(|err| MetadataError::Backend {
                    op: "insert_commit_graph",
                    message: err.to_string(),
                })?;
        }
        write_txn.commit().map_err(|err| MetadataError::Backend {
            op: "commit_commit_set",
            message: err.to_string(),
        })?;
        Ok(())
    }

    pub fn get_commit_parents(
        &self,
        commit_oid: &str,
    ) -> Result<Option<Vec<String>>, MetadataError> {
        let read_txn = self.db.begin_read().map_err(|err| MetadataError::Backend {
            op: "begin_read_commit_get",
            message: err.to_string(),
        })?;
        let table =
            read_txn
                .open_table(COMMIT_GRAPH_TABLE)
                .map_err(|err| MetadataError::Backend {
                    op: "open_commit_graph_table_read",
                    message: err.to_string(),
                })?;
        let value = table
            .get(commit_oid.as_bytes())
            .map_err(|err| MetadataError::Backend {
                op: "get_commit_graph",
                message: err.to_string(),
            })?;

        value
            .map(|v| String::from_utf8(v.value().to_vec()))
            .transpose()
            .map_err(|e| MetadataError::Backend {
                op: "decode_commit_graph_utf8",
                message: e.to_string(),
            })
            .map(|opt| {
                opt.map(|s| {
                    if s.is_empty() {
                        Vec::new()
                    } else {
                        s.split(' ').map(|v| v.to_string()).collect()
                    }
                })
            })
    }
}

pub fn write_object(
    layout: &RepoLayout,
    envelope: &ObjectEnvelope,
) -> Result<ObjectId, ObjectStoreError> {
    let oid = envelope.object_id();
    let oid_hex = oid.to_string();
    let fanout = &oid_hex[0..2];
    let rest = &oid_hex[2..];

    let dir = layout.objects_dir.join(fanout);
    fs::create_dir_all(&dir).map_err(|source| ObjectStoreError::Io {
        path: dir.clone(),
        source,
    })?;

    let final_path = dir.join(rest);
    if final_path.exists() {
        return Ok(oid);
    }

    let mut tmp = NamedTempFile::new_in(&dir).map_err(|source| ObjectStoreError::Io {
        path: dir.clone(),
        source,
    })?;
    let bytes = envelope.encode_canonical();
    tmp.write_all(&bytes)
        .map_err(|source| ObjectStoreError::Io {
            path: final_path.clone(),
            source,
        })?;
    tmp.as_file()
        .sync_all()
        .map_err(|source| ObjectStoreError::Io {
            path: final_path.clone(),
            source,
        })?;
    tmp.persist(&final_path).map_err(|e| ObjectStoreError::Io {
        path: final_path.clone(),
        source: e.error,
    })?;
    sync_dir(&dir).map_err(|e| match e {
        RefUpdateError::Io { path, source } => ObjectStoreError::Io { path, source },
        _ => ObjectStoreError::Io {
            path: dir.clone(),
            source: std::io::Error::other("directory sync error"),
        },
    })?;
    Ok(oid)
}

pub fn read_object(
    layout: &RepoLayout,
    oid_hex: &str,
) -> Result<Option<ObjectEnvelope>, ObjectStoreError> {
    if !is_valid_oid_hex(oid_hex) {
        return Err(ObjectStoreError::InvalidOid);
    }
    let fanout = &oid_hex[0..2];
    let rest = &oid_hex[2..];
    let path = layout.objects_dir.join(fanout).join(rest);
    if !path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(&path).map_err(|source| ObjectStoreError::Io {
        path: path.clone(),
        source,
    })?;
    let envelope = ObjectEnvelope::decode_canonical(&bytes)
        .map_err(|e| ObjectStoreError::Decode(e.to_string()))?;
    Ok(Some(envelope))
}

pub fn verify_repo(
    layout: &RepoLayout,
    options: VerifyOptions,
) -> Result<VerifyReport, VerifyError> {
    let mut report = VerifyReport::default();
    let metadata = if options.rebuild_index {
        Some(MetadataStore::open(layout).map_err(|e| VerifyError::Metadata(e.to_string()))?)
    } else {
        None
    };

    for fanout in fs::read_dir(&layout.objects_dir).map_err(|source| VerifyError::Io {
        path: layout.objects_dir.clone(),
        source,
    })? {
        let fanout = fanout.map_err(|source| VerifyError::Io {
            path: layout.objects_dir.clone(),
            source,
        })?;
        let fanout_path = fanout.path();
        if !fanout_path.is_dir() {
            continue;
        }
        let fanout_name = fanout.file_name().to_string_lossy().to_string();
        if fanout_name == "tmp" {
            continue;
        }
        if fanout_name.len() != 2 || !fanout_name.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
            return Err(VerifyError::InvalidObjectPath { path: fanout_path });
        }

        for entry in fs::read_dir(fanout.path()).map_err(|source| VerifyError::Io {
            path: fanout.path(),
            source,
        })? {
            let entry = entry.map_err(|source| VerifyError::Io {
                path: fanout.path(),
                source,
            })?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let rest = entry.file_name().to_string_lossy().to_string();
            let oid_hex = format!("{fanout_name}{rest}");
            if !is_valid_oid_hex(&oid_hex) {
                return Err(VerifyError::InvalidOid(oid_hex));
            }

            let bytes = fs::read(&path).map_err(|source| VerifyError::Io {
                path: path.clone(),
                source,
            })?;
            let envelope =
                ObjectEnvelope::decode_canonical(&bytes).map_err(|e| VerifyError::Decode {
                    oid: oid_hex.clone(),
                    message: e.to_string(),
                })?;

            let actual = envelope.object_id().to_string();
            if actual != oid_hex {
                return Err(VerifyError::OidMismatch {
                    path,
                    expected: oid_hex,
                    actual,
                });
            }
            report.object_count += 1;

            if let Some(meta) = metadata.as_ref()
                && envelope.kind == bitcup_core::ObjectKind::Commit
            {
                let commit =
                    bitcup_core::decode_commit(&envelope).map_err(|e| VerifyError::Decode {
                        oid: envelope.object_id().to_string(),
                        message: e.to_string(),
                    })?;
                meta.set_commit_parents(&envelope.object_id().to_string(), &commit.parent_oids_hex)
                    .map_err(|e| VerifyError::Metadata(e.to_string()))?;
            }
        }
    }

    let refs_root = layout.bitcup_dir.join("refs");
    if refs_root.exists() {
        for path in walk_files(&refs_root)? {
            let rel_ref = path
                .strip_prefix(&layout.bitcup_dir)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");

            let value = fs::read_to_string(&path).map_err(|source| VerifyError::Io {
                path: path.clone(),
                source,
            })?;
            let oid = value.trim().to_string();
            if !is_valid_oid_hex(&oid) {
                return Err(VerifyError::InvalidRef { path });
            }

            if read_object(layout, &oid)
                .map_err(|e| VerifyError::Metadata(e.to_string()))?
                .is_none()
            {
                return Err(VerifyError::MissingRefObject {
                    ref_name: rel_ref,
                    oid,
                });
            }

            if options.require_signed_refs {
                let signature = read_ref_signature(layout, &rel_ref)
                    .map_err(|e| VerifyError::InvalidRefSignature {
                        ref_name: rel_ref.clone(),
                        message: e.to_string(),
                    })?
                    .ok_or_else(|| VerifyError::MissingRefSignature {
                        ref_name: rel_ref.clone(),
                    })?;
                verify_commit_oid_signature(&oid, &signature).map_err(|e| {
                    VerifyError::InvalidRefSignature {
                        ref_name: rel_ref.clone(),
                        message: e.to_string(),
                    }
                })?;
            }
            report.ref_count += 1;

            if let Some(meta) = metadata.as_ref() {
                meta.set_ref_cache(&rel_ref, &oid)
                    .map_err(|e| VerifyError::Metadata(e.to_string()))?;
            }
        }
    }

    Ok(report)
}

pub fn update_ref(
    layout: &RepoLayout,
    ref_name: &str,
    oid_hex: &str,
) -> Result<(), RefUpdateError> {
    update_ref_signed(
        layout,
        ref_name,
        oid_hex,
        None,
        RefSignaturePolicy::Optional,
    )
}

pub fn update_ref_signed(
    layout: &RepoLayout,
    ref_name: &str,
    oid_hex: &str,
    signature: Option<&CommitSignature>,
    policy: RefSignaturePolicy,
) -> Result<(), RefUpdateError> {
    if !is_valid_ref_name(ref_name) {
        return Err(RefUpdateError::InvalidRefName(ref_name.to_string()));
    }
    if !is_valid_oid_hex(oid_hex) {
        return Err(RefUpdateError::InvalidOid);
    }
    if policy == RefSignaturePolicy::RequireValidSignature && signature.is_none() {
        return Err(RefUpdateError::SignatureRequired);
    }
    if let Some(sig) = signature {
        verify_commit_oid_signature(oid_hex, sig)
            .map_err(|e| RefUpdateError::InvalidSignature(e.to_string()))?;
    }

    fs::create_dir_all(&layout.locks_dir).map_err(|source| RefUpdateError::Io {
        path: layout.locks_dir.clone(),
        source,
    })?;
    let lock_path = layout.locks_dir.join("refs.lock");
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|source| RefUpdateError::Io {
            path: lock_path.clone(),
            source,
        })?;
    let mut lock = RwLock::new(lock_file);
    let _guard = lock
        .write()
        .map_err(|e| RefUpdateError::Lock(e.to_string()))?;

    let ref_path = layout.bitcup_dir.join(ref_name);
    let parent = ref_path
        .parent()
        .ok_or_else(|| RefUpdateError::InvalidRefName(ref_name.to_string()))?;
    fs::create_dir_all(parent).map_err(|source| RefUpdateError::Io {
        path: parent.to_path_buf(),
        source,
    })?;

    let mut tmp = NamedTempFile::new_in(parent).map_err(|source| RefUpdateError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    tmp.write_all(format!("{oid_hex}\n").as_bytes())
        .map_err(|source| RefUpdateError::Io {
            path: ref_path.clone(),
            source,
        })?;
    tmp.as_file()
        .sync_all()
        .map_err(|source| RefUpdateError::Io {
            path: ref_path.clone(),
            source,
        })?;
    tmp.persist(&ref_path).map_err(|e| RefUpdateError::Io {
        path: ref_path.clone(),
        source: e.error,
    })?;

    if let Some(sig) = signature {
        let signature_path = signature_file_path(layout, ref_name);
        write_signature_file(&signature_path, sig)?;
    } else {
        let signature_path = signature_file_path(layout, ref_name);
        if signature_path.exists() {
            fs::remove_file(&signature_path).map_err(|source| RefUpdateError::Io {
                path: signature_path.clone(),
                source,
            })?;
        }
    }

    sync_dir(parent)?;
    Ok(())
}

pub fn read_ref(layout: &RepoLayout, ref_name: &str) -> Result<Option<String>, RefUpdateError> {
    if !is_valid_ref_name(ref_name) {
        return Err(RefUpdateError::InvalidRefName(ref_name.to_string()));
    }
    let ref_path = layout.bitcup_dir.join(ref_name);
    if !ref_path.exists() {
        return Ok(None);
    }

    let mut file = OpenOptions::new()
        .read(true)
        .open(&ref_path)
        .map_err(|source| RefUpdateError::Io {
            path: ref_path.clone(),
            source,
        })?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .map_err(|source| RefUpdateError::Io {
            path: ref_path.clone(),
            source,
        })?;
    Ok(Some(buf.trim().to_string()))
}

pub fn read_ref_signature(
    layout: &RepoLayout,
    ref_name: &str,
) -> Result<Option<CommitSignature>, RefUpdateError> {
    if !is_valid_ref_name(ref_name) {
        return Err(RefUpdateError::InvalidRefName(ref_name.to_string()));
    }
    let path = signature_file_path(layout, ref_name);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).map_err(|source| RefUpdateError::Io {
        path: path.clone(),
        source,
    })?;
    parse_signature_bytes(&bytes)
}

fn create_dir(path: &Path) -> Result<(), InitRepoError> {
    fs::create_dir_all(path).map_err(|source| InitRepoError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn write_new_file(path: &Path, contents: &[u8]) -> Result<(), InitRepoError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| InitRepoError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(contents)
        .map_err(|source| InitRepoError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    file.sync_all().map_err(|source| InitRepoError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>, VerifyError> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).map_err(|source| VerifyError::Io {
            path: dir.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| VerifyError::Io {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                out.push(path);
            }
        }
    }

    out.sort();
    Ok(out)
}

fn sync_dir(path: &Path) -> Result<(), RefUpdateError> {
    let dir = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|source| RefUpdateError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    dir.sync_all().map_err(|source| RefUpdateError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn signature_file_path(layout: &RepoLayout, ref_name: &str) -> PathBuf {
    layout
        .bitcup_dir
        .join("refs-signatures")
        .join(format!("{ref_name}.sig"))
}

fn write_signature_file(path: &Path, signature: &CommitSignature) -> Result<(), RefUpdateError> {
    let parent = path.parent().ok_or_else(|| RefUpdateError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other("signature path has no parent"),
    })?;
    fs::create_dir_all(parent).map_err(|source| RefUpdateError::Io {
        path: parent.to_path_buf(),
        source,
    })?;

    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(&signature.public_key);
    bytes.extend_from_slice(&signature.signature);

    let mut tmp = NamedTempFile::new_in(parent).map_err(|source| RefUpdateError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    tmp.write_all(&bytes).map_err(|source| RefUpdateError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    tmp.as_file()
        .sync_all()
        .map_err(|source| RefUpdateError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    tmp.persist(path).map_err(|e| RefUpdateError::Io {
        path: path.to_path_buf(),
        source: e.error,
    })?;
    sync_dir(parent)?;
    Ok(())
}

fn parse_signature_bytes(bytes: &[u8]) -> Result<Option<CommitSignature>, RefUpdateError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() != 96 {
        return Err(RefUpdateError::InvalidSignature(
            "signature file must be exactly 96 bytes".to_string(),
        ));
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&bytes[..32]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&bytes[32..]);
    Ok(Some(CommitSignature {
        public_key,
        signature,
    }))
}

fn is_valid_ref_name(name: &str) -> bool {
    name.starts_with("refs/heads/")
        && !name.contains("..")
        && !name.contains('\\')
        && !name.ends_with('/')
        && name.len() > "refs/heads/".len()
}

fn is_valid_oid_hex(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;
    use std::thread;

    use bitcup_core::{
        ObjectKind, create_commit, encode_blob, generate_signing_key, sign_commit_oid,
    };
    use tempfile::tempdir;

    use super::{
        BITCUP_DIR, InitRepoError, MetadataStore, RefSignaturePolicy, RefUpdateError, VerifyError,
        VerifyOptions, init_repo, open_repo, read_object, read_ref, read_ref_signature, update_ref,
        update_ref_signed, verify_repo, write_object,
    };

    #[test]
    fn init_repo_creates_expected_layout_and_files() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("project");
        fs::create_dir_all(&root).expect("project dir");

        let layout = init_repo(&root).expect("init must succeed");

        assert_eq!(layout.root, root);
        assert!(layout.bitcup_dir.is_dir());
        assert!(layout.objects_dir.is_dir());
        assert!(layout.objects_tmp_dir.is_dir());
        assert!(layout.refs_heads_dir.is_dir());
        assert!(layout.index_dir.is_dir());
        assert!(layout.locks_dir.is_dir());

        let head = fs::read_to_string(&layout.head_file).expect("read head");
        assert_eq!(head, "ref: refs/heads/main\n");

        let config = fs::read_to_string(&layout.config_file).expect("read config");
        assert_eq!(config, "format_version = 1\ndefault_branch = \"main\"\n");
    }

    #[test]
    fn init_repo_rejects_when_already_initialized() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("project");
        fs::create_dir_all(root.join(BITCUP_DIR)).expect("bitcup dir");

        let err = init_repo(&root).expect_err("must fail");
        assert!(matches!(err, InitRepoError::AlreadyInitialized(_)));
    }

    #[test]
    fn init_repo_rejects_missing_root() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("missing");

        let err = init_repo(&root).expect_err("must fail");
        assert!(matches!(err, InitRepoError::MissingRoot(_)));
    }

    #[test]
    fn metadata_store_open_write_read_ref_cache() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("project");
        fs::create_dir_all(&root).expect("project dir");
        let layout = init_repo(&root).expect("init must succeed");

        let store = MetadataStore::open(&layout).expect("open metadata");
        store
            .set_ref_cache("refs/heads/main", "abc123")
            .expect("write ref cache");

        let value = store
            .get_ref_cache("refs/heads/main")
            .expect("read ref cache");
        assert_eq!(value, Some("abc123".to_string()));
        assert_eq!(store.get_ref_cache("refs/heads/dev").expect("read"), None);
    }

    #[test]
    fn metadata_store_persists_across_reopen() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("project");
        fs::create_dir_all(&root).expect("project dir");
        let layout = init_repo(&root).expect("init must succeed");

        {
            let store = MetadataStore::open(&layout).expect("open metadata");
            store
                .set_ref_cache("refs/heads/main", "def456")
                .expect("write ref cache");
            store
                .set_commit_parents(
                    "commit-1",
                    &["parent-a".to_string(), "parent-b".to_string()],
                )
                .expect("write commit graph");
        }

        let reopened = MetadataStore::open(&layout).expect("reopen metadata");
        let ref_value = reopened
            .get_ref_cache("refs/heads/main")
            .expect("read ref cache");
        assert_eq!(ref_value, Some("def456".to_string()));

        let parents = reopened
            .get_commit_parents("commit-1")
            .expect("read commit graph");
        assert_eq!(
            parents,
            Some(vec!["parent-a".to_string(), "parent-b".to_string()])
        );
    }

    #[test]
    fn metadata_store_commit_graph_handles_empty_parent_list() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("project");
        fs::create_dir_all(&root).expect("project dir");
        let layout = init_repo(&root).expect("init must succeed");

        let store = MetadataStore::open(&layout).expect("open metadata");
        store
            .set_commit_parents("root-commit", &[])
            .expect("write commit graph");

        let parents = store
            .get_commit_parents("root-commit")
            .expect("read commit graph");
        assert_eq!(parents, Some(Vec::new()));
    }

    #[test]
    fn update_ref_writes_and_overwrites_atomically() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("project");
        fs::create_dir_all(&root).expect("project dir");
        let layout = init_repo(&root).expect("init");

        let oid_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let oid_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        update_ref(&layout, "refs/heads/main", oid_a).expect("write ref a");
        assert_eq!(
            read_ref(&layout, "refs/heads/main").expect("read ref"),
            Some(oid_a.to_string())
        );

        update_ref(&layout, "refs/heads/main", oid_b).expect("write ref b");
        assert_eq!(
            read_ref(&layout, "refs/heads/main").expect("read ref"),
            Some(oid_b.to_string())
        );
    }

    #[test]
    fn update_ref_concurrent_writers_do_not_corrupt_content() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("project");
        fs::create_dir_all(&root).expect("project dir");
        let layout = Arc::new(init_repo(&root).expect("init"));
        let expected = vec![
            "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            "3333333333333333333333333333333333333333333333333333333333333333".to_string(),
            "4444444444444444444444444444444444444444444444444444444444444444".to_string(),
        ];

        let mut threads = Vec::new();
        for oid in expected.clone() {
            let layout = Arc::clone(&layout);
            threads.push(thread::spawn(move || {
                for _ in 0..20 {
                    update_ref(&layout, "refs/heads/main", &oid).expect("concurrent write");
                }
            }));
        }
        for t in threads {
            t.join().expect("join");
        }

        let final_value = read_ref(&layout, "refs/heads/main")
            .expect("read ref")
            .expect("value must exist");
        assert_eq!(final_value.len(), 64);
        assert!(final_value.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(expected.contains(&final_value));
    }

    #[test]
    fn open_repo_succeeds_after_init() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("project");
        fs::create_dir_all(&root).expect("project dir");
        let _layout = init_repo(&root).expect("init");

        let opened = open_repo(&root).expect("open");
        assert!(opened.bitcup_dir.is_dir());
        assert!(opened.objects_dir.is_dir());
    }

    #[test]
    fn object_store_roundtrip_blob() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("project");
        fs::create_dir_all(&root).expect("project dir");
        let layout = init_repo(&root).expect("init");

        let blob = encode_blob(b"hello store").expect("encode blob");
        let oid = write_object(&layout, &blob).expect("write object");
        let oid_hex = oid.to_string();

        let loaded = read_object(&layout, &oid_hex)
            .expect("read object")
            .expect("object exists");
        assert_eq!(loaded.kind, ObjectKind::Blob);
        assert_eq!(loaded.object_id().to_string(), oid_hex);
    }

    #[test]
    fn verify_detects_corrupted_object_bytes() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("project");
        fs::create_dir_all(&root).expect("project dir");
        let layout = init_repo(&root).expect("init");

        let blob = encode_blob(b"verify me").expect("encode blob");
        let oid = write_object(&layout, &blob).expect("write object");
        let oid_hex = oid.to_string();
        let path = layout.objects_dir.join(&oid_hex[0..2]).join(&oid_hex[2..]);
        let mut bytes = fs::read(&path).expect("read object file");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(&path, bytes).expect("write corrupted bytes");

        let err = verify_repo(
            &layout,
            VerifyOptions {
                rebuild_index: false,
                require_signed_refs: false,
            },
        )
        .expect_err("verify must fail");
        assert!(matches!(
            err,
            VerifyError::Decode { .. } | VerifyError::OidMismatch { .. }
        ));
    }

    #[test]
    fn verify_rebuild_index_populates_metadata_tables() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("project");
        fs::create_dir_all(&root).expect("project dir");
        let layout = init_repo(&root).expect("init");

        let blob = encode_blob(b"x").expect("blob");
        write_object(&layout, &blob).expect("write blob");
        let tree_oid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let commit = create_commit(tree_oid, &[], "A <a@local>", "A <a@local>", "msg", 1)
            .expect("create commit");
        let commit_oid = write_object(&layout, &commit).expect("write commit");
        update_ref(&layout, "refs/heads/main", &commit_oid.to_string()).expect("update ref");

        let report = verify_repo(
            &layout,
            VerifyOptions {
                rebuild_index: true,
                require_signed_refs: false,
            },
        )
        .expect("verify");
        assert!(report.object_count >= 2);
        assert_eq!(report.ref_count, 1);

        let metadata = MetadataStore::open(&layout).expect("open metadata");
        let ref_cached = metadata
            .get_ref_cache("refs/heads/main")
            .expect("get ref cache");
        assert_eq!(ref_cached, Some(commit_oid.to_string()));

        let parents = metadata
            .get_commit_parents(&commit_oid.to_string())
            .expect("get commit parents");
        assert_eq!(parents, Some(Vec::new()));
    }

    #[test]
    fn signed_ref_update_requires_valid_signature_when_policy_enabled() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("project");
        fs::create_dir_all(&root).expect("project dir");
        let layout = init_repo(&root).expect("init");
        let oid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let err = update_ref_signed(
            &layout,
            "refs/heads/main",
            oid,
            None,
            RefSignaturePolicy::RequireValidSignature,
        )
        .expect_err("must fail");
        assert!(matches!(err, RefUpdateError::SignatureRequired));

        let key = generate_signing_key();
        let sig = sign_commit_oid(oid, &key).expect("sign");
        update_ref_signed(
            &layout,
            "refs/heads/main",
            oid,
            Some(&sig),
            RefSignaturePolicy::RequireValidSignature,
        )
        .expect("signed update");

        let loaded = read_ref_signature(&layout, "refs/heads/main")
            .expect("read signature")
            .expect("signature exists");
        assert_eq!(loaded.public_key, sig.public_key);
    }

    #[test]
    fn verify_requires_ref_signature_when_enabled() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("project");
        fs::create_dir_all(&root).expect("project dir");
        let layout = init_repo(&root).expect("init");

        let blob = encode_blob(b"x").expect("blob");
        let blob_oid = write_object(&layout, &blob).expect("write blob");
        update_ref(&layout, "refs/heads/main", &blob_oid.to_string()).expect("unsigned ref");

        let err = verify_repo(
            &layout,
            VerifyOptions {
                rebuild_index: false,
                require_signed_refs: true,
            },
        )
        .expect_err("verify must fail");
        assert!(matches!(err, VerifyError::MissingRefSignature { .. }));
    }
}
