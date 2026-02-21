use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

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
    let index_dir = bitcup_dir.join("index");
    let locks_dir = bitcup_dir.join("locks");
    let head_file = bitcup_dir.join("HEAD");
    let config_file = bitcup_dir.join("config.toml");

    create_dir(&bitcup_dir)?;
    create_dir(&objects_dir)?;
    create_dir(&objects_tmp_dir)?;
    create_dir(&refs_heads_dir)?;
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

pub fn update_ref(
    layout: &RepoLayout,
    ref_name: &str,
    oid_hex: &str,
) -> Result<(), RefUpdateError> {
    if !is_valid_ref_name(ref_name) {
        return Err(RefUpdateError::InvalidRefName(ref_name.to_string()));
    }
    if !is_valid_oid_hex(oid_hex) {
        return Err(RefUpdateError::InvalidOid);
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

    use tempfile::tempdir;

    use super::{BITCUP_DIR, InitRepoError, MetadataStore, init_repo, read_ref, update_ref};

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
}
