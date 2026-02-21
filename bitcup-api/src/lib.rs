use std::fs;
use std::path::{Path, PathBuf};

use bitcup_core::{ObjectKind, decode_blob, decode_commit, decode_tree};
use bitcup_store::{RepoLayout, VerifyOptions, open_repo, read_object, read_ref, verify_repo};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefEntry {
    pub name: String,
    pub oid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntryView {
    pub path: String,
    pub mode: u32,
    pub blob_oid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectView {
    Blob {
        oid: String,
        size_bytes: usize,
    },
    Tree {
        oid: String,
        entry_count: usize,
        entries: Vec<TreeEntryView>,
    },
    Commit {
        oid: String,
        tree_oid: String,
        parent_oids: Vec<String>,
        author: String,
        committer: String,
        message: String,
        timestamp_unix_secs: i64,
    },
    Tag {
        oid: String,
        payload_len: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifySummary {
    pub object_count: usize,
    pub ref_count: usize,
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("failed to open repository at {path}: {message}")]
    OpenRepo { path: PathBuf, message: String },
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("storage error: {0}")]
    Store(String),
    #[error("decode error: {0}")]
    Decode(String),
}

pub struct BrowseApi {
    layout: RepoLayout,
}

impl BrowseApi {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ApiError> {
        let root = root.as_ref().to_path_buf();
        let layout = open_repo(&root).map_err(|e| ApiError::OpenRepo {
            path: root,
            message: e.to_string(),
        })?;
        Ok(Self { layout })
    }

    pub fn repo_root(&self) -> &Path {
        &self.layout.root
    }

    pub fn head(&self) -> Result<String, ApiError> {
        fs::read_to_string(&self.layout.head_file)
            .map(|v| v.trim().to_string())
            .map_err(|source| ApiError::Io {
                path: self.layout.head_file.clone(),
                source,
            })
    }

    pub fn list_refs(&self) -> Result<Vec<RefEntry>, ApiError> {
        let refs_root = self.layout.bitcup_dir.join("refs");
        if !refs_root.exists() {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        for path in walk_files(&refs_root)? {
            let rel_ref = path
                .strip_prefix(&self.layout.bitcup_dir)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let oid = read_ref(&self.layout, &rel_ref)
                .map_err(|e| ApiError::Store(e.to_string()))?
                .ok_or_else(|| ApiError::Store(format!("missing ref value for {rel_ref}")))?;
            out.push(RefEntry { name: rel_ref, oid });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub fn show_object(&self, oid_hex: &str) -> Result<Option<ObjectView>, ApiError> {
        let envelope =
            match read_object(&self.layout, oid_hex).map_err(|e| ApiError::Store(e.to_string()))? {
                Some(v) => v,
                None => return Ok(None),
            };
        let oid = envelope.object_id().to_string();

        let view = match envelope.kind {
            ObjectKind::Blob => {
                let bytes = decode_blob(&envelope).map_err(|e| ApiError::Decode(e.to_string()))?;
                ObjectView::Blob {
                    oid,
                    size_bytes: bytes.len(),
                }
            }
            ObjectKind::Tree => {
                let tree = decode_tree(&envelope).map_err(|e| ApiError::Decode(e.to_string()))?;
                let entries = tree
                    .entries
                    .into_iter()
                    .map(|e| TreeEntryView {
                        path: e.path,
                        mode: e.mode,
                        blob_oid: e.blob_oid_hex,
                    })
                    .collect::<Vec<_>>();
                ObjectView::Tree {
                    oid,
                    entry_count: entries.len(),
                    entries,
                }
            }
            ObjectKind::Commit => {
                let commit =
                    decode_commit(&envelope).map_err(|e| ApiError::Decode(e.to_string()))?;
                ObjectView::Commit {
                    oid,
                    tree_oid: commit.tree_oid_hex,
                    parent_oids: commit.parent_oids_hex,
                    author: commit.author,
                    committer: commit.committer,
                    message: commit.message,
                    timestamp_unix_secs: commit.timestamp_unix_secs,
                }
            }
            ObjectKind::Tag => ObjectView::Tag {
                oid,
                payload_len: envelope.payload.len(),
            },
        };

        Ok(Some(view))
    }

    pub fn verify_read_only(&self) -> Result<VerifySummary, ApiError> {
        let report = verify_repo(
            &self.layout,
            VerifyOptions {
                rebuild_index: false,
                require_signed_refs: false,
            },
        )
        .map_err(|e| ApiError::Store(e.to_string()))?;
        Ok(VerifySummary {
            object_count: report.object_count,
            ref_count: report.ref_count,
        })
    }
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>, ApiError> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).map_err(|source| ApiError::Io {
            path: dir.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| ApiError::Io {
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

#[cfg(test)]
mod tests {
    use std::fs;

    use bitcup_core::{create_commit, encode_blob};
    use bitcup_store::{init_repo, update_ref, write_object};
    use tempfile::tempdir;

    use super::{BrowseApi, ObjectView};

    #[test]
    fn browse_api_reads_head_refs_objects_and_verify_summary() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("repo");
        fs::create_dir_all(&root).expect("root");
        let layout = init_repo(&root).expect("init");

        let blob = encode_blob(b"hello-api").expect("blob");
        let blob_oid = write_object(&layout, &blob)
            .expect("write blob")
            .to_string();
        let commit = create_commit(
            &blob_oid,
            &[],
            "A <a@local>",
            "A <a@local>",
            "msg",
            1_700_000_000,
        )
        .expect("create commit");
        let commit_oid = write_object(&layout, &commit)
            .expect("write commit")
            .to_string();
        update_ref(&layout, "refs/heads/main", &commit_oid).expect("update ref");

        let api = BrowseApi::open(&root).expect("open api");
        assert_eq!(api.head().expect("head"), "ref: refs/heads/main");

        let refs = api.list_refs().expect("list refs");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "refs/heads/main");
        assert_eq!(refs[0].oid, commit_oid);

        match api
            .show_object(&blob_oid)
            .expect("show blob")
            .expect("exists")
        {
            ObjectView::Blob { size_bytes, .. } => assert_eq!(size_bytes, 9),
            other => panic!("expected blob view, got {other:?}"),
        }

        match api
            .show_object(&commit_oid)
            .expect("show commit")
            .expect("exists")
        {
            ObjectView::Commit {
                tree_oid,
                parent_oids,
                message,
                ..
            } => {
                assert_eq!(tree_oid, blob_oid);
                assert!(parent_oids.is_empty());
                assert_eq!(message, "msg");
            }
            other => panic!("expected commit view, got {other:?}"),
        }

        let verify = api.verify_read_only().expect("verify");
        assert_eq!(verify.ref_count, 1);
        assert!(verify.object_count >= 2);
    }

    #[test]
    fn show_object_returns_none_for_missing_oid() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("repo");
        fs::create_dir_all(&root).expect("root");
        let _layout = init_repo(&root).expect("init");
        let api = BrowseApi::open(&root).expect("open api");

        let missing = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(api.show_object(missing).expect("show").is_none());
    }
}
