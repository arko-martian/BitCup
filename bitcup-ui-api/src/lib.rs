use bitcup_api::{BrowseApi, ObjectView};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UiApiError {
    #[error("{0}")]
    Message(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UiRefEntry {
    pub name: String,
    pub oid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UiTreeEntry {
    pub path: String,
    pub mode: u32,
    pub blob_oid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UiObjectView {
    Blob {
        oid: String,
        size_bytes: usize,
    },
    Tree {
        oid: String,
        entry_count: usize,
        entries: Vec<UiTreeEntry>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct UiVerifySummary {
    pub object_count: usize,
    pub ref_count: usize,
}

pub fn ui_head(repo_path: &str) -> Result<String, UiApiError> {
    let api = BrowseApi::open(repo_path).map_err(|e| UiApiError::Message(e.to_string()))?;
    api.head().map_err(|e| UiApiError::Message(e.to_string()))
}

pub fn ui_list_refs(repo_path: &str) -> Result<Vec<UiRefEntry>, UiApiError> {
    let api = BrowseApi::open(repo_path).map_err(|e| UiApiError::Message(e.to_string()))?;
    let refs = api
        .list_refs()
        .map_err(|e| UiApiError::Message(e.to_string()))?;
    Ok(refs
        .into_iter()
        .map(|r| UiRefEntry {
            name: r.name,
            oid: r.oid,
        })
        .collect())
}

pub fn ui_show_object(repo_path: &str, oid: &str) -> Result<Option<UiObjectView>, UiApiError> {
    let api = BrowseApi::open(repo_path).map_err(|e| UiApiError::Message(e.to_string()))?;
    let object = api
        .show_object(oid)
        .map_err(|e| UiApiError::Message(e.to_string()))?;
    Ok(object.map(map_object_view))
}

pub fn ui_verify_read_only(repo_path: &str) -> Result<UiVerifySummary, UiApiError> {
    let api = BrowseApi::open(repo_path).map_err(|e| UiApiError::Message(e.to_string()))?;
    let summary = api
        .verify_read_only()
        .map_err(|e| UiApiError::Message(e.to_string()))?;
    Ok(UiVerifySummary {
        object_count: summary.object_count,
        ref_count: summary.ref_count,
    })
}

fn map_object_view(value: ObjectView) -> UiObjectView {
    match value {
        ObjectView::Blob { oid, size_bytes } => UiObjectView::Blob { oid, size_bytes },
        ObjectView::Tree {
            oid,
            entry_count,
            entries,
        } => UiObjectView::Tree {
            oid,
            entry_count,
            entries: entries
                .into_iter()
                .map(|e| UiTreeEntry {
                    path: e.path,
                    mode: e.mode,
                    blob_oid: e.blob_oid,
                })
                .collect(),
        },
        ObjectView::Commit {
            oid,
            tree_oid,
            parent_oids,
            author,
            committer,
            message,
            timestamp_unix_secs,
        } => UiObjectView::Commit {
            oid,
            tree_oid,
            parent_oids,
            author,
            committer,
            message,
            timestamp_unix_secs,
        },
        ObjectView::Tag { oid, payload_len } => UiObjectView::Tag { oid, payload_len },
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use bitcup_core::{create_commit, encode_blob};
    use bitcup_store::{init_repo, update_ref, write_object};
    use tempfile::tempdir;

    use crate::{UiObjectView, ui_head, ui_list_refs, ui_show_object, ui_verify_read_only};

    #[test]
    fn read_only_ui_api_roundtrip() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("repo");
        fs::create_dir_all(&root).expect("root");
        let layout = init_repo(&root).expect("init");

        let blob = encode_blob(b"ui-api").expect("blob");
        let blob_oid = write_object(&layout, &blob)
            .expect("write blob")
            .to_string();
        let commit = create_commit(&blob_oid, &[], "A", "A", "msg", 1).expect("commit");
        let commit_oid = write_object(&layout, &commit)
            .expect("write commit")
            .to_string();
        update_ref(&layout, "refs/heads/main", &commit_oid).expect("update");

        let repo_path = root.to_string_lossy();
        assert_eq!(ui_head(&repo_path).expect("head"), "ref: refs/heads/main");

        let refs = ui_list_refs(&repo_path).expect("refs");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "refs/heads/main");
        assert_eq!(refs[0].oid, commit_oid);

        match ui_show_object(&repo_path, &blob_oid)
            .expect("show")
            .expect("exists")
        {
            UiObjectView::Blob { size_bytes, .. } => assert_eq!(size_bytes, 6),
            other => panic!("expected blob, got {other:?}"),
        }

        let verify = ui_verify_read_only(&repo_path).expect("verify");
        assert_eq!(verify.ref_count, 1);
        assert!(verify.object_count >= 2);
    }
}
