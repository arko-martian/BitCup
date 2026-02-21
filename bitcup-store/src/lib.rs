use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

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

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{init_repo, InitRepoError, BITCUP_DIR};

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
}
