use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use bitcup_core::{
    ObjectKind, create_commit, decode_blob, decode_commit, decode_tree, snapshot_tree,
};
use bitcup_store::{
    VerifyOptions, init_repo, open_repo, read_object, read_ref, update_ref, verify_repo,
    write_object,
};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "bitcup")]
#[command(about = "BitCup local VCS CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Init,
    Snapshot,
    Commit {
        #[arg(short, long)]
        message: String,
        #[arg(short, long, default_value = "BitCup User <user@local>")]
        author: String,
    },
    Log,
    Show {
        oid: String,
    },
    Verify {
        #[arg(long)]
        rebuild_index: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cwd = std::env::current_dir().context("failed to resolve current directory")?;

    match cli.command {
        Commands::Init => cmd_init(cwd),
        Commands::Snapshot => cmd_snapshot(cwd),
        Commands::Commit { message, author } => cmd_commit(cwd, &message, &author),
        Commands::Log => cmd_log(cwd),
        Commands::Show { oid } => cmd_show(cwd, &oid),
        Commands::Verify { rebuild_index } => cmd_verify(cwd, rebuild_index),
    }
}

fn cmd_init(root: PathBuf) -> Result<()> {
    let layout =
        init_repo(&root).with_context(|| format!("failed to init repo at {}", root.display()))?;
    println!("initialized repository at {}", layout.bitcup_dir.display());
    Ok(())
}

fn cmd_snapshot(root: PathBuf) -> Result<()> {
    let layout =
        open_repo(&root).with_context(|| format!("failed to open repo at {}", root.display()))?;
    let snapshot = snapshot_tree(&root).context("failed to snapshot working tree")?;

    for blob in &snapshot.blobs {
        write_object(&layout, &blob.envelope).context("failed to write blob object")?;
    }
    let tree_oid = write_object(&layout, &snapshot.tree).context("failed to write tree object")?;
    println!("snapshot tree {}", tree_oid);
    Ok(())
}

fn cmd_commit(root: PathBuf, message: &str, author: &str) -> Result<()> {
    let layout =
        open_repo(&root).with_context(|| format!("failed to open repo at {}", root.display()))?;
    let snapshot = snapshot_tree(&root).context("failed to snapshot working tree")?;
    for blob in &snapshot.blobs {
        write_object(&layout, &blob.envelope).context("failed to write blob object")?;
    }
    let tree_oid = write_object(&layout, &snapshot.tree).context("failed to write tree object")?;
    let head_ref = resolve_head_ref(&layout.head_file)?;
    let maybe_parent = read_ref(&layout, &head_ref).context("failed to read branch ref")?;

    let parents: Vec<String> = maybe_parent.into_iter().collect();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("clock before unix epoch")?
        .as_secs() as i64;
    let commit = create_commit(&tree_oid.to_string(), &parents, author, author, message, ts)
        .context("failed to build commit object")?;
    let commit_oid = write_object(&layout, &commit).context("failed to write commit object")?;
    update_ref(&layout, &head_ref, &commit_oid.to_string())
        .context("failed to update branch ref")?;

    println!("commit {}", commit_oid);
    println!("tree   {}", tree_oid);
    if let Some(parent) = parents.first() {
        println!("parent {}", parent);
    }
    Ok(())
}

fn cmd_log(root: PathBuf) -> Result<()> {
    let layout =
        open_repo(&root).with_context(|| format!("failed to open repo at {}", root.display()))?;
    let head_ref = resolve_head_ref(&layout.head_file)?;
    let mut current = match read_ref(&layout, &head_ref).context("failed to read head ref")? {
        Some(v) => v,
        None => {
            println!("no commits on {}", head_ref);
            return Ok(());
        }
    };

    loop {
        let envelope =
            match read_object(&layout, &current).context("failed to read commit object")? {
                Some(v) => v,
                None => bail!("missing commit object {}", current),
            };
        let commit = decode_commit(&envelope).context("failed to decode commit")?;
        println!("commit {}", current);
        println!("Author: {}", commit.author);
        println!("Date:   {}", commit.timestamp_unix_secs);
        println!();
        println!("    {}", commit.message);
        println!();

        match commit.parent_oids_hex.first() {
            Some(parent) => current = parent.clone(),
            None => break,
        }
    }
    Ok(())
}

fn cmd_show(root: PathBuf, oid: &str) -> Result<()> {
    let layout =
        open_repo(&root).with_context(|| format!("failed to open repo at {}", root.display()))?;
    let envelope = match read_object(&layout, oid).context("failed to read object")? {
        Some(v) => v,
        None => bail!("object not found: {}", oid),
    };

    match envelope.kind {
        ObjectKind::Blob => {
            let bytes = decode_blob(&envelope).context("failed to decode blob")?;
            println!("kind: blob");
            println!("size: {}", bytes.len());
            println!("{}", String::from_utf8_lossy(&bytes));
        }
        ObjectKind::Tree => {
            let tree = decode_tree(&envelope).context("failed to decode tree")?;
            println!("kind: tree");
            println!("entries: {}", tree.entries.len());
            for entry in tree.entries {
                println!("{} {:o} {}", entry.blob_oid_hex, entry.mode, entry.path);
            }
        }
        ObjectKind::Commit => {
            let commit = decode_commit(&envelope).context("failed to decode commit")?;
            println!("kind: commit");
            println!("tree: {}", commit.tree_oid_hex);
            for parent in commit.parent_oids_hex {
                println!("parent: {}", parent);
            }
            println!("author: {}", commit.author);
            println!("committer: {}", commit.committer);
            println!("date: {}", commit.timestamp_unix_secs);
            println!();
            println!("{}", commit.message);
        }
        ObjectKind::Tag => {
            println!("kind: tag");
            println!("tag object support not implemented yet");
        }
    }
    Ok(())
}

fn cmd_verify(root: PathBuf, rebuild_index: bool) -> Result<()> {
    let layout =
        open_repo(&root).with_context(|| format!("failed to open repo at {}", root.display()))?;
    let report =
        verify_repo(&layout, VerifyOptions { rebuild_index }).context("verification failed")?;
    println!("verify ok");
    println!("objects: {}", report.object_count);
    println!("refs: {}", report.ref_count);
    println!("rebuild_index: {}", rebuild_index);
    Ok(())
}

fn resolve_head_ref(head_file: &PathBuf) -> Result<String> {
    let head = fs::read_to_string(head_file)
        .with_context(|| format!("failed to read {}", head_file.display()))?;
    let trimmed = head.trim();
    if let Some(rest) = trimmed.strip_prefix("ref: ") {
        return Ok(rest.to_string());
    }
    bail!("unsupported HEAD format: {}", trimmed);
}
