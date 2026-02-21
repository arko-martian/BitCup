# BitCup Architecture

## Overview
BitCup is a local-first version-control engine with a strict layered architecture:
1. Core domain (`bitcup-core`): immutable object model, repository semantics, integrity rules.
2. Storage engine (`bitcup-store`): on-disk layout, object persistence, indexes, lock and durability mechanics.
3. Interfaces (`bitcup-cli`, `bitcup-api`): command handling and programmatic API for UI.
4. Frontend (`bitcup-ui`): repository visualization and guided operations using stable API calls.

Principle: all write operations go through core + store invariants; UI and CLI are thin clients.

## Repository Layout
Inside project root:
- `.bitcup/config.toml`
- `.bitcup/HEAD`
- `.bitcup/refs/heads/<branch>`
- `.bitcup/objects/xx/<rest-of-id>` (fanout by first byte(s))
- `.bitcup/index/` (auxiliary indexes, optional caches)
- `.bitcup/locks/` (lock files)

Design goals:
- append-safe write flow
- atomic visibility of newly written objects
- deterministic lookup by object ID

## Object Model
Objects are immutable and content-addressed.

- `Blob`: file content bytes + metadata envelope
- `Tree`: sorted entries of `{name, mode, object_id}`
- `Commit`: `{tree_id, parent_ids[], author, committer, message, timestamp, extras}`
- `Tag` (optional MVP)

### Object ID (OID)
- OID = `blake3(canonical_envelope_bytes)`
- Envelope includes: object kind, schema version, payload bytes
- canonicalization rule is fixed to ensure deterministic IDs across platforms

## Serialization Strategy (`rkyv`)
`rkyv` is used for fast archived read paths.

Envelope example:
- `magic`: `BITCUP`
- `format_version`: u16
- `object_kind`: u8
- `payload_schema_version`: u16
- `payload_len`: u64
- `payload`: archived bytes
- `trailer_checksum`: optional secondary checksum (OID remains source of truth)

Compatibility policy:
- forward-incompatible schema changes require version bump
- decoders support a bounded window of historical versions
- migration command can rewrite legacy objects/indexes

## Write Path
1. Build canonical object envelope in memory.
2. Compute BLAKE3 OID.
3. Write to temp file under `.bitcup/objects/tmp/`.
4. `fsync` temp file.
5. Atomic rename into fanout path.
6. `fsync` containing directory.
7. Update refs/index with lock + atomic swap.

Failure behavior:
- partial temp artifacts are recoverable and ignored by readers
- no object becomes visible until rename succeeds

## Read Path
1. Resolve OID to fanout path.
2. Read bytes and validate envelope.
3. Recompute BLAKE3 and verify OID match.
4. Decode archived payload through `rkyv`.
5. Return immutable domain object.

Fast path opportunities:
- mmap for large pack-like structures (post-MVP)
- object decode cache keyed by OID

## Indexing
Indexes are optimization-only and rebuildable.

Initial indexes:
- Commit graph adjacency index
- Path-to-blob lookup for latest commit (optional cache)
- Ref resolution cache

Rules:
- source of truth is object + refs store
- corrupted index never corrupts source data
- `bitcup verify --rebuild-index` restores consistency

## Concurrency Model
- Single-writer lock per repository for mutating commands.
- Multi-reader allowed without lock when reading immutable objects.
- Ref updates use lock file + compare-and-swap semantics.
- Frontend operations route through same locking API as CLI.

## API Boundary
`bitcup-api` provides stable methods:
- `init_repo(path)`
- `snapshot(pathspec)`
- `commit(message, metadata)`
- `list_refs()`
- `resolve_ref(name)`
- `get_commit(oid)`
- `get_tree(oid)`
- `verify(options)`

Contract:
- typed errors with machine-readable codes
- no direct filesystem mutation exposed to UI layer

## Frontend Runtime Choice
Primary recommendation:
- Tauri + Rust backend + web UI frontend.

Rationale:
- direct access to local filesystem and secure command boundary
- reuse core Rust crates without duplicating logic in JS
- option to ship a pure CLI and desktop UI from same engine

Alternative:
- Browser WASM app with restricted filesystem APIs (File System Access API), best for read-heavy workflows and demos, weaker for full local VCS semantics.

## Security and Integrity
- Integrity is content-addressing first (BLAKE3 OID verification on read)
- optional signed commits/tags in later phases
- path sanitization and traversal protection (`..`, symlink policy)
- avoid deserializing untrusted bytes without envelope and version checks

## Testing Strategy
- Unit tests: object model, hashing, canonicalization
- Integration tests: init/snapshot/commit/log/branch flows
- Property tests: deterministic OID under stable input permutations
- Fuzzing: envelope and payload parser robustness
- Crash tests: simulate interruption during write/rename/ref update

## Performance Targets (Initial)
- Snapshot + commit for 10k files in <2s on modern SSD (warm cache)
- Object lookup p95 <5ms for hot objects
- Verify 100k objects with bounded memory profile

## Observability
- structured logs (`tracing`) with operation IDs
- optional performance spans for snapshot, hash, serialize, fsync
- debug command to inspect repository health and index status

## Extension Points
- Remote transport protocol (future)
- Packfile/chunk compaction format (future)
- Pluggable auth/signing provider for commit identity (future)
- Git import/export bridge (future)
