# BitCup Plan

## Vision
BitCup is a local-first, content-addressed source control system inspired by Git, implemented in Rust with:
- `blake3` for fast cryptographic content IDs and integrity verification
- `rkyv` for zero-copy archived object formats and index structures
- an embedded local metadata/index layer for high performance at scale
- a modern UI (WASM frontend or Tauri/web hybrid) over a stable Rust API

BitCup is not a toy. The goal is a robust developer tool with deterministic behavior, clear invariants, and production-grade reliability.

## Product Objectives
1. Deliver a fast local repository engine with deterministic snapshots, commits, branches, and history traversal.
2. Build a durable storage format with explicit compatibility/versioning guarantees.
3. Provide a clear command surface (CLI first), then expose a frontend interface for repository browsing and operations.
4. Make correctness and recoverability first-class: verification, fsync strategy, corruption detection, and repair tooling.

## Scope: Phase 1 (MVP)
- Local repository initialization
- Content-addressed object store
- Snapshot creation from working tree
- Commit object creation (message, author, parent links, root tree)
- Branch refs and HEAD handling
- History log and object inspection
- Integrity verification command
- Minimal frontend for repository graph/tree browsing

## Non-Goals (MVP)
- Network remotes/protocol
- Full Git compatibility layer
- Merge conflict UI
- Multi-user concurrency across network shares
- Pluggable storage backends

## Deliverables
- `bitcup-core` crate: object model, hashing, serialization, repository semantics
- `bitcup-store` crate: storage layout, index, pack/chunk persistence
- `bitcup-cli` crate: user commands (`init`, `status`, `snapshot`, `commit`, `log`, `show`, `verify`)
- `bitcup-ui` package: WASM frontend or Tauri shell consuming a Rust API
- `docs/` with format specs and invariants
- test suite: unit, property, integration, corruption scenarios, benchmark harness

## Milestones

## M0: Foundations (Week 1)
- Workspace setup, crate boundaries, linting, formatting, CI baseline
- Error model, tracing/logging strategy, config handling
- Repository layout spec draft (`.bitcup/`)

Exit criteria:
- `cargo test` and CI baseline green
- repo layout and core object IDs documented

## M1: Storage + Object Model (Week 2-3)
- Object enums: blob/tree/commit/tag (tag optional MVP)
- BLAKE3 ID derivation rules frozen for MVP
- `rkyv` archive schemas and version tag strategy
- On-disk object write/read + checksum validation

Exit criteria:
- roundtrip tests for all object types
- corrupted bytes fail deterministically with actionable errors

## M2: Repository Semantics (Week 3-4)
- Snapshot traversal and tree construction
- Commit creation and parent linkage
- Refs (`refs/heads/*`) and HEAD symbolic ref
- `log` traversal and object inspection APIs

Exit criteria:
- deterministic commits for identical inputs
- history traversal tested on linear and branch scenarios

## M3: CLI UX + Verification (Week 4-5)
- CLI commands with stable output formats
- `verify` command: object walk + hash validation + ref integrity
- lock handling for concurrent local operations

Exit criteria:
- end-to-end user flow tested in integration tests
- verification catches injected corruption/invalid refs

## M4: Frontend MVP (Week 5-6)
- Read-only repo exploration UI (commits/tree/blob)
- branch and commit graph view
- Rust API surface exposed for UI consumption

Exit criteria:
- browse repo history and files from UI
- no direct filesystem mutation from frontend without core validation

## M5: Hardening + v0.1 (Week 7+)
- performance passes (cache/index tuning)
- crash consistency and durability tests
- migration/version checks and upgrade command
- release process + signed binaries

Exit criteria:
- benchmark targets met
- upgrade and rollback procedure documented

## Quality Bar
- 80%+ line coverage in core critical paths; 100% for serialization format and hash invariants
- property tests for content/address invariants
- fuzz targets for object parsing and archive decode paths
- deterministic outputs across macOS/Linux (and Windows before v1)

## Engineering Standards
- Rust stable toolchain, strict clippy lints
- No unchecked panics in core paths
- Explicit fsync policy where durability matters
- Semver and format versioning policy from day one
- ADRs for major decisions (hashing, archive format, lock model, frontend runtime)

## Risks and Mitigations
- Risk: `rkyv` schema evolution complexity
  - Mitigation: versioned envelope wrapper + compatibility tests per version
- Risk: subtle data corruption from partial writes
  - Mitigation: temp file + atomic rename + fsync directory protocol
- Risk: performance regressions on large repos
  - Mitigation: benchmark corpus and CI performance budget checks
- Risk: frontend-runtime lock-in
  - Mitigation: stable core API and UI adapter boundary

## Immediate Next Tasks (Start Now)
1. Create Rust workspace layout and base crates.
2. Define `ObjectId` derivation spec and canonical object envelope.
3. Implement blob write/read path with BLAKE3 + `rkyv` archive roundtrip.
4. Add integration test: init -> snapshot -> commit -> log.
5. Draft ADR-001 for repository layout and object format.
