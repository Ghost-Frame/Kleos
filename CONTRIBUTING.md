# Contributing to Kleos (formerly Engram)

## Getting Started

```bash
git clone https://github.com/Ghost-Frame/Kleos.git
cd Kleos
cargo build --workspace
cargo test --workspace --exclude kleos-migrate
```

`cargo test` is the simple local option above; it is not exact CI parity. CI runs
the same test set through `cargo-nextest` with a 2-way partition -- see
[Before Pushing](#before-pushing) for the nextest install and invocation.

Rust 1.94 or later. The workspace builds on Linux, macOS, and WSL2. Native Windows builds are untested -- use WSL2.

The full workspace is large (26 crates, wants ~8 GiB RAM to build). For day-to-day
server work you can build just what you need and skip the heavy crates:

```bash
cargo build -p kleos-server -p kleos-cli -p kleos-mcp
```

`cargo test --workspace` excludes `kleos-migrate` throughout this guide and in CI:
it links a second SQLite backend and conflicts with the SQLCipher symbols pulled
in by the rest of the workspace.

### System Dependencies

**Debian/Ubuntu:**
```bash
sudo apt install build-essential pkg-config libssl-dev clang protobuf-compiler libpcsclite-dev
```

`libpcsclite-dev` is needed for the PIV/smartcard (YubiKey) path, which the
default workspace build pulls in.

**macOS:**
```bash
brew install openssl protobuf
```

(PC/SC is provided by the system framework on macOS, so no extra smartcard package is needed.)

SQLite is vendored via `rusqlite` (bundled feature). SQLCipher is vendored at compile time -- no system libsqlcipher needed.

## Workspace Structure

26-crate Cargo workspace, plus the `sdk/` directory (non-Rust client SDKs). Crates by area:

**Core & server**
```
kleos-lib       Core library -- all domain logic: memory, search, embeddings, graph,
                intelligence, services, skills, growth, auth, gate, jobs. Feature-gated brain backend.
kleos-server    Axum HTTP API server. Route modules, middleware layers, embedded React web GUI.
kleos-config    Shared config types + env resolution, used by both the server and the
                installer so the two never drift.
kleos-client    Shared Rust HTTP client with PIV/Ed25519 envelope signing.
```

**Clients & integration**
```
kleos-cli           Command-line client over the HTTP API. Memory ops, skills, handoffs, creds.
kleos-mcp           MCP server (Model Context Protocol). Curated tool registry; stdio by default.
kleos-sidecar       Session-scoped memory proxy. File watcher, batched flushing, optional Ollama compression.
kleos-token-client  Tiny std-only client for the phylaxd SO_PEERCRED token broker (no kleos-lib dep).
sdk/                Client SDKs: TypeScript, Python, Go.
```

**Agent tooling & safety**
```
agent-forge         Structured-reasoning CLI. Spec/hypothesis/verify protocol, Tree-sitter AST parsing.
forge               agent-forge compute engine as a library (repo-map, code search, comment-check,
                    challenge-code), used server-side by kleos-server.
kleos-sh            Shell command gate. Static validation, SSRF guard, approval queue, Claude Code hook.
kleos-fs            AST-aware filesystem ops. Guarded read/write/edit with configurable allowed roots.
eidolon-supervisor  Session drift-detection daemon. Real-time transcript watching, rule-based alerts.
```

**Credentials & security**
```
kleos-cred                Credential management library + `cred` CLI. YubiKey, Argon2id, ECDH, vault.
kleos-credd               Base credential daemon. Two-tier (master + agent) keys, AES-256-GCM, ECDH bootstrap.
kleos-phylax              Agent-native credential authority -- approvals, leases, ECDH, namespaces.
kleos-phylaxd             The credential daemon actually deployed (`credd`): kleos-credd + Phylax policy.
kleos-phylax-ssh-agent    OpenSSH agent protocol server -- wire protocol + KeyProvider trait.
kleos-phylax-ssh-agentd   Headless SSH agent daemon that brokers keys/signing through phylaxd.
```

**Ops & install**
```
kleos-migrate       One-shot ETL from an encrypted monolith DB into per-tenant shards.
kleos-cleanup       Deduplication and log-demotion utility.
kleos-ingest        Transcript ingest daemon. Request signing, file watching, LLM summarization.
kleos-install-core  Shared installer library (download, verification, config, system integration).
kleos-install       TUI installer (ratatui wizard).
kleos-install-gui   GUI installer (eframe/egui wizard).
```

**Key rule:** domain logic goes in `kleos-lib`. Server routes go in `kleos-server`. Don't put business logic in the server crate.

## Development Workflow

### Before You Code

1. Check existing issues - someone might already be working on it
2. Open an issue first for significant changes - lets us discuss the approach before you invest time

### Setup (once per clone)

```bash
# Install the tracked git hooks: rustfmt-on-commit, and a pre-push gate that
# runs the CI checks locally so a 25-minute CI cycle never fails on a lint.
scripts/install-git-hooks.sh
```

### While Coding

```bash
# Verify it compiles after every change
cargo check --workspace

# Run tests (in-memory SQLite, no external deps)
cargo test --workspace --exclude kleos-migrate

# Lint before committing - warnings are errors
cargo clippy --workspace -- -D warnings
```

### Before Pushing

Run the local gate before pushing -- this matches most of what `ci.yml` runs,
and is what the pre-push hook runs for you:

```bash
# Fast gate (fmt + clippy + cargo-deny + MSRV) -- a couple of minutes:
scripts/preflight.sh

# Full gate (also cargo check + the workspace test suite):
scripts/preflight.sh --full
```

The individual commands, if you prefer to run them by hand:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --exclude kleos-migrate --all-targets -- -D warnings
cargo test --workspace --exclude kleos-migrate
cargo deny check        # licenses, sources, advisories, bans -- fails independently of your code
```

`preflight.sh` and the plain `cargo test` command above run the workspace test
suite serially through the stock test harness -- close enough for local
iteration, but not what CI actually runs. CI runs the same tests through
`cargo-nextest`, split across a 2-way hash partition, for exact parity:

```bash
# Install cargo-nextest (same release ci.yml pins)
curl -LsSf "https://get.nexte.st/0.9.138/linux" | tar zxf - -C "${CARGO_HOME:-$HOME/.cargo}/bin"

# Reproduce a CI partition locally (partition N of 2)
cargo nextest run --workspace --exclude kleos-migrate --partition "hash:1/2"

# Or run the whole suite through nextest without partitioning
cargo nextest run --workspace --exclude kleos-migrate
```

Release builds run separately, on the project's self-hosted Woodpecker runner
via `.woodpecker.yml`, triggered by `v*` tags. GitHub Actions (`ci.yml`) only
runs the PR/push checks above.

### Code Style

- Follow existing patterns in the codebase
- Prefer surgical edits over large rewrites
- Don't add features beyond what's asked
- Don't add speculative abstractions
- New modules must be declared in the parent `mod.rs` with `pub mod`
- DTOs and request/response types go in `types.rs` within each module

### Commit Messages

- One logical change per commit
- Present tense, imperative mood: "add feature" not "added feature"
- First line under 72 characters
- Reference issues when applicable: "fix memory leak in search (#42)"

### Signed Commits

`main` requires every commit to carry a **verified signature**. If your commits
are unsigned, GitHub shows an "Unverified" badge and the PR cannot be merged.
GitHub does not warn you about this when you push, so set signing up once before
you contribute.

The simplest path is **SSH signing** -- you already have an SSH key for GitHub:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub   # your public key
git config --global commit.gpgsign true
```

Then add that same key as a **Signing Key** under GitHub -> Settings -> SSH and
GPG keys. A signing key is a separate entry from an authentication key, even
when it is the same file -- without it GitHub cannot verify your signature.

GPG and S/MIME signing work too if you prefer them; see GitHub's "About commit
signature verification" documentation. Verify locally before pushing:

```bash
git log --show-signature -1     # expect: Good "git" signature ...
```

If you have already pushed unsigned commits, re-sign them with
`git rebase --exec 'git commit --amend --no-edit -S' -i <base>` and force-push
the branch.

## Pull Requests

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run `scripts/preflight.sh` (or `--full` to include tests)
5. Push and open a PR

### PR Checklist

- [ ] `cargo fmt --all -- --check` is clean
- [ ] `cargo clippy --workspace --exclude kleos-migrate --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace --exclude kleos-migrate` passes (or `cargo nextest run --workspace --exclude kleos-migrate` for exact CI parity, see [Before Pushing](#before-pushing))
- [ ] `cargo deny check` passes (licenses, sources, advisories, bans)
- [ ] New code has tests where applicable
- [ ] Documentation updated if behavior changes
- [ ] Commits are signed with a verified signature (see Signed Commits above)
- [ ] No unrelated changes in the PR

## Testing

Tests use in-memory SQLite - no database setup needed. Each test gets isolated state.

```rust
#[tokio::test]
async fn test_search_returns_recent_memories_first() {
    let db = Database::connect_memory().await.unwrap();
    // ... test logic
}
```

- Use `#[tokio::test]` for async tests
- Name tests descriptively: `test_search_returns_recent_memories_first`
- Tests run with `cargo test --workspace --exclude kleos-migrate` -- no feature flags needed

## Common Pitfalls

1. **Wrong import paths** - check `kleos-lib/src/lib.rs` for what's exported
2. **Forgetting `pub mod`** - new modules must be declared in parent `mod.rs`
3. **Moving out of borrows** - use `.clone()` or restructure; the compiler tells you exactly what's wrong
4. **Missing Cargo.toml deps** - add workspace deps before using them
5. **Not running cargo check** - Rust errors are precise; read them before asking for help
6. **Feature-gated code** - the `brain` module requires `brain_hopfield` feature flag

## Feature Flags

| Crate | Flag | Default | Purpose |
|-------|------|---------|---------|
| `kleos-lib` | `brain_hopfield` | on | Brain module, Hopfield networks, spreading activation |
| `kleos-lib` | `piv` | off | PIV/YubiKey smartcard auth (pulls in PC/SC; needs `libpcsclite-dev` on Linux) |
| `kleos-lib` | `sqlcipher` | off | SQLCipher at-rest encryption (required for `KLEOS_ENCRYPTION_MODE` != `none`) |
| `kleos-lib` | `sqlcipher-vendored` | off | SQLCipher with vendored OpenSSL (cross-compile targets) |
| `kleos-lib` | `vendored-openssl` | off | Vendor OpenSSL from source (cross-compile targets) |
| `kleos-lib` | `bundled-sqlite` | off | Vendor SQLite from source (needed on Windows) |
| `kleos-lib` | `tenant-sharding` | off | Per-tenant database sharding |
| `kleos-lib` | `test-utils` | off | Test helpers for downstream crates |
| `kleos-lib` | `credd-raw` | off | Raw credential access support |
| `kleos-mcp` | `piv` | on | PIV/YubiKey request signing (disable with `--no-default-features`) |
| `kleos-mcp` | `http` | off | HTTP transport (default is stdio only) |
| `kleos-client` | `piv` | on | PIV/Ed25519 envelope signing |
| `kleos-cred` | `gui` | off | eframe-based credential manager GUI (`cred-gui` binary) |

## Migration Tool

`kleos-migrate` copies data from an encrypted SQLCipher monolith database into a per-tenant shard. It filters rows by `--filter-user-id` and writes them to a new tenant directory with `kleos.db` and LanceDB vector index. One-shot utility, not part of normal operation.

```bash
cargo run -p kleos-migrate -- --source system.db --target /data/tenants/1 --filter-user-id 1
```

Use `--dry-run` to preview per-table counts without writing. Use `--handoffs-source` to migrate a legacy handoffs database into the target shard.

## Questions?

- Open a discussion on the repo
- Check existing issues and PRs

## License

By submitting a contribution, you license it under the PolyForm Noncommercial License 1.0.0 and grant the project owner a perpetual, worldwide, irrevocable, royalty-free right to use, modify, sublicense, and relicense your contribution under any terms, including commercial terms.
