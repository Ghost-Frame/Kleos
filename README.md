<div align="center">

<img src="docs/assets/banner.svg" width="800" alt="Kleos Banner" />

# Kleos

**Cognitive infrastructure for AI agents. Not a memory engine -- a full operating system for how agents think, learn, coordinate, and stay safe.**

[![License](https://img.shields.io/badge/License-Elastic--2.0-blue.svg)](LICENSE) [![Rust](https://img.shields.io/badge/rust-1.94%2B-orange.svg)](https://www.rust-lang.org) [![Native](https://img.shields.io/badge/Native-No%20Python-blueviolet.svg)](#) [![Discord](https://img.shields.io/discord/1508468167423430757?label=Discord&logo=discord&logoColor=white&color=5865F2)](https://discord.gg/fKyMpE34fm)

[Quickstart](https://github.com/Ghost-Frame/Kleos/wiki/Getting-Started) · [Why Kleos](https://github.com/Ghost-Frame/Kleos/wiki/Why-Kleos) · [Wiki](https://github.com/Ghost-Frame/Kleos/wiki) · [Discord](https://discord.gg/fKyMpE34fm)

</div>

---

Kleos is not a memory engine. Calling it one is like calling a brain a hard drive.

Yes, Kleos stores and retrieves memories. But it also consolidates them overnight through a six-stage dream cycle. It builds a knowledge graph with causal reasoning and community detection. It assembles context for LLMs through eight parallel retrieval layers with token budget management. It enforces structured reasoning protocols so agents spec before they code and hypothesize before they debug. It runs seven neuroscience-named coordination services for multi-agent orchestration. It gates every shell command and filesystem operation through a security policy engine. It watches agent sessions in real time and injects corrections when they drift.

The difference between Kleos and a memory tool is the difference between a notebook and a nervous system.

One Rust binary. Self-hosted. Your data never leaves your hardware.

![Kleos CLI demo](tools/cli-demo.gif)

---

## What Kleos does

### Biological memory lifecycle

Memory in Kleos follows the same arc as biological memory -- acquisition, consolidation, decay:

- **FSRS-6 spaced repetition** with all 21 trained weights (the algorithm behind Anki). Memories strengthen with use and fade when ignored via power-law forgetting.
- **Six-stage dream cycle** runs during idle: replay, merge, prune, discover, decorrelate, resolve. Consolidates knowledge autonomously.
- **Modern Hopfield network** (feature-gated) with softmax attention and capacity exponential in dimension. Backs an associative instinct system with causal edge scoring.
- **Personality-shaped recall** -- six signal types (preference, value, motivation, decision, emotion, identity) extracted from stored text. Two agents querying the same memories get different results.
- **On-store processing** -- SimHash deduplication, SVO contradiction detection, atomic fact decomposition, entity extraction, and auto-linking all happen before the store call returns.
- **Optional human review gate (off by default).** When enabled, memories from configured sources land in a pending inbox for approve, reject, or edit before they become recallable, instead of auto-approving. Pending memories are withheld from recall, search, and listings until approved. Opt in with `KLEOS_REVIEW_GATE_ENABLED=1` plus `KLEOS_REVIEW_GATE_SOURCES` (a comma-separated source allowlist); leaving either unset keeps every store auto-approved, exactly as before.

### Context assembly

The 8-layer system that builds what the agent actually sees:

| Layer | What it retrieves |
|-------|-------------------|
| Permanent facts | Memories marked as static/always-include |
| Semantic matches | 4-channel hybrid search (vector + FTS5 + graph + personality) |
| Evolution hints | Version history and lineage of retrieved memories |
| Graph neighbors | Memories connected via typed edges or cosine similarity |
| User preferences | Scoped personality and preference signals |
| Current state | Key-value pairs representing the active environment |
| Structured facts | Subject-verb-object triples extracted from text |
| Episode summaries | High-level summaries of past interaction sessions |

All eight layers run in parallel. Results are packed into a token budget with priority-based truncation and prompt-injection sandboxing. A relevance gate then drops off-topic and noise-category memories before injection (tunable via `KLEOS_RECALL_MIN_SEMANTIC` and `KLEOS_RECALL_EXCLUDE_CATEGORIES`; curated `plan:` sources are exempt from the category filter).

### Knowledge graph

- Auto-linking via cosine similarity with typed, weighted edges: `similarity`, `updates`, `extends`, `contradicts`, `caused_by`, `prerequisite_for`, `generalizes`, `resolves`, and more
- Causal edge scoring with NLP markers (strong/context/weak weighting)
- Louvain community detection capped at 10K nodes per pass
- Weighted PageRank with temporal decay (180-day half-life) and deduplicated multi-edges
- 2-hop graph-augmented search -- initial hits expand into their neighborhood for hidden context
- Structural analysis: centrality hubs, bridge nodes between isolated communities

### Coordination

Seven neuroscience-named services sharing a single auth, audit, and rate-limit layer:

- **Axon** -- pub/sub event bus with channels, retention windows, cursor-based consumption, and webhook delivery
- **Broca** -- structured action log with causal tracing back to Axon events
- **Chiasm** -- task tracker with state machine lifecycle, history reconstruction, and multi-agent project scoping
- **Soma** -- agent registry with heartbeats, capability declarations, quality scores, and drift flags
- **Loom** -- DAG workflow engine with state persistence across server restarts
- **Thymus** -- quality evaluation with feedback signals and reinforcement learning integration
- **Brain** -- cognitive orchestrator that abstracts over Hopfield network and external backends

One `POST /activity` call fans out to all of them.

### Structured reasoning (Agent Forge)

A protocol that controls how agents think, not just what they remember:

- **Spec before code** -- `spec-task` requires acceptance criteria and edge cases before implementation begins
- **Hypothesis before fix** -- `log-hypothesis` with confidence scoring, `recall-errors` to prevent repeating mistakes
- **Verification before done** -- `verify` runs commands against spec criteria, `challenge-code` generates adversarial review
- **Human-facing spec views** -- Fluency builds render authoritative Forge records into `requirements.md`, `design.md`, and evidence-derived `tasks.md`
- **AST-aware code analysis** -- Tree-sitter parsing across Rust, TypeScript, Python, Go, C, C++, JS. `repo-map` builds ranked symbol lists within token budgets.
- **Session resilience** -- git checkpoints and rollback for recovery from destructive edits

### Skills, growth, and metacognition

- Skills with version history, execution tracking, trust scores, and lineage graphs
- LLM-backed skill evolution: analyze failure history, propose fixes, derive new skills, capture from natural language
- Cloud library for sharing skills across agents
- Growth system: agents reflect on their own patterns and materialize insights into structured memories
- Insights feed back into the spaced-repetition loop so useful self-knowledge stays accessible

### Security and policy enforcement

- **Encryption** -- SQLCipher at rest, key from file, env var, or YubiKey HMAC-SHA1 challenge-response
- **Credential vault** -- separate daemon (`kleos-credd`) with AES-256-GCM, master/agent two-tier key model, zero-knowledge agent bootstrapping via ECDH + PIV
- **Request signing** -- ECDSA-P256 or Ed25519 with replay-resistant nonces
- **Pre-action gate** -- every agent command checked against allow/warn/block policy before execution, with a human approval queue for risky operations
- **Shell command gating** (`kleos-sh`) -- static validation, SSRF guard, metacharacter blocking, Claude Code hook integration
- **Filesystem sandboxing** (`kleos-fs`) -- AST-aware read/write/edit with configurable allowed roots and path traversal prevention
- **Agent-marked shells** -- `cred get` blocked in agent contexts to prevent secret exfiltration; agents must use `cred exec` for subprocess injection
- **Audit log on every mutation**

### Real-time supervision

- **Eidolon supervisor** watches agent session transcripts as they're written, using async file-system monitoring with LRU-cached file positions
- **Rule-based detection** -- regex pattern matching on assistant text, tool commands, and commit messages
- **Retry loop detection** -- catches agents stuck repeating the same failing command (3+ consecutive repeats)
- **Scope enforcement** -- validates file modifications stay within allowed directory prefixes
- **Three-destination alerting** -- Kleos inbox (human review), Axon event bus (automation), supervisor inject (direct agent intervention)
- **Cooldown management** -- per-rule throttling prevents alert fatigue from runaway processes
- **Server can inject corrections or block the agent's next action**

---

<details>
<summary><strong>Quick start</strong></summary>

<br>

**Install with the interactive installer (recommended):**

Prebuilt binary installers ship for linux-x64: a TUI installer (`kleos-install`) and a GUI installer (`kleos-install-gui`). Download the latest from [Releases](https://github.com/Ghost-Frame/Kleos/releases), then run:

```bash
# TUI installer (terminal) -- linux-x64
./kleos-install

# GUI installer (desktop) -- linux-x64
./kleos-install-gui
```

On Windows, install with the PowerShell script (it fetches the windows-x64 binaries from the latest release):

```powershell
irm https://raw.githubusercontent.com/Ghost-Frame/Kleos/main/dist/install.ps1 | iex
```

Other platforms build from source (below).

The installer walks you through component selection, server configuration, embedding provider setup, security key generation, and optional systemd/launchd service registration. Choose a profile (Server, Agent Host, Full, Custom) or pick individual components.

**Or build from source:**

```bash
git clone https://github.com/Ghost-Frame/Kleos.git && cd Kleos

# System packages (Debian/Ubuntu): protobuf-compiler builds the proto-based
# vector-store dependency (LanceDB); libpcsclite-dev is for the PIV/YubiKey
# smartcard path. Both are pulled in by the default workspace build.
sudo apt install protobuf-compiler libpcsclite-dev

cargo build --release -p kleos-server -p kleos-cli
KLEOS_BOOTSTRAP_SECRET=pick-a-secret \
KLEOS_SESSION_KEY=$(openssl rand -hex 32) \
  ./target/release/kleos-server
```

`KLEOS_SESSION_KEY` is a 32-byte hex HMAC key for session tokens. Leave it
unset for a quick local try and the server generates an ephemeral one at
startup (with a warning) -- fine for one run, but sessions won't survive a
restart. Set it explicitly for anything you plan to keep running.

Server starts on `127.0.0.1:4200`. In another terminal:

**First run:** with default features, the server background-downloads its local
ML models from Hugging Face the first time it starts -- a bge-m3 embedding model
and a cross-encoder reranker (quantized ONNX by default; several hundred MB
each, up to ~2.3 GiB if you switch the embedder to the FP32 variant). They land
under `<data dir>/engram/models/<model-name>` (e.g.
`~/.local/share/engram/models/bge-m3` on Linux), and future restarts skip the
download once the files are present. For air-gapped or pre-staged deployments,
set `KLEOS_EMBEDDING_OFFLINE_ONLY=1` to make a missing model file a hard error
instead of a network fetch, and pre-stage the files yourself (`KLEOS_EMBEDDING_MODEL_DIR`
/ `KLEOS_RERANKER_MODEL_DIR` control where they're expected). Point `KLEOS_EMBEDDING_URL`
and/or `KLEOS_RERANKER_URL` (with `KLEOS_RERANKER_BACKEND=http`) at a remote
provider instead, and the server skips its local download and ONNX runtime
entirely for that model. To leave the whole local inference stack out of the
binary, build with `--no-default-features` (the default-on `ml` cargo feature
gates the ONNX/LanceDB stack; retrieval degrades to FTS + sqlite-vec and the
remote providers above).

**Bootstrap your admin key (one-time):**

```bash
curl -X POST http://localhost:4200/bootstrap \
  -H "Content-Type: application/json" \
  -d '{"secret": "pick-a-secret"}'
```

**Store a memory:**

```bash
curl -X POST http://localhost:4200/store \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"content": "Production DB is PostgreSQL 16 on db.example.com:5432", "category": "reference"}'
```

**Search by meaning:**

```bash
curl -X POST http://localhost:4200/search \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query": "database connection info"}'
```

For Claude Code hooks, encryption setup, the session sidecar, and client SDKs, see the [Getting Started](https://github.com/Ghost-Frame/Kleos/wiki/Getting-Started) guide.

</details>

<details>
<summary><strong>For developers: integration and architecture</strong></summary>

<br>

### Connecting your agent

Kleos speaks three protocols:

| Protocol | Details |
|----------|---------|
| **HTTP API** | 59 route modules -- memory, search, graph, coordination, skills, growth, ingestion, approvals, admin. Bearer token or signed-request auth. |
| **MCP** | Curated daily-driver tool registry over stdio. Drop into Claude Code, Cursor, or any MCP-compatible client. See `docs/MCP_CLIENT_SETUP.md` for known-good client configs. |
| **Client SDKs** | TypeScript, Python (Pydantic v2 + httpx), Go (stdlib only). First-party, typed, tested. |

### Claude Code integration

The `hooks/` bundle is under maintenance and not currently shipped. For
session-start (and other lifecycle) integration today, call the `kleos-cli hook`
subcommands directly from your own hook scripts -- `kleos-cli hook session-start`,
`user-prompt`, `stop`, `pre-tool`, `post-tool`, and `post-bash` are supported and
documented in `docs/KLEOS_OPERATIONS_MANUAL.md`. The mandatory-rules text these
hooks inject is operator-configurable via the `KLEOS_MANDATORY_RULES` environment
variable on the server. A new hooks bundle will ship once the surface stabilises.

### What runs inside

26-crate Rust workspace. The server handles:

- **Multi-tenancy** -- each tenant gets its own encrypted SQLite database, connection pools, and quota limits
- **8 middleware layers** -- auth, per-tenant rate limiting, audit log, IP extraction, JSON depth limits, Prometheus metrics, safe-mode, compression/timeouts
- **7 coordination services** -- Axon, Broca, Chiasm, Soma, Loom, Thymus, Brain
- **Skills platform** -- CRUD, versioned evolution, execution tracking, trust scoring, judgments, cloud library, LLM-backed fix/derive/capture
- **Growth engine** -- self-reflection, pattern observation, insight materialization
- **Ingestion pipeline** -- Markdown, JSON/JSONL, CSV, PDF, ZIP. Semantic chunking, format-aware parsing, Mem0/SuperMemory import
- **Resilience** -- circuit breakers, exponential backoff with jitter, dead-letter queue for failed operations

### Session sidecar

`kleos-sidecar` sits between your agent and the server:

- Buffers observations in memory instead of blocking on every write
- Batched flushing to the server
- Hook-driven repository refresh for deterministic local code context
- `off`, `shadow`, and `inject` rollout modes with an independent code token budget
- In-memory session continuity without a local AI runtime or transcript watcher

### Security model

- SQLCipher encryption at rest -- key from file, env var, or YubiKey HMAC-SHA1
- Bearer tokens hashed with SHA-256 and peppered
- Request signing via ECDSA-P256 or Ed25519 with replay-resistant nonces
- Credential daemon (`kleos-credd`) -- AES-256-GCM vault, master/agent two-tier key model
- Zero-knowledge agent bootstrapping via ECDH + PIV
- Pre-action gate: allow/warn/block with human approval queue
- Shell command gating with static validation and SSRF guard
- Session grants with configurable TTL
- Audit log on every mutation

### Building from source

```bash
# Server-only (recommended for self-hosting)
cargo build --release -p kleos-server -p kleos-cli -p kleos-mcp

# Agent-host (CLI tools, credential daemon, supervisor)
cargo build --release -p kleos-cli -p kleos-sh -p kleos-cred -p kleos-credd \
  -p agent-forge -p eidolon-supervisor

# Full workspace (all 26 crates -- needs ~8 GiB RAM)
cargo build --release --workspace
```

The server-only build skips heavy workspace crates (approval TUI, tree-sitter
parsers, supervisor) and finishes significantly faster.

```bash
cargo test --workspace --exclude kleos-migrate                                # test suite
cargo clippy --workspace --exclude kleos-migrate --all-targets -- -D warnings # lint gate
```

Requires Rust 1.94+, `protoc`, and `libpcsclite-dev` (Linux) for smartcard support.

</details>

<details>
<summary><strong>For researchers: the cognitive science</strong></summary>

<br>

### Spaced repetition (FSRS-6)

- All 21 trained weights from the Free Spaced Repetition Scheduler (same algorithm behind Anki)
- Dual-strength model: storage strength accumulates with use, retrieval strength decays via power-law forgetting
- Live retrievability modulates search scores in real time
- Memories the agent uses stay sharp; ignored ones drift out of the way without deletion

### Hybrid retrieval

Four channels run per query:

| Channel | Implementation |
|---------|---------------|
| **Vector similarity** | BAAI/bge-m3 ONNX embeddings (1024-dim), LanceDB ANN index |
| **Full-text** | FTS5 BM25 scoring |
| **Graph traversal** | 2-hop expansion weighted by typed edges and PageRank |
| **Personality signals** | Preference, value, motivation, decision, emotion, identity |

- Results merge through Reciprocal Rank Fusion
- Question-type detection classifies the query (fact recall, preference, reasoning, generalization, timeline) and reweights channels
- IBM Granite cross-encoder reranks the top-K
- Contradiction damping suppresses stale markers ("no longer," "switched from," etc.)

### Knowledge graph

- Auto-linking by cosine similarity with six typed edges: `similarity`, `updates`, `extends`, `contradicts`, `caused_by`, `prerequisite_for`
- Link-type weights so a "causes" edge outranks an "extends" edge
- Louvain community detection capped at 10K nodes per pass
- Weighted PageRank with deduplicated multi-edges
- Sliding-window entity cooccurrence
- Structural and impact analysis

### Hopfield network (feature-gated)

- Continuous Hopfield network (Ramsauer et al. 2020) with softmax attention and capacity exponential in dimension
- Embedding compression via PCA using power iteration and deflation -- no LAPACK dependency
- Six-stage dream cycle during idle: replay, merge, prune, discover, decorrelate, resolve

### Personality engine

- Six signal types extracted from stored text: preference, value, motivation, decision, emotion, identity
- Each signal carries a subject, valence (positive/negative/neutral/mixed), intensity in [0,1], and the reasoning that produced it
- Recall is shaped by personality context -- two agents querying the same memories get different results

### Growth and self-reflection

- Agents reflect on recent activity to generate pattern observations
- Materialization converts raw observations into structured insight memories
- Deduplication against existing observations
- Integration with the spaced-repetition loop so useful insights stay accessible

### On-store processing

- SimHash near-duplicate suppression
- SVO contradiction detection against a structured-fact triple store
- Atomic fact decomposition (LLM-first with rule-based fallbacks) -- splits long memories into self-contained facts linked via `has_fact` edges

### Skill evolution

- Skills are versioned, tracked, and judged
- LLM analyzes execution history and proposes fixes for failed skills
- New skills can be derived from existing ones or captured from natural language
- Trust scores aggregate execution success rates and human/agent judgments
- Lineage graph tracks which skills evolved from which

</details>

<details>
<summary><strong>For those evaluating the engineering</strong></summary>

<br>

### Scope

- 26 Rust crates, ~211K lines of Rust across 621 files
- ~1,800 test declarations (`#[test]` / `#[tokio::test]`) across 246 files
- Single statically linked binary with the mimalloc allocator
- No Python runtime. No external service dependencies at rest.

### Workspace

| Crate | What it does |
| --- | --- |
| `kleos-lib` | Core library: memory, search, embeddings, graph, intelligence, services, skills, growth, auth, gate, jobs. Feature-gated `brain` backend. |
| `kleos-server` | Axum HTTP server. 59 route modules, 8 middleware layers, embedded React web GUI (dashboard + 3D memory graph). |
| `kleos-config` | Shared configuration types and environment resolution, used by both the server and the installer so the two never drift. |
| `kleos-cli` | Command-line client. Memory ops, skill management, handoffs, credential management. |
| `kleos-client` | Shared Rust HTTP client with PIV/Ed25519 envelope signing. |
| `kleos-mcp` | MCP transport bridge. Curated daily-driver registry with compatibility aliases; stdio by default, HTTP behind a feature flag. |
| `kleos-sidecar` | Session-scoped memory proxy. Batched flushing and hook-driven local code-context retrieval. |
| `kleos-cred` | Credential library. YubiKey challenge-response, Argon2id KDF, ECDH agreement, CRED:v3 vault resolution. |
| `kleos-credd` | Base credential daemon. Two-tier auth (master + agent keys), AES-256-GCM encryption, zero-knowledge agent bootstrap. |
| `kleos-phylax` | Agent-native credential authority library: approvals, leases, ECDH, namespaces. |
| `kleos-phylaxd` (`phylaxd`) | Composes `kleos-credd`'s base router with Phylax agent-native security policy enforcement; behaves as plain `credd` with no policies set. Not yet part of releases or the installer -- `kleos-credd` is the credential daemon that actually ships as the `credd` service. |
| `kleos-phylax-ssh-agent` | OpenSSH agent protocol server: wire protocol and KeyProvider trait. |
| `kleos-phylax-ssh-agentd` | Headless SSH agent daemon that brokers keys and signing through phylaxd. |
| `kleos-token-client` | Tiny std-only client for the phylaxd SO_PEERCRED token broker (no kleos-lib dependency). |
| `kleos-ingest` | Transcript ingest daemon. PIV/software-key request signing, file watching, LLM summarization, real-time observation streaming. |
| `agent-forge` | Structured reasoning CLI. 20+ subcommands. Tree-sitter AST parsing for 7 languages. |
| `forge` | agent-forge compute engine as a library (repo-map, code search, comment-check, challenge-code), used server-side by kleos-server. |
| `eidolon-supervisor` | Session drift detection daemon. Real-time transcript watching, rule-based alerts. |
| `kleos-sh` | Shell command gate. Static validation, SSRF guard, human approval queue. |
| `kleos-fs` | AST-aware filesystem operations. Guarded read/write with agent-forge integration. |
| `kleos-migrate` | One-shot ETL from encrypted monolith to per-tenant shards. |
| `kleos-cleanup` | Deduplication and log demotion utility. |
| `kleos-approval-tui` | Ratatui terminal UI for human-in-the-loop approval workflows. |
| `kleos-install` | TUI installer. Ratatui-based interactive setup wizard with profile selection, config generation, and service registration. |
| `kleos-install-gui` | GUI installer. eframe/egui desktop wizard with the same capabilities as the TUI installer. |
| `kleos-install-core` | Shared installer library. Download, verification, config generation, system integration logic. |
| `sdk` | Client SDKs: TypeScript, Python, Go. |

### Design decisions

- **No external services** -- embeddings run locally via ONNX, vector storage is embedded LanceDB, coordination is in-process. No message broker. No Python runtime.
- **Database-per-tenant isolation** -- not schema-per-tenant, not row-level. Each tenant gets its own SQLite file with its own encryption key and connection pool.
- **ServiceGuard on all external calls** -- three-state circuit breaker + exponential backoff + dead-letter queue. Failed work is inspectable and replayable.
- **Hardware-anchored trust** -- YubiKey-derived keys for both credential daemon and server. PIV request signing. ECDH agent bootstrapping so API keys never hit disk in plaintext.
- **Phylax credential authority** -- clients prefer `PHYLAXD_URL` for the
  external credential authority and keep `CREDD_URL` as a transition fallback.
- **Skills as a first-class system** -- versioned, trust-scored, LLM-evolvable, with execution analytics, judgment history, and lineage tracking.
- **Built-in supervision** -- Eidolon watches agent sessions in real time and can intervene before damage is done.

### Install profiles

The installer (`kleos-install` or `kleos-install-gui`) supports four profiles:

| Profile | Includes |
|---------|----------|
| `Server` | kleos-server, kleos-cli |
| `Agent Host` | kleos-cli, kleos-sh, agent-forge, eidolon-supervisor, cred, kleos-credd |
| `Full` | Every binary |
| `Custom` | Pick individual components |

</details>

---

<div align="center">

[Wiki](https://github.com/Ghost-Frame/Kleos/wiki) · [Issues](https://github.com/Ghost-Frame/Kleos/issues)

PolyForm Noncommercial License 1.0.0

</div>

### Commercial licensing

Kleos is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE). Personal, hobby, research, and other noncommercial use is permitted. Any commercial use, including selling, reselling, hosting, bundling, or otherwise earning revenue from this software, requires a separate written commercial license. Contact support@syntheos.dev.
