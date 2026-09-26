mod doctor;
mod hook;
mod import_plugins;
use hook::{run_hook, HookCommands};
use kleos_client::{truncate, Client};
use kleos_lib::config::DEFAULT_CREDENTIAL_AUTHORITY_URL;
use std::time::Duration;

use clap::{Parser, Subcommand};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::{json, Value};

#[derive(Parser)]
#[command(name = "kleos-cli")]
#[command(about = "Kleos memory system CLI", long_about = None)]
/// Top-level CLI entry point; selects the server URL and dispatches subcommands.
struct Cli {
    /// Server URL
    #[arg(long, default_value = "http://127.0.0.1:4200", env = "KLEOS_URL")]
    server: String,

    /// Preferred Phylax credential authority URL
    #[arg(long, visible_alias = "credential-authority-url", env = "PHYLAXD_URL")]
    phylaxd_url: Option<String>,

    /// Legacy credd daemon URL
    #[arg(long, env = "CREDD_URL")]
    credd_url: Option<String>,

    /// API key
    #[arg(long)]
    key: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

/// Resolve preferred and legacy credential authority URL inputs.
fn resolve_credential_authority_url(phylaxd_url: Option<&str>, credd_url: Option<&str>) -> String {
    phylaxd_url
        .or(credd_url)
        .unwrap_or(DEFAULT_CREDENTIAL_AUTHORITY_URL)
        .to_string()
}

/// All top-level subcommands available through `kleos-cli`.
#[derive(Subcommand)]
enum Commands {
    /// Store a new memory
    Store {
        /// Memory content
        content: String,
        /// Category (task, discovery, decision, state, issue, general, reference)
        #[arg(short, long, default_value = "general")]
        category: String,
        /// Importance score 0-10 (integer)
        #[arg(short, long)]
        importance: Option<u8>,
        /// Comma-separated tags
        #[arg(short, long)]
        tags: Option<String>,
        /// Source identifier
        #[arg(short, long)]
        source: Option<String>,
    },
    /// Search memories
    Search {
        /// Search query
        query: String,
        /// Maximum results
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
    /// Get context for a query (richer output than search)
    Context {
        /// Query
        query: String,
        /// Maximum memories to return
        #[arg(short, long, default_value = "5")]
        limit: usize,
    },
    /// Recall a specific memory by ID
    Recall {
        /// Memory ID
        id: String,
    },
    /// Evaluate content through the guard system
    Guard {
        /// Content to evaluate
        content: String,
    },
    /// List memories
    List {
        /// Maximum results
        #[arg(short, long, default_value = "20")]
        limit: usize,
        /// Offset
        #[arg(short, long, default_value = "0")]
        offset: usize,
    },
    /// Delete a memory
    Delete {
        /// Memory ID
        id: String,
    },
    /// Bootstrap the database schema
    Bootstrap {
        /// Database path
        #[arg(short, long, default_value = "kleos.db")]
        db: String,
    },
    /// Ingest text or a file into the memory pipeline
    Ingest {
        /// Inline text to ingest (use --file for paths)
        #[arg(short, long, conflicts_with = "file")]
        text: Option<String>,
        /// Read content from a file (any supported format: .md, .txt, .html, .csv, .jsonl, .pdf, .docx, .zip)
        #[arg(short, long)]
        file: Option<std::path::PathBuf>,
        /// Ingestion mode: raw | extract
        #[arg(short, long, default_value = "raw")]
        mode: String,
        /// Source label recorded on each memory
        #[arg(short, long)]
        source: Option<String>,
        /// Category to assign
        #[arg(short, long, default_value = "general")]
        category: String,
    },
    /// Surface memories most in need of reinforcement for a topic
    RecallDue {
        /// Topic to search for
        topic: String,
        /// Maximum results
        #[arg(short, long, default_value = "5")]
        limit: usize,
        /// Session filter
        #[arg(short, long)]
        session: Option<String>,
    },
    /// Check server health
    Health,
    /// Diagnose client installation, configuration, and server access (read-only)
    Doctor {
        /// Emit the report as JSON
        #[arg(long)]
        json: bool,
        /// Directory used for project resolution (defaults to the current directory)
        #[arg(long)]
        dir: Option<String>,
    },
    /// Report an activity event (fans out to Chiasm/Axon/Broca/Thymus/Skills/Memory)
    Activity {
        /// Action (e.g. task.started, task.progress, task.completed, task.blocked, error.raised)
        #[arg(short, long)]
        action: String,
        /// Human-readable summary of what happened
        #[arg(short, long)]
        summary: String,
        /// Project label (optional)
        #[arg(short, long)]
        project: Option<String>,
        /// Agent label
        #[arg(long, default_value = "claude-code")]
        agent: String,
        /// Optional JSON object of additional metadata
        #[arg(short, long)]
        metadata: Option<String>,
    },
    /// Durable job queue inspection and control
    #[command(subcommand)]
    Jobs(JobsCommands),
    /// Skill management
    #[command(subcommand)]
    Skill(SkillCommands),
    /// Credential management (talks to credd)
    #[command(subcommand)]
    Cred(CredCommands),
    /// Session handoff management
    #[command(subcommand)]
    Handoff(HandoffCommands),
    /// Claude Code hook handlers (native replacements for bash hooks)
    #[command(subcommand)]
    Hook(HookCommands),
    /// Identity key management (PIV YubiKey + software Ed25519)
    #[command(subcommand)]
    Identity(IdentityCommands),
    /// Bearer API key management (list, revoke)
    #[command(subcommand, name = "api-key")]
    ApiKey(ApiKeyCommands),
    /// MCP direct-auth token management (mint, list, revoke)
    #[command(subcommand, name = "mcp-token")]
    McpToken(McpTokenCommands),
    /// User account management (admin-only, multi-user instances)
    #[command(subcommand)]
    User(UserCommands),
    /// Artifact storage management
    #[command(subcommand)]
    Artifact(ArtifactCommands),
    /// Admin operations (require admin role, signed request, long timeouts)
    #[command(subcommand)]
    Admin(AdminCommands),
    /// Agent-forge stateful operations (specs, hypotheses, approaches, verify, session learns)
    #[command(subcommand)]
    Forge(ForgeCommands),
}

/// Subcommands for `kleos-cli forge` -- agent-forge stateful operations.
///
/// Each subcommand maps 1:1 to a server-side HTTP route under `/forge/*`.
/// All state is stored in the Kleos tenant database; no local DB is used.
#[derive(Subcommand)]
enum ForgeCommands {
    /// Create a new task spec with acceptance criteria and file coverage for gate enforcement.
    SpecTask {
        /// Human-readable description of the task
        #[arg(long)]
        task_description: String,
        /// Category of work: feature, bugfix, refactor, enhancement, test, docs
        #[arg(long)]
        task_type: String,
        /// Acceptance criteria (pass multiple times, minimum 2)
        #[arg(long = "criterion", required = true)]
        acceptance_criteria: Vec<String>,
        /// Stable public interface description for the change
        #[arg(long)]
        interface_contract: String,
        /// Known failure modes and boundary conditions (pass multiple times, minimum 3)
        #[arg(long = "edge-case", required = true)]
        edge_cases: Vec<String>,
        /// Optional agent session identifier for gate enforcement
        #[arg(long)]
        session_id: Option<String>,
        /// Paths the agent expects to write (pass multiple times)
        #[arg(long = "file")]
        files_to_touch: Vec<String>,
        /// Free-text external dependencies or blockers
        #[arg(long)]
        dependencies: Option<String>,
    },
    /// Transition a spec to a new lifecycle status.
    UpdateSpec {
        /// ID of the spec to transition
        #[arg(long)]
        spec_id: String,
        /// New lifecycle status: active, completed, failed, blocked
        #[arg(long)]
        status: String,
        /// Optional human note recorded alongside the transition
        #[arg(long)]
        note: Option<String>,
    },
    /// List forge specs for the authenticated user, optionally filtered by status.
    ListSpecs {
        /// Filter by lifecycle status
        #[arg(long)]
        status: Option<String>,
        /// Maximum rows to return
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// Fetch one full spec by ID including related sub-records.
    GetSpec {
        /// Spec ID to fetch
        id: String,
    },
    /// Record a new hypothesis before touching code in response to a bug.
    LogHypothesis {
        /// Description of the observed bug or failure
        #[arg(long)]
        bug_description: String,
        /// Agent's proposed root cause
        #[arg(long)]
        hypothesis: String,
        /// Optional agent session identifier
        #[arg(long)]
        session_id: Option<String>,
        /// Subjective confidence in [0.0, 1.0]
        #[arg(long)]
        confidence: Option<f64>,
        /// Optional parent spec ID to link to
        #[arg(long)]
        spec_id: Option<String>,
    },
    /// Record the outcome of an existing hypothesis.
    LogOutcome {
        /// ID of the hypothesis to close
        #[arg(long)]
        hypothesis_id: String,
        /// Verdict: correct, incorrect, or partial
        #[arg(long)]
        outcome: String,
        /// Optional free-text notes about what was learned
        #[arg(long)]
        notes: Option<String>,
    },
    /// Search past hypotheses by keyword across bug description and hypothesis text.
    RecallErrors {
        /// Keyword to search in bug_description and hypothesis columns
        #[arg(long)]
        query: Option<String>,
        /// Maximum rows to return
        #[arg(long, default_value = "10")]
        limit: usize,
    },
    /// Store two or more named design alternatives and return a structured comparison prompt.
    ConsiderApproaches {
        /// Short description of the design problem being evaluated
        #[arg(long)]
        problem: String,
        /// Design alternatives as JSON objects (pass multiple times, minimum 2)
        #[arg(long = "approach", required = true)]
        approaches: Vec<String>,
        /// Optional parent spec ID to link the approaches to
        #[arg(long)]
        spec_id: Option<String>,
        /// Zero-based index of the chosen alternative, if decided
        #[arg(long)]
        chosen_index: Option<usize>,
    },
    /// Record the result of a client-side verification run against a spec criterion.
    Verify {
        /// The command string that was executed client-side
        #[arg(long)]
        command: String,
        /// Process exit code
        #[arg(long)]
        exit_code: i32,
        /// Whether the run is considered a success
        #[arg(long)]
        success: bool,
        /// Optional parent spec ID to link the record to
        #[arg(long)]
        spec_id: Option<String>,
        /// Wall-clock duration of the command in milliseconds
        #[arg(long)]
        duration_ms: Option<i64>,
        /// Zero-based index into the spec's acceptance_criteria array
        #[arg(long)]
        criteria_index: Option<i64>,
        /// Standard output (pre-clipped to 4096 bytes client-side)
        #[arg(long)]
        stdout: Option<String>,
        /// Standard error (pre-clipped to 4096 bytes client-side)
        #[arg(long)]
        stderr: Option<String>,
    },
    /// Persist a mid-session discovery to forge_session_learns.
    SessionLearn {
        /// Discovery text to persist
        #[arg(long)]
        discovery: String,
        /// Optional surrounding context (file name, function, etc.)
        #[arg(long)]
        context: Option<String>,
        /// Optional tag list for future recall filtering (pass multiple times)
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Optional parent spec ID
        #[arg(long)]
        spec_id: Option<String>,
    },
    /// Search forge_session_learns by keyword in the discovery text.
    SessionRecall {
        /// Keyword to search in the discovery column
        #[arg(long)]
        query: Option<String>,
        /// Maximum rows to return
        #[arg(long, default_value = "10")]
        limit: usize,
    },
    /// Pure structured-reasoning prompt builder; no filesystem access, no DB writes.
    Think {
        /// The problem statement to reason about
        #[arg(long)]
        problem: Option<String>,
        /// Optional constraints that bound the solution space (pass multiple times)
        #[arg(long = "constraint")]
        constraints: Vec<String>,
        /// Optional context the caller already holds
        #[arg(long)]
        context: Option<String>,
    },
    /// Partition unknowns into blocking and non-blocking sets; returns a clear action directive.
    DeclareUnknowns {
        /// Unknowns as JSON objects: {"description":"...","blocking":true} (pass multiple times)
        #[arg(long = "unknown", required = true)]
        unknowns: Vec<String>,
    },
    /// Scan a source file for declarations that lack a preceding comment.
    ///
    /// Supply exactly one of --path (server-visible) or --content-file (local file).
    CommentCheck {
        /// Server-visible absolute path to the file to scan
        #[arg(long, conflicts_with = "content_file")]
        path: Option<String>,
        /// Local file whose content is sent inline to the server
        #[arg(long)]
        content_file: Option<std::path::PathBuf>,
        /// File extension hint when using --content-file (e.g. rs, ts)
        #[arg(long)]
        extension: Option<String>,
    },
    /// Build an adversarial review prompt for a source file.
    ///
    /// Supply exactly one of --path (server-visible) or --content-file (local file).
    ChallengeCode {
        /// Server-visible absolute path to the file to review
        #[arg(long, conflicts_with = "content_file")]
        path: Option<String>,
        /// Local file whose content is sent inline to the server
        #[arg(long)]
        content_file: Option<std::path::PathBuf>,
        /// File extension hint when using --content-file (e.g. rs, ts)
        #[arg(long)]
        extension: Option<String>,
    },
    /// Walk a directory tree, extract named symbols, and return a ranked symbol map.
    ///
    /// The path must resolve within KLEOS_FORGE_FS_ROOTS on the server.
    RepoMap {
        /// Absolute path to the directory root to scan (must be within server FS roots)
        #[arg(long)]
        path: String,
        /// Path fragments to prioritise in the output (pass multiple times)
        #[arg(long = "focus")]
        focus: Vec<String>,
        /// Token budget for the output (default 4000)
        #[arg(long)]
        max_tokens: Option<usize>,
    },
    /// Walk a directory tree and return symbols whose names match a query string (case-insensitive).
    ///
    /// The path must resolve within KLEOS_FORGE_FS_ROOTS on the server.
    SearchCode {
        /// Symbol name fragment to search for
        #[arg(long)]
        query: Option<String>,
        /// Absolute path to the directory root to walk (must be within server FS roots)
        #[arg(long)]
        path: String,
        /// Optional kind filter: function, class, enum, etc.
        #[arg(long)]
        symbol_type: Option<String>,
        /// Maximum number of results to return (default 20)
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Import specs from the local agent-forge SQLite database into the Kleos server.
    ///
    /// Opens ~/.agent-forge/forge.db (or --db path), reads the `specs` table,
    /// and POSTs each row to /forge/spec-task. Rows that fail server validation
    /// (4xx) are counted as skipped; import continues regardless.
    ImportLocal {
        /// Path to the local agent-forge SQLite file (default: ~/.agent-forge/forge.db)
        #[arg(long)]
        db: Option<String>,
        /// Session ID to record on each imported spec (default: "import-local")
        #[arg(long)]
        session_id: Option<String>,
        /// Include specs whose status is not 'active' (completed, failed, blocked, etc.)
        #[arg(long)]
        include_completed: bool,
    },
    /// Show a git diff summary for the current working directory.
    ///
    /// Runs `git diff --stat` and `git diff --name-only` against the optional
    /// base ref (default: uncommitted working-tree changes). No server call is made.
    SessionDiff {
        /// Base git ref to diff against (e.g. HEAD~5, main, a commit SHA)
        #[arg(long)]
        base: Option<String>,
    },
}

/// Subcommands for `kleos-cli admin` -- long-running admin operations.
#[derive(Subcommand)]
enum AdminCommands {
    /// Backfill missing primary + chunk embeddings across all tenants. Long-running.
    BackfillChunks,
    /// Backfill associative ('similarity') links for unlinked memories across all
    /// tenants by nearest-neighbour search. Restores graph connectivity lost to a
    /// regression. Long-running. Use --dry-run first to preview counts.
    BackfillLinks {
        /// Compute how many links WOULD be created without writing any.
        #[arg(long)]
        dry_run: bool,
        /// Max unlinked memories to process per tenant (throttle). Default: 100000.
        #[arg(long, default_value_t = 100_000)]
        limit: usize,
    },
    /// Rebuild the FTS5 index on every tenant DB. Cheap.
    RebuildFts,
    /// Rebuild the Lance ANN index (IVF_HNSW_PQ) over current vectors.
    VectorRebuildIndex {
        /// Drop and recreate the existing index instead of skipping when present.
        #[arg(long)]
        replace: bool,
    },
    /// Rebuild the per-chunk LanceDB index from existing SQLite rows.
    VectorChunkSync,
    /// Report Lance / FTS / per-tenant vector health.
    VectorHealth,
    /// Drain the vector_sync_pending ledger.
    VectorSyncReplay {
        /// Max pending rows to drain in this call.
        #[arg(short, long, default_value = "5000")]
        limit: usize,
    },
}

/// Subcommands for `kleos-cli identity` -- PIV YubiKey and software Ed25519 key management.
#[derive(Subcommand)]
enum IdentityCommands {
    /// Initialize signing identity: detect PIV YubiKey or generate Ed25519 key, then enroll with server
    Init {
        /// Label for this identity key
        #[arg(short, long)]
        label: Option<String>,
        /// Force software Ed25519 even if YubiKey is available
        #[arg(long)]
        software: bool,
    },
    /// Show current local signing identity
    Status,
    /// List enrolled identity keys for the current user
    List,
    /// Revoke an enrolled identity key by ID
    Revoke {
        /// Identity key ID to revoke
        id: i64,
        /// Reason for revocation
        #[arg(short, long)]
        reason: Option<String>,
    },
}

/// Subcommands for `kleos-cli api-key` -- inspect and revoke Bearer API keys via /api-keys.
#[derive(Subcommand)]
enum ApiKeyCommands {
    /// List Bearer API keys for the current caller (admin sees all keys).
    List,
    /// Create a new Bearer API key. Admin scope required for admin-scoped keys.
    Create {
        /// Human-readable name for the key
        #[arg(short, long)]
        name: String,
        /// Comma-separated scopes: read, write, admin
        #[arg(short, long, default_value = "read,write")]
        scopes: String,
        /// Requests-per-minute rate limit (default: inherit from caller)
        #[arg(short, long)]
        rate_limit: Option<i64>,
    },
    /// Revoke a Bearer API key by ID. PIV-signed; admin scope required to revoke others.
    Revoke {
        /// API key ID to revoke
        id: i64,
    },
}

/// Subcommands for `kleos-cli mcp-token` -- mint and manage MCP direct-auth tokens.
/// These tokens let MCP clients authenticate with a static Bearer header
/// instead of per-request PIV signing.
#[derive(Subcommand)]
enum McpTokenCommands {
    /// Mint a new MCP token, register it with the server, and print the bearer string.
    Mint {
        /// Human-readable name for this token
        #[arg(short, long)]
        name: String,
        /// Comma-separated scopes (read, write, admin). No wildcards.
        #[arg(short, long, default_value = "read,write")]
        scopes: String,
        /// Token lifetime (e.g. 30d, 7d, 90d, 24h)
        #[arg(short, long, default_value = "30d")]
        ttl: String,
    },
    /// List your registered MCP tokens.
    List,
    /// Revoke a single MCP token by its jti.
    Revoke {
        /// The jti (token ID) to revoke
        jti: String,
    },
    /// Revoke all your MCP tokens.
    RevokeAll,
    /// Show details for a single MCP token by jti.
    Info {
        /// The jti (token ID) to inspect
        jti: String,
    },
}

/// Parse a human-readable TTL string like "30d", "7d", "24h" into seconds.
fn parse_ttl(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(days) = s.strip_suffix('d') {
        let n: u64 = days.parse().map_err(|_| format!("invalid TTL: {}", s))?;
        n.checked_mul(86400)
            .ok_or_else(|| format!("TTL too large: {}", s))
    } else if let Some(hours) = s.strip_suffix('h') {
        let n: u64 = hours.parse().map_err(|_| format!("invalid TTL: {}", s))?;
        n.checked_mul(3600)
            .ok_or_else(|| format!("TTL too large: {}", s))
    } else {
        s.parse::<u64>()
            .map_err(|_| format!("invalid TTL: {} (use Nd or Nh)", s))
    }
}

/// Subcommands for `kleos-cli user` -- CRUD on user accounts.
#[derive(Subcommand)]
enum UserCommands {
    /// Create a new user account on the server
    Create {
        /// Username (must be unique)
        #[arg(short, long)]
        username: String,
        /// Optional email address
        #[arg(short, long)]
        email: Option<String>,
        /// Role label (defaults to "user")
        #[arg(short, long)]
        role: Option<String>,
    },
    /// List all user accounts
    List {
        /// Include deactivated users in the output
        #[arg(long)]
        include_inactive: bool,
    },
}

/// Subcommands for `kleos-cli artifact` -- upload, list, download, and inspect artifacts.
#[derive(Subcommand)]
enum ArtifactCommands {
    /// Upload a file as an artifact attached to a memory
    Upload {
        /// Memory ID to attach the artifact to
        memory_id: i64,
        /// Path to the file to upload
        file: String,
        /// Display name (defaults to filename)
        #[arg(short, long)]
        name: Option<String>,
        /// Artifact type (defaults to "file")
        #[arg(short = 't', long)]
        artifact_type: Option<String>,
        /// Agent name
        #[arg(long, default_value = "claude-code")]
        agent: String,
    },
    /// List artifacts attached to a memory
    List {
        /// Memory ID
        memory_id: i64,
    },
    /// Download an artifact by ID
    Get {
        /// Artifact ID
        id: i64,
        /// Output file path (defaults to original filename, or stdout with -)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Delete an artifact by ID
    Delete {
        /// Artifact ID
        id: i64,
    },
    /// Full-text search across artifact name and content
    Search {
        /// FTS query string
        query: String,
        /// Maximum results to return
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
    /// Show artifact storage statistics
    Stats,
}

/// Subcommands for `kleos-cli jobs` -- durable job queue inspection and control.
#[derive(Subcommand)]
enum JobsCommands {
    /// Show queue stats (pending / running / completed / failed counts)
    Stats,
    /// List jobs filtered by status
    List {
        /// Status filter: pending | running | failed
        #[arg(short, long, default_value = "pending")]
        status: String,
        /// Maximum rows to return
        #[arg(short, long, default_value = "20")]
        limit: usize,
        /// Row offset
        #[arg(short, long, default_value = "0")]
        offset: usize,
    },
    /// Retry a failed job by id, or retry every failed job when --all is given
    Retry {
        /// Job id to retry (omit together with --all to retry every failed job)
        id: Option<i64>,
        /// Retry every failed job
        #[arg(long)]
        all: bool,
    },
    /// Delete failed jobs older than N days
    Purge {
        /// Only purge failed jobs older than this many days
        #[arg(long, default_value = "7")]
        older_than_days: i64,
    },
    /// Delete completed jobs older than N days
    Cleanup {
        /// Only remove completed jobs older than this many days
        #[arg(long, default_value = "1")]
        older_than_days: i64,
    },
}

/// Subcommands for `kleos-cli cred` -- secret CRUD and agent key management via credd.
#[derive(Subcommand)]
enum CredCommands {
    /// Get a secret value
    Get {
        /// Category (service namespace)
        category: String,
        /// Secret name
        name: String,
        /// Output raw value only (no JSON)
        #[arg(long)]
        raw: bool,
    },
    /// Set a secret
    Set {
        /// Category (service namespace)
        category: String,
        /// Secret name
        name: String,
        /// Secret type (api_key, login, oauth_app, ssh_key, note, environment)
        #[arg(short = 't', long, default_value = "api_key")]
        secret_type: String,
        /// Secret value (prompted if not provided)
        #[arg(short, long)]
        value: Option<String>,
        /// For login: username
        #[arg(long)]
        username: Option<String>,
        /// For login/oauth: URL
        #[arg(long)]
        url: Option<String>,
    },
    /// List secrets
    List {
        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,
    },
    /// Delete a secret
    Delete {
        /// Category
        category: String,
        /// Secret name
        name: String,
    },
    /// Create an agent key
    AgentCreate {
        /// Agent name
        name: String,
        /// Allowed categories (comma-separated, empty = all)
        #[arg(short, long)]
        categories: Option<String>,
        /// Allow raw access tier
        #[arg(long)]
        allow_raw: bool,
    },
    /// List agent keys
    AgentList,
    /// Revoke an agent key
    AgentRevoke {
        /// Agent name to revoke
        name: String,
    },
    /// Sync: pull all Kleos v3 entries into local credd database
    Sync,
    /// Fetch a secret from credd and exec a child command with the secret
    /// injected as an environment variable. The secret is set in the
    /// child's environment block directly and is never written to stdout,
    /// stderr, or the process command line, so it does not leak into shell
    /// history, agent context capture, or `ps` output.
    ///
    /// Example:
    ///   kleos-cli cred exec kleos my-agent --env API_KEY -- \
    ///     curl -H "Authorization: Bearer $API_KEY" http://...
    Exec {
        /// Category (service namespace)
        category: String,
        /// Secret name
        name: String,
        /// Env var name to set in the child process
        #[arg(long)]
        env: String,
        /// Specific field to extract (defaults to the primary value:
        /// key/password/client_secret/private_key/content in that order).
        #[arg(long)]
        field: Option<String>,
        /// Command + args to exec. Use `--` to separate from cred flags.
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
}

/// Subcommands for `kleos-cli skill` -- Skills Cloud CRUD, search, import, and materialization.
#[derive(Subcommand)]
enum SkillCommands {
    /// Search skills by query
    Search {
        /// Search query
        query: String,
        /// Maximum results
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
    /// List skills
    List {
        /// Maximum results
        #[arg(short, long, default_value = "20")]
        limit: usize,
        /// Offset
        #[arg(short, long, default_value = "0")]
        offset: usize,
        /// Filter by agent
        #[arg(short, long)]
        agent: Option<String>,
    },
    /// Get a skill by ID
    Get {
        /// Skill ID
        id: i64,
    },
    /// Record an execution result for a skill
    Execute {
        /// Skill ID
        id: i64,
        /// Whether the execution succeeded
        #[arg(short, long)]
        success: bool,
        /// Duration in milliseconds
        #[arg(short, long)]
        duration_ms: Option<i64>,
        /// Error type (if failed)
        #[arg(long)]
        error_type: Option<String>,
        /// Error message (if failed)
        #[arg(long)]
        error_message: Option<String>,
    },
    /// Capture a new skill from a description
    Capture {
        /// Description of the skill to capture
        description: String,
        /// Agent name
        #[arg(short, long, default_value = "claude-code")]
        agent: String,
    },
    /// Create a skill directly with code from a file
    Create {
        /// Skill name (snake_case)
        name: String,
        /// Description
        #[arg(short, long)]
        description: String,
        /// Path to file containing skill code (markdown)
        #[arg(short, long)]
        file: String,
        /// Agent name
        #[arg(short, long, default_value = "claude-code")]
        agent: String,
        /// Language
        #[arg(short, long, default_value = "markdown")]
        language: String,
    },
    /// Fix / refine an existing skill
    Fix {
        /// Skill ID
        id: i64,
        /// Direction for the fix
        #[arg(short, long)]
        direction: Option<String>,
        /// Agent name
        #[arg(short, long, default_value = "claude-code")]
        agent: String,
    },
    /// Derive a new skill from parent skills
    Derive {
        /// Parent skill IDs (at least one required)
        #[arg(required = true)]
        parent_ids: Vec<i64>,
        /// Direction for derivation
        #[arg(short, long)]
        direction: String,
        /// Agent name
        #[arg(short, long, default_value = "claude-code")]
        agent: String,
    },
    /// Show skill dashboard stats
    Stats,
    /// Show lineage for a skill
    Lineage {
        /// Skill ID
        id: i64,
    },
    /// Show recent skill evolution
    Evolve {
        /// Hours to look back
        #[arg(short = 'H', long, default_value = "24")]
        hours: u64,
        /// Maximum results
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
    /// Hybrid search across the Skills Cloud (FTS + alias + filters).
    /// Use this in place of `search` for fuzzy / on-demand dispatch.
    Find {
        /// Search query (partial name, intent, alias)
        query: String,
        /// Maximum results
        #[arg(short, long, default_value = "10")]
        limit: usize,
        /// Filter by kind: skill | agent | command | workflow
        #[arg(short, long)]
        kind: Option<String>,
        /// Filter by source plugin name
        #[arg(short, long)]
        plugin: Option<String>,
        /// Filter by tag (e.g. "af-phase:verify", "domain:code-dev")
        #[arg(short, long)]
        tag: Option<String>,
        /// Include deprecated skills in results
        #[arg(long)]
        include_deprecated: bool,
    },
    /// Print a skill's content formatted for context injection.
    /// Accepts a numeric id OR a fuzzy name; on fuzzy, picks the top match.
    Inject {
        /// Skill id (numeric) or fuzzy name
        target: String,
        /// Always pick the top match without confirmation when fuzzy
        #[arg(long)]
        top: bool,
    },
    /// Materialize a kind:agent skill to ~/.claude/agents/<plugin>__<name>.md
    /// so Claude Code's harness picks it up natively next session.
    Materialize {
        /// Skill id
        id: i64,
        /// Override target directory (default: ~/.claude/agents/)
        #[arg(long)]
        dir: Option<String>,
    },
    /// Forget a materialization (deletes the .md and the DB row).
    Dematerialize {
        /// Skill id
        id: i64,
    },
    /// Manage user-defined aliases for a skill.
    Alias {
        #[command(subcommand)]
        sub: AliasCommands,
    },
    /// Manage skill bundles (named collections).
    Bundle {
        #[command(subcommand)]
        sub: BundleCommands,
    },
    /// Walk ~/.claude/plugins/installed_plugins.json and ingest every
    /// plugin's SKILL.md / agents / commands into the Skills Cloud.
    ImportPlugins {
        /// Show what would happen without writing
        #[arg(long)]
        dry_run: bool,
        /// Only import this plugin (matches the bare plugin name)
        #[arg(short, long)]
        plugin: Option<String>,
        /// Only import plugins from this marketplace
        #[arg(short, long)]
        marketplace: Option<String>,
        /// Source override: PLUGIN=PATH (repeatable). Replaces the plugin
        /// cache install path. Used for canonical sources like ralph.
        #[arg(long = "source-override")]
        source_overrides: Vec<String>,
    },
}

// User-driven alias management. Auto-aliases come from the importer and
// don't surface here.
#[derive(Subcommand)]
enum AliasCommands {
    /// Add an alias to a skill (confidence defaults to 1.0).
    Add {
        skill_id: i64,
        alias: String,
        #[arg(short, long, default_value = "1.0")]
        confidence: f64,
    },
    /// Remove a single alias from a skill.
    Rm { skill_id: i64, alias: String },
    /// List all aliases attached to a skill.
    List { skill_id: i64 },
    /// Resolve a fuzzy alias string into ranked candidate skills.
    Resolve {
        query: String,
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
}

// Bundle CRUD + member ops.
#[derive(Subcommand)]
enum BundleCommands {
    /// List bundles with member counts.
    List {
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },
    /// Create (or upsert by name) a bundle.
    Create {
        name: String,
        #[arg(short, long)]
        description: Option<String>,
    },
    /// Show bundle metadata.
    Get { id: i64 },
    /// Delete a bundle (cascades members).
    Delete { id: i64 },
    /// Show member skill ids.
    Members { id: i64 },
    /// Add a skill to a bundle.
    Add { bundle_id: i64, skill_id: i64 },
    /// Remove a skill from a bundle.
    Remove { bundle_id: i64, skill_id: i64 },
}

/// Subcommands for `kleos-cli handoff` -- session state dump, restore, and garbage collection.
#[derive(Subcommand)]
enum HandoffCommands {
    /// Store a session handoff
    Dump {
        #[arg(long)]
        project: Option<String>,
        /// Logical stream used to group related standalone sessions.
        #[arg(long)]
        workstream: Option<String>,
        /// Human-readable session label shown during candidate selection.
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long, name = "type")]
        handoff_type: Option<String>,
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        content: Option<String>,
        #[arg(long)]
        dir: Option<String>,
    },
    /// Get latest handoff(s) with filters
    Restore {
        /// Exact handoff id to restore without inference.
        #[arg(long)]
        id: Option<i64>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        workstream: Option<String>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long, name = "type")]
        handoff_type: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long, default_value = "1")]
        limit: i64,
        #[arg(long)]
        dir: Option<String>,
    },
    /// Get the single latest handoff
    Latest {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        dir: Option<String>,
    },
    /// Gather and store mechanical state from git
    Mechanical {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        dir: Option<String>,
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        host: Option<String>,
    },
    /// List recent handoffs
    List {
        #[arg(long, default_value = "20")]
        limit: i64,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        workstream: Option<String>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long, name = "type")]
        handoff_type: Option<String>,
    },
    /// List the newest checkpoint for each stable session identity.
    Candidates {
        #[arg(long, default_value = "20")]
        limit: i64,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        workstream: Option<String>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        since: Option<String>,
    },
    /// Full-text search across handoff content
    Search {
        query: String,
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = "10")]
        limit: i64,
    },
    /// Show database statistics
    Stats,
    /// Garbage-collect old handoffs
    Gc {
        #[arg(long)]
        tiered: bool,
        #[arg(long)]
        keep: Option<i64>,
    },
    /// Atom operations (list, packed context, supersede, decay)
    Atoms {
        #[command(subcommand)]
        cmd: AtomCommands,
    },
}

/// Subcommands for `kleos-cli handoff atoms` -- list, pack, supersede, and
/// decay handoff atoms extracted from session dumps.
#[derive(Subcommand)]
enum AtomCommands {
    /// List active atoms for a project
    List {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        atom_type: Option<String>,
        #[arg(long, default_value = "active")]
        status: String,
        #[arg(long, default_value = "50")]
        limit: i64,
        #[arg(long)]
        dir: Option<String>,
    },
    /// Get budget-packed context atoms for a project
    Packed {
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = "4000")]
        max_tokens: usize,
        #[arg(long)]
        dir: Option<String>,
    },
    /// Mark an atom as superseded by another
    Supersede {
        #[arg(long)]
        old: String,
        #[arg(long)]
        new: String,
    },
    /// Apply decay to atoms (call on session start)
    Decay {
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = "1")]
        sessions: u32,
        #[arg(long)]
        dir: Option<String>,
    },
}

/// Extracts a JSON value as a string, coercing integers.
fn value_as_string(value: Option<&Value>) -> Option<String> {
    value.and_then(|v| {
        v.as_str()
            .map(ToOwned::to_owned)
            .or_else(|| v.as_i64().map(|n| n.to_string()))
            .or_else(|| v.as_u64().map(|n| n.to_string()))
    })
}

/// Reads the API key from KLEOS_API_KEY or ENGRAM_API_KEY env vars.
fn direct_env_api_key() -> Option<String> {
    std::env::var("KLEOS_API_KEY")
        .ok()
        .filter(|k| !k.trim().is_empty())
        .or_else(|| {
            kleos_lib::kleos_env("API_KEY")
                .ok()
                .filter(|k| !k.trim().is_empty())
        })
}

/// CLI entry point -- parses args and dispatches subcommands.
#[tokio::main]
async fn main() {
    kleos_lib::config::migrate_env_prefix();

    // yubikey=off suppresses the upstream crate's "no YubiKey detected!" ERROR
    // emitted on every probe when no card is plugged in. We handle the Err
    // return explicitly in RequestSigner::from_yubikey, so the tracing log
    // is just stderr noise on YubiKey-less hosts.
    let _otel_guard = kleos_lib::observability::init_tracing("engram-cli", "warn,yubikey=off");

    let cli = Cli::parse();
    let host_label = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let agent_label = std::env::var("KLEOS_AGENT_LABEL").unwrap_or_else(|_| "kleos-cli".into());
    let model_label = std::env::var("KLEOS_MODEL_LABEL").unwrap_or_else(|_| "none".into());

    let signer = match kleos_lib::auth_piv::RequestSigner::from_env_or_file(
        &host_label,
        &agent_label,
        &model_label,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("warning: identity key error: {e}");
            None
        }
    };

    // Always resolve the API key. The signer takes precedence for normal
    // request auth, but enrollment and other bootstrap paths need the key.
    let api_key = if let Some(k) = cli.key.clone() {
        Some(k)
    } else if matches!(cli.command, Commands::Hook(_)) {
        direct_env_api_key()
    } else {
        let slot = kleos_lib::cred::bootstrap::current_agent_slot();
        match kleos_lib::cred::bootstrap::resolve_api_key(&slot).await {
            Ok(k) => Some(k),
            Err(e) => {
                if signer.is_none() {
                    eprintln!("warning: could not resolve API key: {}", e);
                }
                None
            }
        }
    };
    let client = Client::new(cli.server.clone(), api_key.clone(), signer);

    match &cli.command {
        Commands::Store {
            content,
            category,
            importance,
            tags,
            source,
        } => {
            let tags_list: Vec<String> = tags
                .as_deref()
                .unwrap_or("")
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();

            let mut body = json!({
                "content": content,
                "category": category,
            });

            if let Some(imp) = importance {
                body["importance"] = json!(imp);
            }
            if !tags_list.is_empty() {
                body["tags"] = json!(tags_list);
            }
            if let Some(src) = source {
                body["source"] = json!(src);
            }

            match client.post("/store", body).await {
                Ok(v) => {
                    if let Some(existing_id) = value_as_string(v.get("existing_id")) {
                        println!("Duplicate of #{}", existing_id);
                    } else if let Some(id) = value_as_string(v.get("id")) {
                        println!("Stored memory #{}", id);
                    } else {
                        println!("{}", serde_json::to_string_pretty(&v).unwrap());
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        Commands::Search { query, limit } => {
            let body = json!({ "query": query, "limit": limit });
            match client.post("/search", body).await {
                Ok(v) => {
                    let results = v.as_array().cloned().unwrap_or_else(|| {
                        v.get("results")
                            .and_then(|r| r.as_array())
                            .cloned()
                            .unwrap_or_default()
                    });
                    if results.is_empty() {
                        println!("No results.");
                    }
                    for item in &results {
                        let id = value_as_string(item.get("id")).unwrap_or_else(|| "?".to_string());
                        let score = item
                            .get("score")
                            .and_then(|x| x.as_f64())
                            .map(|s| format!("{:.3}", s))
                            .unwrap_or_else(|| "?".to_string());
                        // SEC-recall-1.6: surface the per-channel breakdown
                        // when the server returns it. Each field is optional;
                        // a "-" placeholder keeps columns aligned for hits that
                        // arrived only via FTS or graph (no cosine signal).
                        let semantic = item
                            .get("semantic_score")
                            .and_then(|x| x.as_f64())
                            .map(|s| format!("{:.3}", s))
                            .unwrap_or_else(|| "-".to_string());
                        let fts = item
                            .get("fts_score")
                            .and_then(|x| x.as_f64())
                            .map(|s| format!("{:.3}", s))
                            .unwrap_or_else(|| "-".to_string());
                        let content = item.get("content").and_then(|x| x.as_str()).unwrap_or("");
                        println!(
                            "#{} [final={} cos={} bm25={}] {}",
                            id,
                            score,
                            semantic,
                            fts,
                            truncate(content, 100)
                        );
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        Commands::Context { query, limit } => {
            let body = json!({ "query": query, "context": query, "limit": limit });
            match client.post("/recall", body).await {
                Ok(v) => {
                    println!("{}", serde_json::to_string_pretty(&v).unwrap());
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        Commands::Recall { id } => match client.get(&format!("/memory/{}", id)).await {
            Ok(v) => {
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            }
            Err(e) => eprintln!("Error: {}", e),
        },

        Commands::Guard { content } => {
            let body = json!({ "action": content });
            match client.post("/guard", body).await {
                Ok(v) => {
                    let signal = v.get("signal").and_then(|s| s.as_str()).unwrap_or("?");
                    let message = v.get("message").and_then(|s| s.as_str()).unwrap_or("");
                    let rules = v
                        .get("rules")
                        .and_then(|r| r.as_array())
                        .cloned()
                        .unwrap_or_default();
                    println!("{}: {}", signal, message);
                    for rule in &rules {
                        let id = value_as_string(rule.get("id")).unwrap_or_else(|| "?".into());
                        let importance =
                            rule.get("importance").and_then(|x| x.as_i64()).unwrap_or(0);
                        let rule_content =
                            rule.get("content").and_then(|x| x.as_str()).unwrap_or("");
                        println!(
                            "  rule #{} [imp={}] {}",
                            id,
                            importance,
                            truncate(rule_content, 100)
                        );
                    }
                    if signal == "warn" || signal == "block" {
                        std::process::exit(2);
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::RecallDue {
            topic,
            limit,
            session,
        } => {
            let encoded_topic = utf8_percent_encode(topic, NON_ALPHANUMERIC).to_string();
            let mut url = format!("/fsrs/recall-due?topic={}&limit={}", encoded_topic, limit);
            if let Some(s) = &session {
                let encoded_s = utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();
                url.push_str(&format!("&session={}", encoded_s));
            }
            match client.get(&url).await {
                Ok(v) => {
                    let results = v
                        .get("results")
                        .and_then(|r| r.as_array())
                        .cloned()
                        .unwrap_or_default();
                    if results.is_empty() {
                        println!("No recall-due memories for \"{}\".", topic);
                    }
                    for item in &results {
                        let id = value_as_string(item.get("memory_id"))
                            .unwrap_or_else(|| "?".to_string());
                        let r = item
                            .get("retrievability")
                            .and_then(|x| x.as_f64())
                            .map(|v| format!("R={:.2}", v))
                            .unwrap_or_else(|| "R=?".to_string());
                        let score = item
                            .get("recall_due_score")
                            .and_then(|x| x.as_f64())
                            .map(|s| format!("{:.3}", s))
                            .unwrap_or_else(|| "?".to_string());
                        let content = item.get("content").and_then(|x| x.as_str()).unwrap_or("");
                        println!("#{} [{}] ({}) {}", id, score, r, truncate(content, 90));
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        Commands::List { limit, offset } => {
            match client
                .get(&format!("/list?limit={}&offset={}", limit, offset))
                .await
            {
                Ok(v) => {
                    let items = v.as_array().cloned().unwrap_or_else(|| {
                        v.get("results")
                            .and_then(|r| r.as_array())
                            .cloned()
                            .unwrap_or_default()
                    });
                    if items.is_empty() {
                        println!("No memories.");
                    }
                    for item in &items {
                        let id = value_as_string(item.get("id")).unwrap_or_else(|| "?".to_string());
                        let category = item.get("category").and_then(|x| x.as_str()).unwrap_or("?");
                        let content = item.get("content").and_then(|x| x.as_str()).unwrap_or("");
                        println!("#{} [{}] {}", id, category, truncate(content, 100));
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        Commands::Delete { id } => match client.delete(&format!("/memory/{}", id)).await {
            Ok(_) => println!("Deleted memory #{}", id),
            Err(e) => eprintln!("Error: {}", e),
        },

        Commands::Bootstrap { db: _ } => match client.post("/bootstrap", json!({})).await {
            Ok(v) => {
                if let Some(key) =
                    value_as_string(v.get("api_key")).or_else(|| value_as_string(v.get("key")))
                {
                    println!("{}", key);
                } else {
                    println!("{}", serde_json::to_string_pretty(&v).unwrap());
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        },

        Commands::Ingest {
            text,
            file,
            mode,
            source,
            category,
        } => {
            handle_ingest(&client, text, file, mode, source, category).await;
        }

        Commands::Health => match client.get("/health").await {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(e) => eprintln!("Error: {}", e),
        },

        Commands::Doctor { json, dir } => {
            let target = dir
                .as_ref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
            let inputs = doctor::LocalInputs {
                version: env!("CARGO_PKG_VERSION"),
                current_exe: std::env::current_exe().ok(),
                path_env: std::env::var_os("PATH"),
                server_url: cli.server.clone(),
                repo_project: detect_project_at_path(&target),
                env_project: std::env::var("SESSION_HANDOFF_PROJECT")
                    .ok()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty()),
                home: std::env::var_os("HOME").map(std::path::PathBuf::from),
                dir: target,
            };
            let mut report = doctor::Report {
                checks: doctor::local_checks(&inputs),
            };
            report
                .checks
                .extend(doctor::server_checks(&client, env!("CARGO_PKG_VERSION")).await);
            if *json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                print!("{}", report.render_text());
            }
            std::process::exit(report.exit_code());
        }

        Commands::Activity {
            action,
            summary,
            project,
            agent,
            metadata,
        } => {
            let mut body = json!({
                "agent": agent,
                "action": action,
                "summary": summary,
            });
            if let Some(p) = project {
                body["project"] = json!(p);
            }
            if let Some(m) = metadata {
                match serde_json::from_str::<Value>(m) {
                    Ok(v) => body["metadata"] = v,
                    Err(e) => {
                        eprintln!("Error: --metadata is not valid JSON: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            match client.post("/activity", body).await {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Jobs(jobs_cmd) => {
            handle_jobs_command(&client, jobs_cmd).await;
        }

        Commands::Skill(skill_cmd) => {
            handle_skill_command(&client, skill_cmd).await;
        }

        Commands::Cred(cred_cmd) => {
            // credd's auth middleware only accepts the cred master key,
            // a DB-backed agent key, or a file-backed bootstrap-agent
            // token. The Kleos bearer in `api_key` is none of those, so
            // pull credd auth from CREDD_AGENT_KEY env (set by the shell
            // rc from ~/.config/cred/credd-agent-key.token) and only
            // fall back to the Kleos bearer if that is missing.
            let credd_token = std::env::var("CREDD_AGENT_KEY")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    let path = std::env::var("HOME")
                        .map(|h| {
                            std::path::PathBuf::from(h).join(".config/cred/credd-agent-key.token")
                        })
                        .ok()?;
                    std::fs::read_to_string(path)
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                })
                .or_else(|| api_key.clone());
            let cred_authority_url = resolve_credential_authority_url(
                cli.phylaxd_url.as_deref(),
                cli.credd_url.as_deref(),
            );
            let cred_client = Client::new(cred_authority_url, credd_token, None);
            handle_cred_command(&cred_client, cred_cmd).await;
        }

        Commands::Handoff(handoff_cmd) => {
            handle_handoff_command(&client, handoff_cmd).await;
        }

        Commands::Hook(hook_cmd) => {
            run_hook(hook_cmd, &client).await;
        }

        Commands::Identity(id_cmd) => match id_cmd {
            IdentityCommands::Status => match &client.signer {
                Some(signer) => {
                    println!("Signing identity active:");
                    println!("  Fingerprint: {}", signer.fingerprint());
                    println!("  Algorithm:   {}", signer.algo().as_str());
                    println!("  Host:        {}", signer.host_label());
                    println!("  Agent:       {}", signer.agent_label());
                    println!("  Identity:    {}", signer.identity_hash());
                }
                None => {
                    eprintln!("No signing identity available.");
                    eprintln!("Run `kleos-cli identity init` to set one up.");
                    std::process::exit(1);
                }
            },

            IdentityCommands::Init { label, software } => {
                handle_identity_init(
                    &client,
                    &host_label,
                    &agent_label,
                    &model_label,
                    label.as_deref(),
                    *software,
                )
                .await;
            }

            IdentityCommands::List => match client.get("/identity-keys/mine").await {
                Ok(v) => {
                    let keys = v.get("keys").and_then(|k| k.as_array());
                    match keys {
                        Some(keys) if !keys.is_empty() => {
                            for k in keys {
                                let id = k.get("id").and_then(|i| i.as_i64()).unwrap_or(0);
                                let tier = k.get("tier").and_then(|s| s.as_str()).unwrap_or("?");
                                let algo = k.get("algo").and_then(|s| s.as_str()).unwrap_or("?");
                                let fpr = k
                                    .get("pubkey_fingerprint")
                                    .and_then(|s| s.as_str())
                                    .unwrap_or("?");
                                let host =
                                    k.get("host_label").and_then(|s| s.as_str()).unwrap_or("?");
                                let active = k
                                    .get("is_active")
                                    .and_then(|b| b.as_bool())
                                    .unwrap_or(false);
                                let enrolled =
                                    k.get("enrolled_at").and_then(|s| s.as_str()).unwrap_or("?");
                                let status = if active { "active" } else { "revoked" };
                                println!(
                                    "#{:<4} {} {} {} {} [{}] {}",
                                    id,
                                    tier,
                                    algo,
                                    &fpr[..16.min(fpr.len())],
                                    host,
                                    status,
                                    enrolled
                                );
                            }
                        }
                        _ => println!("No identity keys enrolled."),
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            },

            IdentityCommands::Revoke { id, reason } => {
                let body = json!({ "reason": reason });
                match client
                    .post(&format!("/identity-keys/{}/revoke", id), body)
                    .await
                {
                    Ok(v) => {
                        if v.get("revoked").and_then(|b| b.as_bool()).unwrap_or(false) {
                            println!("Key #{} revoked.", id);
                        } else {
                            eprintln!(
                                "Unexpected response: {}",
                                serde_json::to_string_pretty(&v).unwrap()
                            );
                        }
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
        },

        Commands::ApiKey(cmd) => match cmd {
            ApiKeyCommands::List => match client.get("/api-keys").await {
                Ok(v) => match v.get("keys").and_then(|k| k.as_array()) {
                    Some(keys) if !keys.is_empty() => {
                        println!("ID     NAME                     SCOPES               CREATED");
                        for k in keys {
                            let id = k.get("id").and_then(|x| x.as_i64()).unwrap_or(-1);
                            let name = k.get("name").and_then(|x| x.as_str()).unwrap_or("");
                            let scopes = k
                                .get("scopes")
                                .and_then(|x| x.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str())
                                        .collect::<Vec<_>>()
                                        .join(",")
                                })
                                .unwrap_or_default();
                            let created =
                                k.get("created_at").and_then(|x| x.as_str()).unwrap_or("");
                            println!("{:<6} {:<24} {:<20} {}", id, name, scopes, created);
                        }
                    }
                    _ => println!("No API keys."),
                },
                Err(e) => eprintln!("Error: {}", e),
            },
            ApiKeyCommands::Create {
                name,
                scopes,
                rate_limit,
            } => {
                let mut body = serde_json::json!({ "name": name, "scopes": scopes });
                if let Some(rl) = rate_limit {
                    body["rate_limit"] = serde_json::json!(rl);
                }
                match client.post("/api-keys", body).await {
                    Ok(v) => {
                        let full_key = v.get("full_key").and_then(|x| x.as_str()).unwrap_or("");
                        let key = v.get("key").unwrap_or(&serde_json::Value::Null);
                        let id = key.get("id").and_then(|x| x.as_i64()).unwrap_or(-1);
                        let name = key.get("name").and_then(|x| x.as_str()).unwrap_or("");
                        let scopes = key
                            .get("scopes")
                            .and_then(|x| x.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str())
                                    .collect::<Vec<_>>()
                                    .join(",")
                            })
                            .unwrap_or_default();
                        if !full_key.is_empty() {
                            println!(
                                "Created API key: id={} name=\"{}\" scopes={}",
                                id, name, scopes
                            );
                            println!();
                            println!("  {}", full_key);
                            println!();
                            println!("Save this key -- it cannot be retrieved again.");
                        } else {
                            eprintln!(
                                "Unexpected response: {}",
                                serde_json::to_string_pretty(&v).unwrap()
                            );
                        }
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            ApiKeyCommands::Revoke { id } => {
                match client.delete(&format!("/api-keys/{}", id)).await {
                    Ok(v) => {
                        if v.get("deleted").and_then(|b| b.as_bool()).unwrap_or(false) {
                            println!("API key #{} revoked.", id);
                        } else {
                            eprintln!(
                                "Unexpected response: {}",
                                serde_json::to_string_pretty(&v).unwrap()
                            );
                        }
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
        },

        Commands::McpToken(cmd) => {
            match cmd {
                McpTokenCommands::Mint { name, scopes, ttl } => {
                    // Validate scopes client-side before contacting server.
                    if let Err(e) = kleos_lib::mcp_token::parse_scopes_strict(scopes) {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                    let ttl_secs = match parse_ttl(ttl) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    };

                    // Require an identity key (Ed25519 software key).
                    let signer_ref = match &client.signer {
                        Some(s) => s,
                        None => {
                            eprintln!("Error: No identity key loaded. Run 'kleos-cli identity init' first.");
                            std::process::exit(1);
                        }
                    };
                    let sk_bytes = match signer_ref.ed25519_secret_bytes() {
                        Some(b) => b,
                        None => {
                            eprintln!("Error: MCP token minting requires an Ed25519 software key (PIV keys cannot export secrets).");
                            std::process::exit(1);
                        }
                    };
                    let kid = signer_ref.fingerprint().to_string();
                    let uid = 1_i64; // Ignored server-side; ownership is the signed identity's.

                    // Mint the token locally.
                    let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
                    let max_ttl = kleos_lib::mcp_token::DEFAULT_MAX_TTL_SECS;
                    let (token, payload) = match kleos_lib::mcp_token::mint(
                        &sk, &kid, uid, None, scopes, ttl_secs, max_ttl,
                    ) {
                        Ok(t) => t,
                        Err(e) => {
                            eprintln!("Error minting token: {}", e);
                            std::process::exit(1);
                        }
                    };

                    // Register with server via signed POST /mcp-tokens.
                    let body = serde_json::json!({
                        "token": token,
                        "name": name,
                        "scopes": scopes,
                        "ttl_secs": ttl_secs,
                    });
                    match client.post("/mcp-tokens", body).await {
                        Ok(_) => {
                            let base = client.base_url();
                            println!("\nMCP Token minted and registered.\n");
                            println!("Token (save this -- it won't be shown again):");
                            println!("  {}\n", token);
                            println!("Claude Code config (~/.claude.json or project .mcp.json):");
                            println!("  {{");
                            println!("    \"mcpServers\": {{");
                            println!("      \"kleos\": {{");
                            println!("        \"type\": \"http\",");
                            println!("        \"url\": \"{}/mcp\",", base);
                            println!("        \"headers\": {{");
                            println!("          \"Authorization\": \"Bearer {}\"", token);
                            println!("        }}");
                            println!("      }}");
                            println!("    }}");
                            println!("  }}\n");
                            println!(
                                "Expires: {}",
                                chrono::DateTime::from_timestamp(payload.exp as i64, 0)
                                    .map(|dt| dt.to_rfc3339())
                                    .unwrap_or_else(|| "unknown".into())
                            );
                            println!("Scopes: {}", scopes);
                            println!("Revoke:  kleos-cli mcp-token revoke {}", payload.jti);
                        }
                        Err(e) => {
                            eprintln!("Server rejected token registration: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                McpTokenCommands::List => match client.get("/mcp-tokens").await {
                    Ok(v) => match v.get("tokens").and_then(|k| k.as_array()) {
                        Some(tokens) if !tokens.is_empty() => {
                            println!(
                                "{:<10} {:<20} {:<12} {:<8} {:<22} LAST USED",
                                "JTI", "NAME", "SCOPES", "ACTIVE", "EXPIRES"
                            );
                            for t in tokens {
                                let jti = t["jti"].as_str().unwrap_or("?");
                                let short_jti = if jti.len() > 8 { &jti[..8] } else { jti };
                                println!(
                                    "{:<10} {:<20} {:<12} {:<8} {:<22} {}",
                                    short_jti,
                                    t["name"].as_str().unwrap_or("?"),
                                    t["scopes"].as_str().unwrap_or("?"),
                                    t["is_active"].as_bool().unwrap_or(false),
                                    t["expires_at"].as_str().unwrap_or("never"),
                                    t["last_used_at"].as_str().unwrap_or("never"),
                                );
                            }
                        }
                        _ => println!("No MCP tokens."),
                    },
                    Err(e) => eprintln!("Error: {}", e),
                },
                McpTokenCommands::Revoke { jti } => {
                    match client.delete(&format!("/mcp-tokens/{}", jti)).await {
                        Ok(_) => println!("Token {} revoked.", jti),
                        Err(e) => eprintln!("Error: {}", e),
                    }
                }
                McpTokenCommands::RevokeAll => match client.delete("/mcp-tokens").await {
                    Ok(v) => {
                        let count = v["revoked_count"].as_u64().unwrap_or(0);
                        println!("Revoked {} token(s).", count);
                    }
                    Err(e) => eprintln!("Error: {}", e),
                },
                McpTokenCommands::Info { jti } => {
                    match client.get(&format!("/mcp-tokens/{}", jti)).await {
                        Ok(v) => {
                            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
                        }
                        Err(e) => eprintln!("Error: {}", e),
                    }
                }
            }
        }

        Commands::User(user_cmd) => {
            handle_user_command(&client, user_cmd).await;
        }

        Commands::Artifact(artifact_cmd) => {
            handle_artifact_command(&client, artifact_cmd).await;
        }

        Commands::Admin(admin_cmd) => {
            handle_admin_command(&client, admin_cmd).await;
        }

        Commands::Forge(forge_cmd) => {
            handle_forge_command(&client, forge_cmd).await;
        }
    }
}

/// Dispatch an `kleos-cli admin <op>` invocation. Cheap operations
/// (rebuild_fts, vector_rebuild_index, vector_health, vector_sync_replay)
/// use a 120s timeout; `backfill_chunks` uses a 7200s (2 hour) timeout to
/// survive end-to-end re-embedding of ~10k memories with bge-m3.
async fn handle_admin_command(client: &Client, cmd: &AdminCommands) {
    // Generous timeout for long-running admin work (backfill can run 30+ min on
    // ~10k memories with bge-m3). Falls back to default for the cheap calls.
    let long_timeout = Duration::from_secs(7200);
    let short_timeout = Duration::from_secs(120);
    let pretty = |v: Value| println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    let err = |label: &str, e: String| eprintln!("{label} failed: {e}");
    match cmd {
        AdminCommands::BackfillChunks => {
            match client
                .post_with_timeout("/admin/backfill_chunks", json!({}), long_timeout)
                .await
            {
                Ok(v) => pretty(v),
                Err(e) => err("backfill_chunks", e),
            }
        }
        AdminCommands::BackfillLinks { dry_run, limit } => {
            let path = format!("/admin/backfill_links?dry_run={dry_run}&limit={limit}");
            match client
                .post_with_timeout(&path, json!({}), long_timeout)
                .await
            {
                Ok(v) => pretty(v),
                Err(e) => err("backfill_links", e),
            }
        }
        AdminCommands::RebuildFts => {
            match client
                .post_with_timeout("/admin/rebuild-fts", json!({}), short_timeout)
                .await
            {
                Ok(v) => pretty(v),
                Err(e) => err("rebuild-fts", e),
            }
        }
        AdminCommands::VectorRebuildIndex { replace } => {
            match client
                .post_with_timeout(
                    "/admin/vector/rebuild-index",
                    json!({ "replace": *replace }),
                    short_timeout,
                )
                .await
            {
                Ok(v) => pretty(v),
                Err(e) => err("vector/rebuild-index", e),
            }
        }
        AdminCommands::VectorChunkSync => {
            match client
                .post_with_timeout("/admin/vector/chunk-sync", json!({}), long_timeout)
                .await
            {
                Ok(v) => pretty(v),
                Err(e) => err("vector/chunk-sync", e),
            }
        }
        AdminCommands::VectorHealth => match client.get("/admin/vector_health").await {
            Ok(v) => pretty(v),
            Err(e) => err("vector_health", e),
        },
        AdminCommands::VectorSyncReplay { limit } => {
            match client
                .post_with_timeout(
                    "/admin/vector/sync-replay",
                    json!({ "limit": *limit }),
                    short_timeout,
                )
                .await
            {
                Ok(v) => pretty(v),
                Err(e) => err("vector/sync-replay", e),
            }
        }
    }
}

/// Initializes a new identity key pair and registers it with the server.
async fn handle_identity_init(
    client: &Client,
    host_label: &str,
    agent_label: &str,
    model_label: &str,
    label: Option<&str>,
    force_software: bool,
) {
    use kleos_lib::auth_piv::RequestSigner;

    let signer: RequestSigner;
    let key_path_msg: Option<String>;
    let serial: Option<String>;

    if force_software {
        match RequestSigner::generate_software_key(host_label, agent_label, model_label) {
            Ok((s, path)) => {
                println!("Generated Ed25519 software key at {}", path.display());
                key_path_msg = Some(path.display().to_string());
                serial = None;
                signer = s;
            }
            Err(e) => {
                eprintln!("Error generating software key: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        match RequestSigner::from_yubikey(host_label, agent_label, model_label) {
            Ok(s) => {
                let ser = s.yubikey_serial().unwrap_or_default();
                println!("Detected PIV YubiKey (serial: {})", ser);
                serial = Some(ser);
                key_path_msg = None;
                signer = s;
            }
            Err(e) => {
                eprintln!("No YubiKey detected ({}), generating software key...", e);
                match RequestSigner::generate_software_key(host_label, agent_label, model_label) {
                    Ok((s, path)) => {
                        println!("Generated Ed25519 software key at {}", path.display());
                        key_path_msg = Some(path.display().to_string());
                        serial = None;
                        signer = s;
                    }
                    Err(e2) => {
                        eprintln!("Error generating software key: {}", e2);
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    // Post-bootstrap enrollments must bind the proof to a server-issued
    // single-use nonce. Try the challenge endpoint first; when it is not
    // available (bootstrap has no credentials yet, or the server predates
    // the challenge flow) fall back to the legacy nonce-less proof.
    let nonce: Option<String> = match client
        .post("/identity-keys/enroll/challenge", json!({}))
        .await
    {
        // A successful response that lacks a usable nonce is a real problem
        // (mangled by a proxy, or a schema change) -- do not silently degrade
        // to a nonce-less proof the server will then reject. Abort with a
        // clear message instead.
        Ok(v) => match v.get("nonce").and_then(|n| n.as_str()) {
            Some(n) => Some(n.to_string()),
            None => {
                eprintln!(
                    "Enrollment challenge response did not contain a nonce; aborting. Response: {}",
                    v
                );
                std::process::exit(1);
            }
        },
        // A transport/HTTP error means the endpoint is unavailable: this is
        // the bootstrap (no credentials yet) or pre-challenge-server case, so
        // fall back to the legacy nonce-less proof.
        Err(_) => None,
    };

    let sig_result = match &nonce {
        Some(n) => signer.sign_enrollment_proof_with_nonce(n),
        None => signer.sign_enrollment_proof(),
    };
    let sig_hex = match sig_result {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error signing enrollment proof: {}", e);
            std::process::exit(1);
        }
    };
    let mut body = json!({
        "tier": signer.tier(),
        "algo": signer.algo().as_str(),
        "pubkey_pem": signer.pubkey_pem(),
        "host_label": host_label,
        "label": label,
        "serial": serial,
        "sig_hex": sig_hex,
    });
    // Only attach the nonce when one was issued; the bootstrap middleware
    // parses the body strictly and the legacy proof has no nonce field.
    if let Some(n) = &nonce {
        body["nonce"] = json!(n);
    }

    let result = client.post("/identity-keys/enroll", body).await;
    match result {
        Ok(v) => {
            let id = v.get("id").and_then(|i| i.as_i64()).unwrap_or(0);
            let fpr = v
                .get("pubkey_fingerprint")
                .and_then(|s| s.as_str())
                .unwrap_or("?");
            println!("Enrolled identity key #{}", id);
            println!("  Fingerprint: {}", fpr);
            println!("  Tier:        {}", signer.tier());
            println!("  Algorithm:   {}", signer.algo().as_str());
            println!("  Host:        {}", host_label);
            if let Some(path) = key_path_msg {
                println!("  Key file:    {}", path);
            }
        }
        Err(e) => {
            eprintln!("Enrollment failed: {}", e);
            eprintln!("Make sure you have a valid API key or existing identity to authenticate.");
            std::process::exit(1);
        }
    }
}

/// Ingests text or a file into Kleos as a new memory.
async fn handle_ingest(
    client: &Client,
    text: &Option<String>,
    file: &Option<std::path::PathBuf>,
    mode: &str,
    source: &Option<String>,
    category: &str,
) {
    // Prefer --file when given; fall back to --text; error otherwise.
    let (raw_bytes, is_binary, source_label) = match (file, text) {
        (Some(path), _) => match std::fs::read(path) {
            Ok(bytes) => {
                // We treat UTF-8 decodable input as text ingest and hand off
                // binary content to the chunked upload flow.
                let looks_text = std::str::from_utf8(&bytes).is_ok();
                let label = source
                    .clone()
                    .or_else(|| {
                        path.file_name()
                            .and_then(|n| n.to_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| "file".to_string());
                (bytes, !looks_text, label)
            }
            Err(e) => {
                eprintln!("Error reading {}: {}", path.display(), e);
                return;
            }
        },
        (None, Some(t)) => (
            t.as_bytes().to_vec(),
            false,
            source.clone().unwrap_or_else(|| "cli".to_string()),
        ),
        (None, None) => {
            eprintln!("Error: supply --text or --file");
            return;
        }
    };

    if !is_binary {
        // Hot path: POST /ingest with the decoded string body.
        let text_body = String::from_utf8(raw_bytes).expect("utf8 verified above");
        let body = json!({
            "text": text_body,
            "mode": mode,
            "source": source_label,
            "category": category,
        });
        match client.post("/ingest", body).await {
            Ok(v) => {
                if let Some(id) = value_as_string(v.get("job_id")) {
                    let memories = v
                        .get("ingested")
                        .and_then(|v| v.as_i64())
                        .or_else(|| v.get("ingested_memories").and_then(|v| v.as_i64()))
                        .unwrap_or(0);
                    let chunks = v
                        .get("chunks_processed")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    println!("Ingested: job {id} -- {memories} memories, {chunks} chunks");
                } else {
                    println!("{}", serde_json::to_string_pretty(&v).unwrap());
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }
        return;
    }

    // Binary path: chunked upload flow. Split into 1MiB chunks, POST init →
    // chunk* → complete so PDF/DOCX/ZIP payloads reach ingest_binary().
    const CHUNK_SIZE: usize = 1 << 20;
    let filename = file.as_ref().and_then(|p| {
        p.file_name()
            .and_then(|n| n.to_str().map(|s| s.to_string()))
    });
    let content_type =
        filename
            .as_deref()
            .and_then(|f| f.rsplit_once('.'))
            .map(|(_, ext)| match ext.to_ascii_lowercase().as_str() {
                "pdf" => "application/pdf",
                "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "zip" => "application/zip",
                _ => "application/octet-stream",
            });

    let total_chunks = raw_bytes.len().div_ceil(CHUNK_SIZE);
    let mut init_body = json!({
        "total_chunks": total_chunks as i64,
        "source": source_label,
    });
    if let Some(name) = &filename {
        init_body["filename"] = json!(name);
    }
    if let Some(ct) = content_type {
        init_body["content_type"] = json!(ct);
    }

    let init_resp = match client.post("/ingest/upload/init", init_body).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error initiating upload: {}", e);
            return;
        }
    };
    let upload_id = match init_resp.get("upload_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => {
            eprintln!("Upload init returned no upload_id: {init_resp}");
            return;
        }
    };

    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut full_hasher = Sha256::new();
    for (idx, chunk) in raw_bytes.chunks(CHUNK_SIZE).enumerate() {
        full_hasher.update(chunk);
        let chunk_hash = format!("{:x}", Sha256::digest(chunk));
        let body = json!({
            "upload_id": upload_id,
            "chunk_index": idx as i64,
            "chunk_hash": chunk_hash,
            "data": b64.encode(chunk),
        });
        if let Err(e) = client.post("/ingest/upload/chunk", body).await {
            eprintln!("Error uploading chunk {}: {}", idx, e);
            return;
        }
    }
    let final_hash = format!("{:x}", full_hasher.finalize());
    let complete_body = json!({
        "upload_id": upload_id,
        "total_chunks": total_chunks as i64,
        "final_sha256": final_hash,
        "mode": mode,
        "category": category,
    });
    match client.post("/ingest/upload/complete", complete_body).await {
        Ok(v) => {
            let memories = v
                .get("ingested_memories")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let chunks = v
                .get("chunks_processed")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let job = value_as_string(v.get("job_id")).unwrap_or_else(|| "?".into());
            println!("Ingested: job {job} -- {memories} memories, {chunks} chunks");
        }
        Err(e) => eprintln!("Error completing upload: {}", e),
    }
}

/// Dispatches background job subcommands (stats, list, retry, cancel).
async fn handle_jobs_command(client: &Client, cmd: &JobsCommands) {
    match cmd {
        JobsCommands::Stats => match client.get("/jobs/stats").await {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(e) => eprintln!("Error: {}", e),
        },
        JobsCommands::List {
            status,
            limit,
            offset,
        } => {
            let path = format!("/jobs?status={status}&limit={limit}&offset={offset}");
            match client.get(&path).await {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        JobsCommands::Retry { id, all } => {
            if *all {
                // Server has no "retry all" endpoint -- emulate by listing
                // failed jobs and retrying each id.
                let listing = match client.get("/jobs/failed?limit=200&offset=0").await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Error listing failed jobs: {}", e);
                        return;
                    }
                };
                let empty = Vec::new();
                let jobs = listing
                    .get("jobs")
                    .and_then(|v| v.as_array())
                    .unwrap_or(&empty);
                if jobs.is_empty() {
                    println!("No failed jobs to retry.");
                    return;
                }
                let mut retried = 0usize;
                for job in jobs {
                    if let Some(job_id) = job.get("id").and_then(|v| v.as_i64()) {
                        match client
                            .post(&format!("/jobs/{job_id}/retry"), json!({}))
                            .await
                        {
                            Ok(_) => retried += 1,
                            Err(e) => eprintln!("Retry {job_id} failed: {e}"),
                        }
                    }
                }
                println!("Retried {retried} of {} failed jobs.", jobs.len());
                return;
            }
            let Some(id) = id else {
                eprintln!("Error: provide a job id or --all");
                return;
            };
            match client.post(&format!("/jobs/{id}/retry"), json!({})).await {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        JobsCommands::Purge { older_than_days } => {
            let body = json!({ "older_than_days": older_than_days });
            match client.post("/jobs/purge", body).await {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        JobsCommands::Cleanup { older_than_days } => {
            let body = json!({ "older_than_days": older_than_days });
            match client.post("/jobs/cleanup", body).await {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
    }
}

/// Dispatches skill subcommands (search, get, capture, execute, etc.).
async fn handle_skill_command(client: &Client, cmd: &SkillCommands) {
    match cmd {
        SkillCommands::Search { query, limit } => {
            let body = json!({ "query": query, "limit": limit });
            match client.post("/skills/search", body).await {
                Ok(v) => {
                    let results = v.as_array().cloned().unwrap_or_else(|| {
                        v.get("results")
                            .and_then(|r| r.as_array())
                            .cloned()
                            .unwrap_or_default()
                    });
                    if results.is_empty() {
                        println!("No results.");
                    }
                    for item in &results {
                        let id = value_as_string(item.get("id")).unwrap_or_else(|| "?".to_string());
                        let trust = item
                            .get("trust_score")
                            .and_then(|x| x.as_f64())
                            .unwrap_or(0.0);
                        let name = item.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                        let desc = item
                            .get("description")
                            .and_then(|x| x.as_str())
                            .unwrap_or("");
                        println!(
                            "#{} [trust:{:.2}] {} -- {}",
                            id,
                            trust,
                            name,
                            truncate(desc, 80)
                        );
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        SkillCommands::List {
            limit,
            offset,
            agent,
        } => {
            let mut path = format!("/skills?limit={}&offset={}", limit, offset);
            if let Some(a) = agent {
                path.push_str(&format!("&agent={}", a));
            }
            match client.get(&path).await {
                Ok(v) => {
                    let items = v.as_array().cloned().unwrap_or_else(|| {
                        v.get("skills")
                            .and_then(|r| r.as_array())
                            .cloned()
                            .unwrap_or_default()
                    });
                    if items.is_empty() {
                        println!("No skills.");
                    }
                    for item in &items {
                        let id = value_as_string(item.get("id")).unwrap_or_else(|| "?".to_string());
                        let version =
                            value_as_string(item.get("version")).unwrap_or_else(|| "?".to_string());
                        let trust = item
                            .get("trust_score")
                            .and_then(|x| x.as_f64())
                            .unwrap_or(0.0);
                        let name = item.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                        println!("#{} [v{} trust:{:.2}] {}", id, version, trust, name);
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        SkillCommands::Get { id } => match client.get(&format!("/skills/{}", id)).await {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(e) => eprintln!("Error: {}", e),
        },

        SkillCommands::Execute {
            id,
            success,
            duration_ms,
            error_type,
            error_message,
        } => {
            let body = json!({
                "success": success,
                "duration_ms": duration_ms,
                "error_type": error_type,
                "error_message": error_message,
            });
            match client.post(&format!("/skills/{}/execute", id), body).await {
                Ok(_) => println!("Recorded execution for skill #{}", id),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        SkillCommands::Create {
            name,
            description,
            file,
            agent,
            language,
        } => {
            let code = std::fs::read_to_string(file).unwrap_or_else(|e| {
                eprintln!("Error reading {}: {}", file, e);
                std::process::exit(1);
            });
            let body = json!({
                "name": name,
                "agent": agent,
                "description": description,
                "code": code,
                "language": language,
            });
            match client.post("/skills", body).await {
                Ok(v) => {
                    let id = v.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
                    println!("Created skill #{}: {}", id, name);
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        SkillCommands::Capture { description, agent } => {
            let body = json!({ "description": description, "agent": agent });
            match client.post("/skills/capture", body).await {
                Ok(v) => {
                    let skill_id =
                        value_as_string(v.get("skill_id")).unwrap_or_else(|| "?".to_string());
                    let message = v.get("message").and_then(|x| x.as_str()).unwrap_or("");
                    let success = v.get("success").and_then(|x| x.as_bool()).unwrap_or(false);
                    if success {
                        println!("Captured skill #{}: {}", skill_id, message);
                    } else {
                        println!("Capture failed: {}", message);
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        SkillCommands::Fix {
            id,
            direction,
            agent,
        } => {
            let dir = direction.as_deref().unwrap_or("").to_string();
            let body = json!({ "direction": dir, "agent": agent });
            match client.post(&format!("/skills/{}/fix", id), body).await {
                Ok(v) => {
                    let skill_id =
                        value_as_string(v.get("skill_id")).unwrap_or_else(|| "?".to_string());
                    let message = v.get("message").and_then(|x| x.as_str()).unwrap_or("");
                    let success = v.get("success").and_then(|x| x.as_bool()).unwrap_or(false);
                    if success {
                        println!("Fixed skill #{}: {}", skill_id, message);
                    } else {
                        println!("Fix failed: {}", message);
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        SkillCommands::Derive {
            parent_ids,
            direction,
            agent,
        } => {
            let body = json!({ "parent_ids": parent_ids, "direction": direction, "agent": agent });
            match client.post("/skills/derive", body).await {
                Ok(v) => {
                    let skill_id =
                        value_as_string(v.get("skill_id")).unwrap_or_else(|| "?".to_string());
                    let message = v.get("message").and_then(|x| x.as_str()).unwrap_or("");
                    let success = v.get("success").and_then(|x| x.as_bool()).unwrap_or(false);
                    if success {
                        println!("Derived skill #{}: {}", skill_id, message);
                    } else {
                        println!("Derive failed: {}", message);
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        SkillCommands::Stats => match client.get("/skills/dashboard/overview").await {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(e) => eprintln!("Error: {}", e),
        },

        SkillCommands::Lineage { id } => {
            match client.get(&format!("/skills/{}/lineage", id)).await {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        SkillCommands::Evolve { hours, limit } => {
            match client
                .get(&format!(
                    "/skills/evolution/recent?hours={}&limit={}",
                    hours, limit
                ))
                .await
            {
                Ok(v) => {
                    let evolutions = v.as_array().cloned().unwrap_or_else(|| {
                        v.get("evolutions")
                            .and_then(|r| r.as_array())
                            .cloned()
                            .unwrap_or_default()
                    });
                    if evolutions.is_empty() {
                        println!("No recent evolutions.");
                    }
                    for item in &evolutions {
                        let skill_id = value_as_string(item.get("skill_id"))
                            .unwrap_or_else(|| "?".to_string());
                        let version =
                            value_as_string(item.get("version")).unwrap_or_else(|| "?".to_string());
                        let name = item.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                        let origin = item.get("origin").and_then(|x| x.as_str()).unwrap_or("?");
                        let parent_ids: Vec<String> = item
                            .get("parent_ids")
                            .and_then(|x| x.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| value_as_string(Some(v)))
                                    .collect()
                            })
                            .unwrap_or_default();
                        println!(
                            "#{} [v{}] {} ({}) -- parents: {:?}",
                            skill_id, version, name, origin, parent_ids
                        );
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        SkillCommands::Find {
            query,
            limit,
            kind,
            plugin,
            tag,
            include_deprecated,
        } => {
            let mut body = json!({ "query": query, "limit": limit });
            if let Some(k) = kind {
                body["kind"] = json!(k);
            }
            if let Some(p) = plugin {
                body["plugin"] = json!(p);
            }
            if let Some(t) = tag {
                body["tag"] = json!(t);
            }
            if *include_deprecated {
                body["include_deprecated"] = json!(true);
            }
            match client.post("/skills/find", body).await {
                Ok(v) => {
                    let results = v
                        .get("results")
                        .and_then(|r| r.as_array())
                        .cloned()
                        .unwrap_or_default();
                    if results.is_empty() {
                        println!("No results.");
                    }
                    for item in &results {
                        let skill = item.get("skill").cloned().unwrap_or(item.clone());
                        let id =
                            value_as_string(skill.get("id")).unwrap_or_else(|| "?".to_string());
                        let score = item.get("score").and_then(|x| x.as_f64()).unwrap_or(0.0);
                        let name = skill.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                        let kind = skill
                            .get("kind")
                            .and_then(|x| x.as_str())
                            .unwrap_or("skill");
                        let plugin = skill
                            .get("source_plugin")
                            .and_then(|x| x.as_str())
                            .unwrap_or("");
                        let desc = skill
                            .get("description")
                            .and_then(|x| x.as_str())
                            .unwrap_or("");
                        let plugin_str = if plugin.is_empty() {
                            String::new()
                        } else {
                            format!(" [{}]", plugin)
                        };
                        println!(
                            "#{} ({}) score:{:.3}{} {} -- {}",
                            id,
                            kind,
                            score,
                            plugin_str,
                            name,
                            truncate(desc, 80)
                        );
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        SkillCommands::Inject { target, top } => {
            // Resolve target -> skill id. If parseable as i64, use as id;
            // otherwise run a fuzzy find and pick the top result.
            let id: Option<i64> = match target.parse::<i64>() {
                Ok(n) => Some(n),
                Err(_) => {
                    let body = json!({ "query": target, "limit": if *top { 1 } else { 5 } });
                    match client.post("/skills/find", body).await {
                        Ok(v) => {
                            let results = v
                                .get("results")
                                .and_then(|r| r.as_array())
                                .cloned()
                                .unwrap_or_default();
                            if results.is_empty() {
                                eprintln!("No skill matches '{}'", target);
                                None
                            } else if *top || results.len() == 1 {
                                results
                                    .first()
                                    .and_then(|r| r.get("skill"))
                                    .and_then(|s| s.get("id"))
                                    .and_then(|x| x.as_i64())
                            } else {
                                // Print candidates and let the caller re-run with --top
                                // or with the explicit numeric id.
                                println!("Multiple matches; rerun with --top to inject the first, or pass the explicit id:");
                                for r in &results {
                                    let s = r.get("skill").cloned().unwrap_or(r.clone());
                                    let sid = value_as_string(s.get("id"))
                                        .unwrap_or_else(|| "?".to_string());
                                    let name =
                                        s.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                                    let plugin = s
                                        .get("source_plugin")
                                        .and_then(|x| x.as_str())
                                        .unwrap_or("");
                                    println!("  #{} {} [{}]", sid, name, plugin);
                                }
                                None
                            }
                        }
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            None
                        }
                    }
                }
            };
            if let Some(id) = id {
                match client.get(&format!("/skills/{}", id)).await {
                    Ok(v) => {
                        let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                        let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("skill");
                        let plugin = v
                            .get("source_plugin")
                            .and_then(|x| x.as_str())
                            .unwrap_or("");
                        let desc = v.get("description").and_then(|x| x.as_str()).unwrap_or("");
                        let code = v.get("code").and_then(|x| x.as_str()).unwrap_or("");
                        // Markdown-formatted output ready to paste into a
                        // session as a system / user message.
                        println!("# Skill: {} (#{}, kind:{})", name, id, kind);
                        if !plugin.is_empty() {
                            println!("Source plugin: {}", plugin);
                        }
                        if !desc.is_empty() {
                            println!();
                            println!("> {}", desc);
                        }
                        println!();
                        println!("---");
                        println!();
                        println!("{}", code);
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
        }

        SkillCommands::Materialize { id, dir } => {
            // Fetch the skill, reconstruct the agent .md (frontmatter from
            // metadata + body from `code`), write to disk, then POST the
            // materialization record so the DB tracks it.
            match client.get(&format!("/skills/{}", id)).await {
                Ok(v) => {
                    let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("skill");
                    if kind != "agent" {
                        eprintln!(
                            "Skill #{} kind is '{}', not 'agent' -- materialize is for agents only.",
                            id, kind
                        );
                        return;
                    }
                    let target_dir = dir.clone().unwrap_or_else(|| {
                        std::env::var("HOME")
                            .map(|h| format!("{}/.claude/agents", h))
                            .unwrap_or_else(|_| "./agents".to_string())
                    });
                    let plugin = v
                        .get("source_plugin")
                        .and_then(|x| x.as_str())
                        .unwrap_or("");
                    let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("agent");
                    let raw_filename = if plugin.is_empty() {
                        format!("{}.md", name)
                    } else {
                        format!("{}__{}.md", plugin, name)
                    };
                    // `name`/`plugin` are server-controlled. Strip any directory
                    // components so a crafted skill name (e.g. "../../.bashrc")
                    // cannot escape target_dir. sanitize_download_name returns a
                    // single safe path component or None.
                    let Some(safe_name) = sanitize_download_name(&raw_filename) else {
                        eprintln!(
                            "Refusing to materialize skill #{}: name '{}' yields no safe filename",
                            id, name
                        );
                        return;
                    };
                    if let Err(e) = std::fs::create_dir_all(&target_dir) {
                        eprintln!("Failed to create {}: {}", target_dir, e);
                        return;
                    }
                    let path = std::path::Path::new(&target_dir)
                        .join(&safe_name)
                        .to_string_lossy()
                        .into_owned();
                    // Reconstruct: prefer metadata['frontmatter'] when the
                    // importer stored the original; otherwise synthesize a
                    // minimal frontmatter from name + description.
                    let body = v.get("code").and_then(|x| x.as_str()).unwrap_or("");
                    let desc = v.get("description").and_then(|x| x.as_str()).unwrap_or("");
                    let meta_fm = v
                        .get("metadata")
                        .and_then(|x| x.as_str())
                        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
                        .and_then(|j| j.get("frontmatter").cloned());
                    let content =
                        if let Some(fm) = meta_fm.and_then(|f| f.as_str().map(String::from)) {
                            format!("---\n{}\n---\n\n{}", fm.trim(), body)
                        } else {
                            format!(
                                "---\nname: {}\ndescription: {}\n---\n\n{}",
                                name, desc, body
                            )
                        };
                    let hash = sha256_hex(&content);
                    // Refuse to write through an existing symlink or any
                    // non-regular entry: a poisoned skill row could otherwise
                    // redirect this write over an arbitrary user file.
                    if let Ok(meta) = std::fs::symlink_metadata(&path) {
                        if !meta.is_file() {
                            eprintln!(
                                "Refusing to write {}: existing path is not a regular file",
                                path
                            );
                            return;
                        }
                    }
                    if let Err(e) = std::fs::write(&path, &content) {
                        eprintln!("Failed to write {}: {}", path, e);
                        return;
                    }
                    let post_body = json!({
                        "target_path": path,
                        "content_hash": hash,
                    });
                    match client
                        .post(&format!("/skills/{}/materialize", id), post_body)
                        .await
                    {
                        Ok(_) => {
                            println!(
                                "Materialized #{} -> {} (Task subagent available next session)",
                                id, path
                            );
                        }
                        Err(e) => eprintln!("Wrote file but failed to record: {}", e),
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        SkillCommands::Dematerialize { id } => {
            match client.get(&format!("/skills/{}/materialization", id)).await {
                Ok(v) => {
                    if let Some(m) = v.get("materialization") {
                        if let Some(path) = m.get("target_path").and_then(|x| x.as_str()) {
                            // target_path comes from the server. Only delete a
                            // file that looks like a materialized agent (a .md
                            // with no traversal component) so a poisoned record
                            // cannot turn dematerialize into arbitrary deletion.
                            if !is_safe_materialization_path(
                                path,
                                std::env::var("HOME").ok().as_deref(),
                            ) {
                                eprintln!(
                                    "Refusing to remove suspicious materialization path: {}",
                                    path
                                );
                            } else if let Err(e) = std::fs::remove_file(path) {
                                if e.kind() != std::io::ErrorKind::NotFound {
                                    eprintln!("Failed to remove {}: {}", path, e);
                                }
                            }
                            // Even if file was already gone, drop the row.
                            match client
                                .delete(&format!("/skills/{}/materialization", id))
                                .await
                            {
                                Ok(_) => println!("Dematerialized #{} (removed {})", id, path),
                                Err(e) => eprintln!("Error clearing record: {}", e),
                            }
                        } else {
                            println!("Skill #{} has no materialization on file.", id);
                        }
                    } else {
                        println!("Skill #{} has no materialization on file.", id);
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        SkillCommands::Alias { sub } => match sub {
            AliasCommands::Add {
                skill_id,
                alias,
                confidence,
            } => {
                let body = json!({ "alias": alias, "confidence": confidence });
                match client
                    .post(&format!("/skills/{}/aliases", skill_id), body)
                    .await
                {
                    Ok(_) => println!("Added alias '{}' to skill #{}", alias, skill_id),
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            AliasCommands::Rm { skill_id, alias } => {
                match client
                    .delete(&format!("/skills/{}/aliases/{}", skill_id, alias))
                    .await
                {
                    Ok(_) => println!("Removed alias '{}' from skill #{}", alias, skill_id),
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            AliasCommands::List { skill_id } => {
                match client.get(&format!("/skills/{}/aliases", skill_id)).await {
                    Ok(v) => {
                        let aliases = v
                            .get("aliases")
                            .and_then(|r| r.as_array())
                            .cloned()
                            .unwrap_or_default();
                        if aliases.is_empty() {
                            println!("No aliases.");
                        }
                        for a in &aliases {
                            let alias = a.get("alias").and_then(|x| x.as_str()).unwrap_or("?");
                            let confidence =
                                a.get("confidence").and_then(|x| x.as_f64()).unwrap_or(0.0);
                            let source = a.get("source").and_then(|x| x.as_str()).unwrap_or("?");
                            println!("  {} (conf:{:.2} src:{})", alias, confidence, source);
                        }
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            AliasCommands::Resolve { query, limit } => {
                let body = json!({ "query": query, "limit": limit });
                match client.post("/skills/aliases/resolve", body).await {
                    Ok(v) => {
                        let matches = v
                            .get("matches")
                            .and_then(|r| r.as_array())
                            .cloned()
                            .unwrap_or_default();
                        if matches.is_empty() {
                            println!("No alias matches.");
                        }
                        for m in &matches {
                            let sid = value_as_string(m.get("skill_id"))
                                .unwrap_or_else(|| "?".to_string());
                            let alias = m.get("alias").and_then(|x| x.as_str()).unwrap_or("?");
                            let conf = m.get("confidence").and_then(|x| x.as_f64()).unwrap_or(0.0);
                            println!("  -> #{} via '{}' (conf:{:.2})", sid, alias, conf);
                        }
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
        },

        SkillCommands::ImportPlugins {
            dry_run,
            plugin,
            marketplace,
            source_overrides,
        } => {
            let cfg = import_plugins::load_config();
            let mut overrides: std::collections::BTreeMap<String, std::path::PathBuf> =
                std::collections::BTreeMap::new();
            for (k, v) in cfg.source_overrides {
                overrides.insert(k, std::path::PathBuf::from(shellexpand_home(&v)));
            }
            for raw in source_overrides {
                if let Some((k, v)) = raw.split_once('=') {
                    overrides.insert(k.to_string(), std::path::PathBuf::from(shellexpand_home(v)));
                } else {
                    eprintln!(
                        "Warning: --source-override expects PLUGIN=PATH, got: {}",
                        raw
                    );
                }
            }
            // Match arms see `cmd` by ref so primitive / Option fields are
            // borrows; clone or deref into ImportArgs which owns its fields.
            let args = import_plugins::ImportArgs {
                dry_run: *dry_run,
                plugin_filter: plugin.clone(),
                marketplace_filter: marketplace.clone(),
                source_overrides: overrides,
            };
            import_plugins::run(client, args).await;
        }

        SkillCommands::Bundle { sub } => match sub {
            BundleCommands::List { limit } => {
                match client.get(&format!("/bundles?limit={}", limit)).await {
                    Ok(v) => {
                        let bundles = v
                            .get("bundles")
                            .and_then(|r| r.as_array())
                            .cloned()
                            .unwrap_or_default();
                        if bundles.is_empty() {
                            println!("No bundles.");
                        }
                        for b in &bundles {
                            let bundle = b.get("bundle").cloned().unwrap_or(b.clone());
                            let bid = value_as_string(bundle.get("id"))
                                .unwrap_or_else(|| "?".to_string());
                            let name = bundle.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                            let n = b.get("member_count").and_then(|x| x.as_i64()).unwrap_or(0);
                            let auto = bundle
                                .get("auto_generated")
                                .and_then(|x| x.as_bool())
                                .unwrap_or(false);
                            let suffix = if auto { " [auto]" } else { "" };
                            println!("#{} {} ({} members){}", bid, name, n, suffix);
                        }
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            BundleCommands::Create { name, description } => {
                let body = json!({ "name": name, "description": description });
                match client.post("/bundles", body).await {
                    Ok(v) => {
                        let id = v.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
                        println!("Created bundle #{}: {}", id, name);
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            BundleCommands::Get { id } => match client.get(&format!("/bundles/{}", id)).await {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => eprintln!("Error: {}", e),
            },
            BundleCommands::Delete { id } => {
                match client.delete(&format!("/bundles/{}", id)).await {
                    Ok(_) => println!("Deleted bundle #{}", id),
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            BundleCommands::Members { id } => {
                match client.get(&format!("/bundles/{}/skills", id)).await {
                    Ok(v) => {
                        let ids = v
                            .get("skill_ids")
                            .and_then(|r| r.as_array())
                            .cloned()
                            .unwrap_or_default();
                        if ids.is_empty() {
                            println!("No members.");
                        }
                        for sid in &ids {
                            if let Some(n) = sid.as_i64() {
                                println!("  #{}", n);
                            }
                        }
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            BundleCommands::Add {
                bundle_id,
                skill_id,
            } => {
                let body = json!({ "skill_id": skill_id });
                match client
                    .post(&format!("/bundles/{}/skills", bundle_id), body)
                    .await
                {
                    Ok(_) => println!("Added skill #{} to bundle #{}", skill_id, bundle_id),
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            BundleCommands::Remove {
                bundle_id,
                skill_id,
            } => {
                match client
                    .delete(&format!("/bundles/{}/skills/{}", bundle_id, skill_id))
                    .await
                {
                    Ok(_) => println!("Removed skill #{} from bundle #{}", skill_id, bundle_id),
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
        },
    }
}

// SHA-256 hex helper used by materialize to fingerprint on-disk content.
// Kept inline (rather than pulled into a util module) because this is the
// only place it's used.
fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let digest = h.finalize();
    hex_encode(&digest)
}

// Expand a leading `~/` to $HOME for paths read out of skill-import.toml
// or --source-override flags. Plain paths and absolute paths pass through.
fn shellexpand_home(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{}", home, rest);
        }
    }
    s.to_string()
}

/// Reduces a server-supplied artifact filename to a safe, CWD-relative name.
///
/// A malicious or compromised server controls the `filename` returned for an
/// artifact. Writing it verbatim allows path traversal (`../../etc/cron.d/x`)
/// or absolute-path overwrite (`/home/user/.bashrc`). This strips every
/// directory component and returns only the final path element, so the write
/// always lands in the current directory. Returns `None` for names that have
/// no usable final component (empty, `.`, `..`, `/`).
fn sanitize_download_name(server_name: &str) -> Option<std::path::PathBuf> {
    let final_component = std::path::Path::new(server_name).file_name()?;
    let name = final_component.to_str()?;
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    Some(std::path::PathBuf::from(name))
}

/// True when a server-supplied materialization path is safe to delete: it must
/// be a `.md` file (what materialize writes), contain no `..` traversal
/// component, and -- when absolute -- sit inside `~/.claude/`. Guards
/// dematerialize against a poisoned record pointing the removal at an
/// arbitrary file.
fn is_safe_materialization_path(path: &str, home: Option<&str>) -> bool {
    let p = std::path::Path::new(path);
    let is_md = p
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("md"));
    let no_traversal = !p
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir));
    // Absolute paths must sit inside ~/.claude/: target_path comes from the
    // server, and an unconstrained absolute path from a poisoned record could
    // point the dematerialize remove_file at any .md the user owns. Custom
    // materialize dirs outside ~/.claude get a refusal and delete manually.
    let in_allowed_root = if p.is_absolute() {
        home.is_some_and(|h| p.starts_with(std::path::Path::new(h).join(".claude")))
    } else {
        true
    };
    is_md && no_traversal && in_allowed_root
}

/// Encodes a byte slice as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Dispatches credential vault subcommands (get, set, delete, list).
async fn handle_cred_command(client: &Client, cmd: &CredCommands) {
    match cmd {
        CredCommands::Get {
            category,
            name,
            raw,
        } => {
            match client.get(&format!("/secret/{}/{}", category, name)).await {
                Ok(v) => {
                    if *raw {
                        // Extract primary value
                        if let Some(value) = v.get("value") {
                            let primary = value
                                .get("key")
                                .or_else(|| value.get("password"))
                                .or_else(|| value.get("client_secret"))
                                .or_else(|| value.get("private_key"))
                                .or_else(|| value.get("content"))
                                .and_then(|v| v.as_str());
                            if let Some(s) = primary {
                                println!("{}", s);
                            } else {
                                println!("{}", serde_json::to_string(&value).unwrap_or_default());
                            }
                        }
                    } else {
                        println!("{}", serde_json::to_string_pretty(&v).unwrap());
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        CredCommands::Set {
            category,
            name,
            secret_type,
            value,
            username,
            url,
        } => {
            let secret_value = match value {
                Some(v) => v.clone(),
                None => {
                    eprint!("Enter secret value: ");
                    std::io::Write::flush(&mut std::io::stderr()).ok();
                    rpassword::read_password().unwrap_or_default()
                }
            };

            let data = match secret_type.as_str() {
                "login" => json!({
                    "type": "login",
                    "username": username.clone().unwrap_or_default(),
                    "password": secret_value,
                    "url": url,
                }),
                "api_key" => json!({
                    "type": "api_key",
                    "key": secret_value,
                }),
                "oauth_app" => json!({
                    "type": "oauth_app",
                    "client_id": username.clone().unwrap_or_default(),
                    "client_secret": secret_value,
                    "redirect_uri": url,
                }),
                "ssh_key" => json!({
                    "type": "ssh_key",
                    "private_key": secret_value,
                }),
                "note" => json!({
                    "type": "note",
                    "content": secret_value,
                }),
                _ => json!({
                    "type": "api_key",
                    "key": secret_value,
                }),
            };

            let body = json!({ "data": data });
            match client
                .post(&format!("/secret/{}/{}", category, name), body)
                .await
            {
                Ok(v) => {
                    println!(
                        "Stored {}/{} (id: {})",
                        category,
                        name,
                        value_as_string(v.get("id")).unwrap_or_else(|| "?".to_string())
                    );
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        CredCommands::List { category } => {
            let path = match category {
                Some(cat) => format!("/secrets?category={}", cat),
                None => "/secrets".to_string(),
            };
            match client.get(&path).await {
                Ok(v) => {
                    let secrets = v
                        .get("secrets")
                        .and_then(|s| s.as_array())
                        .cloned()
                        .unwrap_or_default();
                    if secrets.is_empty() {
                        println!("No secrets.");
                    } else {
                        for s in &secrets {
                            let cat = s
                                .get("service")
                                .or_else(|| s.get("category"))
                                .and_then(|x| x.as_str())
                                .unwrap_or("?");
                            let name = s
                                .get("key")
                                .or_else(|| s.get("name"))
                                .and_then(|x| x.as_str())
                                .unwrap_or("?");
                            let stype =
                                s.get("secret_type").and_then(|x| x.as_str()).unwrap_or("?");
                            println!("{}/{} [{}]", cat, name, stype);
                        }
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        CredCommands::Delete { category, name } => {
            match client
                .delete(&format!("/secret/{}/{}", category, name))
                .await
            {
                Ok(_) => println!("Deleted {}/{}", category, name),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        CredCommands::AgentCreate {
            name,
            categories,
            allow_raw,
        } => {
            let cats: Vec<String> = categories
                .as_deref()
                .unwrap_or("")
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let body = json!({
                "name": name,
                "categories": cats,
                "allow_raw": allow_raw,
            });

            match client.post("/agents", body).await {
                Ok(v) => {
                    if let Some(key) = v.get("key").and_then(|k| k.as_str()) {
                        println!("Agent key created: {}", name);
                        println!("Key: {}", key);
                        println!("Save this key -- it cannot be retrieved later.");
                    } else {
                        println!("{}", serde_json::to_string_pretty(&v).unwrap());
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        CredCommands::AgentList => match client.get("/agents").await {
            Ok(v) => {
                let keys = v
                    .get("keys")
                    .and_then(|k| k.as_array())
                    .cloned()
                    .unwrap_or_default();
                if keys.is_empty() {
                    println!("No agent keys.");
                } else {
                    for k in &keys {
                        let name = k.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                        let valid = k.get("is_valid").and_then(|v| v.as_bool()).unwrap_or(false);
                        let status = if valid { "active" } else { "revoked" };
                        println!("{} [{}]", name, status);
                    }
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        },

        CredCommands::AgentRevoke { name } => {
            match client
                .post(&format!("/agents/{}/revoke", name), json!({}))
                .await
            {
                Ok(_) => println!("Revoked agent key: {}", name),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        CredCommands::Sync => match client.post("/sync", json!({})).await {
            Ok(v) => {
                let synced = v.get("synced").and_then(|x| x.as_u64()).unwrap_or(0);
                let skipped = v.get("skipped").and_then(|x| x.as_u64()).unwrap_or(0);
                let errors = v.get("errors").and_then(|x| x.as_u64()).unwrap_or(0);
                let total = v.get("total_v3").and_then(|x| x.as_u64()).unwrap_or(0);
                println!(
                    "Sync complete: {} synced, {} skipped (already local), {} errors, {} total v3 entries",
                    synced, skipped, errors, total
                );
            }
            Err(e) => eprintln!("Error: {}", e),
        },

        CredCommands::Exec {
            category,
            name,
            env,
            field,
            cmd,
        } => {
            // Two routes depending on what the caller is asking for:
            //
            //   category in {"engram-rust","kleos"} -> per-agent Kleos
            //     bearer via /bootstrap/kleos-bearer (the bootstrap-broker
            //     path; bootstrap-agent token has scope for this).
            //   otherwise -> centralized credd secret store via
            //     /secret/{cat}/{name} (requires a DB-backed agent key
            //     with category permissions).
            //
            // The bootstrap path is the one most agents need (injecting
            // a Kleos API key into a child like curl), so it gets the
            // easy `kleos-cli cred exec engram-rust <slot>` form.
            let secret = if matches!(category.as_str(), "engram-rust" | "kleos") {
                // Use the same bootstrap-broker path that resolve_api_key
                // takes -- this picks up CREDD_SOCKET / CREDD_BIND /
                // CREDD_AGENT_KEY / PIV pubkeys automatically and works
                // without needing a Kleos API key already in hand.
                match kleos_lib::cred::bootstrap::resolve_api_key(name).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Error fetching bootstrap bearer: {}", e);
                        std::process::exit(2);
                    }
                }
            } else {
                let secret_value = match client.get(&format!("/secret/{}/{}", category, name)).await
                {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Error fetching secret: {}", e);
                        std::process::exit(2);
                    }
                };
                let value_obj = match secret_value.get("value") {
                    Some(v) => v,
                    None => {
                        eprintln!("Error: response missing `value` field");
                        std::process::exit(2);
                    }
                };
                if let Some(f) = field.as_deref() {
                    match value_obj.get(f).and_then(|v| v.as_str()) {
                        Some(s) => s.to_string(),
                        None => {
                            eprintln!("Error: field `{}` not found or not a string", f);
                            std::process::exit(2);
                        }
                    }
                } else {
                    let primary = value_obj
                        .get("key")
                        .or_else(|| value_obj.get("password"))
                        .or_else(|| value_obj.get("client_secret"))
                        .or_else(|| value_obj.get("private_key"))
                        .or_else(|| value_obj.get("content"))
                        .and_then(|v| v.as_str());
                    match primary {
                        Some(s) => s.to_string(),
                        None => {
                            eprintln!(
                                "Error: no primary value (key/password/client_secret/private_key/content) in secret"
                            );
                            std::process::exit(2);
                        }
                    }
                }
            };

            // Build child Command. The secret is passed via env() which
            // hands it directly to the kernel exec call -- it never
            // appears on the command line, in stdout, or in shell history.
            let (program, args) = match cmd.split_first() {
                Some((p, a)) => (p.clone(), a.to_vec()),
                None => {
                    eprintln!("Error: no command supplied after `--`");
                    std::process::exit(2);
                }
            };
            let status = std::process::Command::new(&program)
                .args(&args)
                .env(env, &secret)
                .status();
            match status {
                Ok(s) => std::process::exit(s.code().unwrap_or(1)),
                Err(e) => {
                    eprintln!("Error: failed to exec `{}`: {}", program, e);
                    std::process::exit(2);
                }
            }
        }
    }
}

/// Detects a project only inside a Git worktree, using the origin name or Git
/// root basename. Ordinary directory names are never promoted to projects.
fn detect_project(dir: Option<&str>) -> Option<String> {
    let dir = dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let detected = detect_project_at_path(&dir)?;
    std::env::var("SESSION_HANDOFF_PROJECT")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or(Some(detected))
}

/// Detects a repository identity at an exact filesystem path and returns
/// `None` when the path is not inside a Git worktree.
fn detect_project_at_path(dir: &std::path::Path) -> Option<String> {
    let root_output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(dir)
        .output()
        .ok()?;
    if !root_output.status.success() {
        return None;
    }
    let git_root = std::path::PathBuf::from(
        String::from_utf8_lossy(&root_output.stdout)
            .trim()
            .to_string(),
    );
    if git_root.as_os_str().is_empty() {
        return None;
    }

    let output = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(&git_root)
        .output();
    if let Ok(output) = output {
        if output.status.success() {
            let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if let Some(name) = project_from_remote(&url) {
                return Some(name);
            }
        }
    }

    git_root
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .filter(|name| !name.is_empty())
}

/// Extracts a repository name from HTTPS, filesystem, or SCP-style Git URLs.
fn project_from_remote(url: &str) -> Option<String> {
    let tail = url.rsplit(['/', ':']).next()?.trim();
    let name = tail.strip_suffix(".git").unwrap_or(tail).trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// Detects the current git branch name.
fn detect_branch(dir: Option<&str>) -> Option<String> {
    let dir = dir.unwrap_or(".");
    let output = std::process::Command::new("git")
        .args(["branch", "--show-current"])
        .current_dir(dir)
        .output()
        .ok()?;
    if output.status.success() {
        let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !branch.is_empty() {
            return Some(branch);
        }
    }
    None
}

/// Detects the hostname from env or system command.
fn detect_host() -> String {
    if let Ok(val) = std::env::var("SESSION_HANDOFF_HOST") {
        if !val.is_empty() {
            return val;
        }
    }
    if std::path::Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists() {
        return "wsl".to_string();
    }
    if cfg!(target_os = "windows") {
        return "windows".to_string();
    }
    std::process::Command::new("hostname")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Returns the agent identifier from SESSION_HANDOFF_AGENT env var.
fn detect_agent() -> String {
    std::env::var("SESSION_HANDOFF_AGENT").unwrap_or_else(|_| "unknown".to_string())
}

/// Returns the model identifier from env vars (SESSION_HANDOFF_MODEL, ANTHROPIC_MODEL, MODEL_ID).
fn detect_model() -> Option<String> {
    std::env::var("SESSION_HANDOFF_MODEL")
        .or_else(|_| std::env::var("ANTHROPIC_MODEL"))
        .or_else(|_| std::env::var("MODEL_ID"))
        .ok()
        .filter(|s| !s.is_empty())
}

/// Resolves the stable handoff session id from an explicit value or known
/// agent environment variables.
fn detect_session_id(explicit: Option<&String>) -> Option<String> {
    explicit
        .cloned()
        .or_else(|| std::env::var("CODEX_THREAD_ID").ok())
        .or_else(|| std::env::var("SESSION_ID").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Resolves a logical workstream from an explicit value, environment, or
/// repository project label.
fn detect_workstream(explicit: Option<&String>, project: Option<&String>) -> Option<String> {
    explicit
        .cloned()
        .or_else(|| std::env::var("SESSION_HANDOFF_WORKSTREAM").ok())
        .or_else(|| project.cloned())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Returns whether restore is running outside Git without the stable session
/// identity required to avoid selecting an unrelated standalone handoff.
fn restore_requires_exact_session(in_git_worktree: bool, session_id: Option<&str>) -> bool {
    !in_git_worktree && session_id.is_none()
}

/// Resolves dump scope exclusively from Git worktree detection so an explicit
/// compatibility project label cannot turn a standalone session into a
/// repository handoff.
fn dump_scope(in_git_worktree: bool) -> &'static str {
    if in_git_worktree {
        "repository"
    } else {
        "standalone"
    }
}

/// Dispatches session handoff subcommands (dump, restore, list, gc, etc.).
async fn handle_handoff_command(client: &Client, cmd: &HandoffCommands) {
    match cmd {
        HandoffCommands::Dump {
            project,
            workstream,
            title,
            branch,
            agent,
            handoff_type,
            session,
            model,
            host,
            content,
            dir,
        } => {
            let content_str = if let Some(c) = content {
                c.clone()
            } else {
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin()
                    .read_to_string(&mut buf)
                    .unwrap_or_else(|e| {
                        eprintln!("Error reading stdin: {}", e);
                        std::process::exit(1);
                    });
                if buf.is_empty() {
                    eprintln!("Error: provide --content or pipe content via stdin");
                    std::process::exit(1);
                }
                buf
            };

            let dir_str = dir.as_deref();
            let detected_project = detect_project(dir_str);
            let in_git_worktree = detected_project.is_some();
            let project = project.clone().or(detected_project);
            let branch = branch.clone().or_else(|| detect_branch(dir_str));
            let scope = dump_scope(in_git_worktree);
            let Some(workstream) = detect_workstream(workstream.as_ref(), project.as_ref()) else {
                eprintln!("Error: standalone handoffs require --workstream");
                std::process::exit(1);
            };
            let session_id = detect_session_id(session.as_ref());
            if scope == "standalone" && session_id.is_none() {
                eprintln!(
                    "Error: standalone handoffs require --session, SESSION_ID, or CODEX_THREAD_ID"
                );
                std::process::exit(1);
            }
            if scope == "standalone" && handoff_type.as_deref() == Some("mechanical") {
                eprintln!("Error: mechanical handoffs require a Git worktree");
                std::process::exit(1);
            }

            let mut body = json!({
                "scope": scope,
                "workstream": workstream,
                "title": title,
                "branch": branch,
                "directory": dir.clone().or_else(|| std::env::current_dir().ok().map(|p| p.to_string_lossy().to_string())),
                "agent": agent.clone().unwrap_or_else(detect_agent),
                "type": handoff_type.clone().unwrap_or_else(|| "manual".to_string()),
                "content": content_str,
                "session_id": session_id,
                "model": model.clone().or_else(detect_model),
                "host": host.clone().unwrap_or_else(detect_host),
            });
            if let Some(ref project) = project {
                body["project"] = json!(project);
            }

            match client.post("/handoffs", body).await {
                Ok(v) => {
                    if v.get("skipped").and_then(|s| s.as_bool()).unwrap_or(false) {
                        eprintln!("Skipped duplicate handoff for '{}'", workstream);
                    } else if let Some(id) = v.get("id") {
                        println!(
                            "Stored handoff #{} (scope={}, workstream={})",
                            id, scope, workstream
                        );
                    } else {
                        println!("{}", serde_json::to_string_pretty(&v).unwrap());
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        HandoffCommands::Restore {
            id,
            project,
            scope,
            workstream,
            agent,
            handoff_type,
            model,
            session,
            since,
            limit,
            dir,
        } => {
            if let Some(id) = id {
                match client.get(&format!("/handoffs/{id}")).await {
                    Ok(value) => {
                        if let Some(content) = value.get("content").and_then(|c| c.as_str()) {
                            println!("{}", content);
                        } else {
                            println!("{}", serde_json::to_string_pretty(&value).unwrap());
                        }
                    }
                    Err(error) => eprintln!("Error: {}", error),
                }
                return;
            }

            let detected_project = detect_project(dir.as_deref());
            let in_git_worktree = detected_project.is_some();
            let project = project.clone().or(detected_project);
            let session_id = detect_session_id(session.as_ref());
            if restore_requires_exact_session(in_git_worktree, session_id.as_deref()) {
                eprintln!(
                    "Error: standalone restore requires --id or a stable --session. Use `kleos-cli handoff candidates` to choose one."
                );
                std::process::exit(1);
            }
            let workstream = detect_workstream(workstream.as_ref(), project.as_ref());
            let mut params: Vec<(&str, String)> = Vec::new();
            if let Some(ref p) = project {
                params.push(("project", p.clone()));
            }
            if let Some(value) = scope
                .clone()
                .or_else(|| project.is_none().then(|| "standalone".to_string()))
            {
                params.push(("scope", value));
            }
            if let Some(ref value) = workstream {
                params.push(("workstream", value.clone()));
            }
            if let Some(ref a) = agent {
                params.push(("agent", a.clone()));
            }
            if let Some(ref t) = handoff_type {
                params.push(("type", t.clone()));
            }
            if let Some(ref m) = model {
                params.push(("model", m.clone()));
            }
            if let Some(ref s) = session_id {
                params.push(("session_id", s.clone()));
            }
            if let Some(ref s) = since {
                params.push(("since", s.clone()));
            }
            params.push(("limit", limit.to_string()));

            let query = params
                .iter()
                .map(|(k, v)| format!("{}={}", k, utf8_percent_encode(v, NON_ALPHANUMERIC)))
                .collect::<Vec<_>>()
                .join("&");

            match client.get(&format!("/handoffs?{}", query)).await {
                Ok(v) => {
                    if let Some(handoffs) = v.get("handoffs").and_then(|h| h.as_array()) {
                        for h in handoffs {
                            if let Some(content) = h.get("content").and_then(|c| c.as_str()) {
                                println!("{}", content);
                                if handoffs.len() > 1 {
                                    println!("\n---\n");
                                }
                            }
                        }
                        if handoffs.is_empty() {
                            eprintln!("No handoffs found");
                        }
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        HandoffCommands::Latest { project, dir } => {
            let project = project.clone().or_else(|| detect_project(dir.as_deref()));
            let Some(ref project) = project else {
                eprintln!(
                    "Error: latest requires a Git project. For standalone sessions use `handoff restore --session ...` or `handoff candidates`."
                );
                std::process::exit(1);
            };
            let query = format!(
                "?project={}",
                utf8_percent_encode(project, NON_ALPHANUMERIC)
            );

            match client.get(&format!("/handoffs/latest{}", query)).await {
                Ok(v) => {
                    if let Some(content) = v.get("content").and_then(|c| c.as_str()) {
                        println!("{}", content);
                    } else {
                        println!("{}", serde_json::to_string_pretty(&v).unwrap());
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        HandoffCommands::Mechanical {
            project,
            agent,
            dir,
            session,
            model,
            host,
        } => {
            let work_dir = dir.clone().unwrap_or_else(|| {
                std::env::current_dir()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            });
            let detected_project = detect_project(Some(&work_dir));
            if detected_project.is_none() {
                eprintln!(
                    "Error: mechanical handoffs require a Git worktree. Use `handoff dump --workstream ...` for standalone sessions."
                );
                std::process::exit(1);
            }
            let project = project.clone().or(detected_project);

            let Some(ref project) = project else {
                eprintln!("Error: could not detect project. Use --project");
                std::process::exit(1);
            };

            let branch = detect_branch(Some(&work_dir));

            let git = |args: &[&str]| -> String {
                std::process::Command::new("git")
                    .args(args)
                    .current_dir(&work_dir)
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default()
            };

            let status = git(&["status", "--porcelain"]);
            let log = git(&["log", "--oneline", "--no-decorate", "-15"]);
            let diff_stat = git(&["diff", "--stat", "HEAD"]);
            let stash_list = git(&["stash", "list"]);

            let recent_files = std::process::Command::new("find")
                .args([
                    &*work_dir,
                    "-maxdepth",
                    "4",
                    "-mmin",
                    "-30",
                    "-not",
                    "-path",
                    "*/.git/*",
                    "-not",
                    "-path",
                    "*/node_modules/*",
                    "-not",
                    "-path",
                    "*/__pycache__/*",
                    "-not",
                    "-path",
                    "*/target/*",
                    "-type",
                    "f",
                    "-print",
                ])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();

            let recent_lines: Vec<&str> = recent_files.lines().take(30).collect();

            let mut content = format!("# Mechanical State: {}\n\n", project);
            content.push_str(&format!("**Directory:** {}\n", work_dir));
            if let Some(ref b) = branch {
                content.push_str(&format!("**Branch:** {}\n", b));
            }
            content.push_str(&format!(
                "Generated: {}\n\n",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
            ));

            if !status.is_empty() {
                content.push_str("## Git Status\n```\n");
                content.push_str(&status);
                content.push_str("\n```\n\n");
            }
            if !log.is_empty() {
                content.push_str("## Recent Commits\n```\n");
                content.push_str(&log);
                content.push_str("\n```\n\n");
            }
            if !diff_stat.is_empty() {
                content.push_str("## Uncommitted Changes\n```\n");
                content.push_str(&diff_stat);
                content.push_str("\n```\n\n");
            }
            if !stash_list.is_empty() {
                content.push_str("## Git Stashes\n```\n");
                content.push_str(&stash_list);
                content.push_str("\n```\n\n");
            }
            if !recent_lines.is_empty() {
                content.push_str("## Recently Modified Files\n");
                for f in &recent_lines {
                    content.push_str(&format!("- {}\n", f));
                }
                content.push('\n');
            }

            let body = json!({
                "project": project,
                "scope": "repository",
                "workstream": project,
                "branch": branch,
                "directory": work_dir,
                "agent": agent.clone().unwrap_or_else(detect_agent),
                "type": "mechanical",
                "content": content,
                "session_id": detect_session_id(session.as_ref()),
                "model": model.clone().or_else(detect_model),
                "host": host.clone().unwrap_or_else(detect_host),
                "metadata": json!({"cwd": work_dir, "auto": true}),
            });

            match client.post("/handoffs", body).await {
                Ok(v) => {
                    if v.get("skipped").and_then(|s| s.as_bool()).unwrap_or(false) {
                        eprintln!("Skipped duplicate mechanical handoff for '{}'", project);
                    } else if let Some(id) = v.get("id") {
                        // stderr, not stdout: Codex fails any hook whose stdout is non-JSON,
                        // and this runs as a Stop hook. Matches the skip-path message above.
                        eprintln!("Stored mechanical handoff #{} (project={})", id, project);
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        HandoffCommands::List {
            limit,
            project,
            scope,
            workstream,
            agent,
            handoff_type,
        } => {
            let mut params: Vec<(&str, String)> = Vec::new();
            if let Some(ref p) = project {
                params.push(("project", p.clone()));
            }
            if let Some(ref value) = scope {
                params.push(("scope", value.clone()));
            }
            if let Some(ref value) = workstream {
                params.push(("workstream", value.clone()));
            }
            if let Some(ref a) = agent {
                params.push(("agent", a.clone()));
            }
            if let Some(ref t) = handoff_type {
                params.push(("type", t.clone()));
            }
            params.push(("limit", limit.to_string()));

            let query = params
                .iter()
                .map(|(k, v)| format!("{}={}", k, utf8_percent_encode(v, NON_ALPHANUMERIC)))
                .collect::<Vec<_>>()
                .join("&");

            match client.get(&format!("/handoffs?{}", query)).await {
                Ok(v) => {
                    if let Some(handoffs) = v.get("handoffs").and_then(|h| h.as_array()) {
                        print_handoff_rows(handoffs, false);
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        HandoffCommands::Candidates {
            limit,
            scope,
            workstream,
            agent,
            since,
        } => {
            let mut params: Vec<(&str, String)> = vec![("limit", limit.to_string())];
            if let Some(ref value) = scope {
                params.push(("scope", value.clone()));
            }
            if let Some(ref value) = workstream {
                params.push(("workstream", value.clone()));
            }
            if let Some(ref value) = agent {
                params.push(("agent", value.clone()));
            }
            if let Some(ref value) = since {
                params.push(("since", value.clone()));
            }
            let query = params
                .iter()
                .map(|(key, value)| {
                    format!("{}={}", key, utf8_percent_encode(value, NON_ALPHANUMERIC))
                })
                .collect::<Vec<_>>()
                .join("&");

            match client.get(&format!("/handoffs/candidates?{query}")).await {
                Ok(value) => {
                    if let Some(handoffs) = value.get("handoffs").and_then(|rows| rows.as_array()) {
                        if handoffs.is_empty() {
                            eprintln!("No session handoff candidates found");
                        } else {
                            print_handoff_rows(handoffs, true);
                            eprintln!("Restore exactly with: kleos-cli handoff restore --id <ID>");
                        }
                    }
                }
                Err(error) => eprintln!("Error: {}", error),
            }
        }

        HandoffCommands::Search {
            query,
            project,
            limit,
        } => {
            let mut params: Vec<(&str, String)> = vec![("q", query.clone())];
            if let Some(ref p) = project {
                params.push(("project", p.clone()));
            }
            params.push(("limit", limit.to_string()));

            let query_str = params
                .iter()
                .map(|(k, v)| format!("{}={}", k, utf8_percent_encode(v, NON_ALPHANUMERIC)))
                .collect::<Vec<_>>()
                .join("&");

            match client.get(&format!("/handoffs/search?{}", query_str)).await {
                Ok(v) => {
                    if let Some(results) = v.get("results").and_then(|r| r.as_array()) {
                        for r in results {
                            let model_str = r
                                .get("model")
                                .and_then(|m| m.as_str())
                                .map(|m| format!(" [model={}]", m))
                                .unwrap_or_default();
                            println!(
                                "#{:<5}  {}  [{}]  {}  {}{}",
                                r.get("id").and_then(|i| i.as_i64()).unwrap_or(0),
                                r.get("created_at").and_then(|s| s.as_str()).unwrap_or(""),
                                r.get("project").and_then(|s| s.as_str()).unwrap_or(""),
                                r.get("agent").and_then(|s| s.as_str()).unwrap_or(""),
                                r.get("type").and_then(|s| s.as_str()).unwrap_or(""),
                                model_str,
                            );
                            if let Some(snippet) = r.get("snippet").and_then(|s| s.as_str()) {
                                println!("  {}", snippet.replace('\n', " "));
                            }
                        }
                        if results.is_empty() {
                            eprintln!("No results found");
                        }
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        HandoffCommands::Stats => match client.get("/handoffs/stats").await {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(e) => eprintln!("Error: {}", e),
        },

        HandoffCommands::Gc { tiered, keep } => {
            let body = json!({
                "tiered": tiered,
                "keep": keep,
            });
            match client.post("/handoffs/gc", body).await {
                Ok(v) => {
                    let deleted = v.get("deleted").and_then(|d| d.as_i64()).unwrap_or(0);
                    let remaining = v.get("remaining").and_then(|r| r.as_i64()).unwrap_or(0);
                    println!("Deleted {} handoffs. Remaining: {}", deleted, remaining);
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        HandoffCommands::Atoms { cmd } => {
            handle_atom_command(client, cmd).await;
        }
    }
}

/// Prints identity-first handoff rows so standalone candidates remain
/// distinguishable even when they have no repository directory.
fn print_handoff_rows(handoffs: &[Value], full_session: bool) {
    println!("ID\tCreated\tScope\tWorkstream\tTitle\tSession\tType\tAgent");
    for handoff in handoffs {
        let session = handoff
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let session_display = if full_session {
            session.to_string()
        } else {
            session.chars().take(12).collect()
        };
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            handoff.get("id").and_then(Value::as_i64).unwrap_or(0),
            handoff
                .get("created_at")
                .and_then(Value::as_str)
                .unwrap_or(""),
            handoff
                .get("scope")
                .and_then(Value::as_str)
                .unwrap_or("legacy"),
            handoff
                .get("workstream")
                .and_then(Value::as_str)
                .or_else(|| handoff.get("project").and_then(Value::as_str))
                .unwrap_or(""),
            handoff.get("title").and_then(Value::as_str).unwrap_or(""),
            session_display,
            handoff.get("type").and_then(Value::as_str).unwrap_or(""),
            handoff.get("agent").and_then(Value::as_str).unwrap_or(""),
        );
    }
}

/// Dispatch an `kleos-cli handoff atoms <op>` invocation against the server's
/// `/handoff/atoms/*` endpoints.
async fn handle_atom_command(client: &Client, cmd: &AtomCommands) {
    match cmd {
        AtomCommands::List {
            project,
            atom_type,
            status,
            limit,
            dir,
        } => {
            let dir_str = dir.as_deref();
            let project = project.clone().or_else(|| detect_project(dir_str));

            let Some(ref project) = project else {
                eprintln!("Error: could not detect project. Use --project");
                std::process::exit(1);
            };

            let mut query = format!("project={}&status={}&limit={}", project, status, limit);
            if let Some(ref at) = atom_type {
                query.push_str(&format!("&atom_type={}", at));
            }

            match client.get(&format!("/handoffs/atoms?{}", query)).await {
                Ok(v) => {
                    if let Some(atoms) = v.get("atoms").and_then(|a| a.as_array()) {
                        if atoms.is_empty() {
                            println!("No atoms found for project '{}'", project);
                            return;
                        }
                        for atom in atoms {
                            let atype = atom
                                .get("atom_type")
                                .and_then(|t| t.as_str())
                                .unwrap_or("?");
                            let content =
                                atom.get("content").and_then(|c| c.as_str()).unwrap_or("");
                            let salience =
                                atom.get("salience").and_then(|s| s.as_f64()).unwrap_or(0.0);
                            let seen = atom.get("seen_count").and_then(|s| s.as_i64()).unwrap_or(1);
                            let aid = atom.get("atom_id").and_then(|a| a.as_str()).unwrap_or("");
                            println!(
                                "[{:.2}] ({}) {} [seen:{}] id:{}",
                                salience, atype, content, seen, aid
                            );
                        }
                        println!("\n{} atoms total", atoms.len());
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        AtomCommands::Packed {
            project,
            max_tokens,
            dir,
        } => {
            let dir_str = dir.as_deref();
            let project = project.clone().or_else(|| detect_project(dir_str));

            let Some(ref project) = project else {
                eprintln!("Error: could not detect project. Use --project");
                std::process::exit(1);
            };

            let query = format!("project={}&max_tokens={}", project, max_tokens);
            match client
                .get(&format!("/handoffs/atoms/packed?{}", query))
                .await
            {
                Ok(v) => {
                    if let Some(context) = v.get("context").and_then(|c| c.as_str()) {
                        println!("{}", context);
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        AtomCommands::Supersede { old, new } => {
            let body = serde_json::json!({
                "old_atom_id": old,
                "new_atom_id": new,
            });
            match client.post("/handoffs/atoms/supersede", body).await {
                Ok(_) => println!("Atom {} superseded by {}", old, new),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        AtomCommands::Decay {
            project,
            sessions,
            dir,
        } => {
            let dir_str = dir.as_deref();
            let project = project.clone().or_else(|| detect_project(dir_str));

            let Some(ref project) = project else {
                eprintln!("Error: could not detect project. Use --project");
                std::process::exit(1);
            };

            let body = serde_json::json!({
                "project": project,
                "sessions_elapsed": sessions,
            });
            match client.post("/handoffs/atoms/decay", body).await {
                Ok(v) => {
                    let affected = v.get("affected").and_then(|a| a.as_i64()).unwrap_or(0);
                    println!(
                        "Applied decay ({} sessions): {} atoms affected",
                        sessions, affected
                    );
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
    }
}

/// Dispatches `kleos-cli user` subcommands to the /users API.
async fn handle_user_command(client: &Client, cmd: &UserCommands) {
    match cmd {
        UserCommands::Create {
            username,
            email,
            role,
        } => {
            let mut body = json!({ "username": username });
            if let Some(e) = email {
                body["email"] = json!(e);
            }
            if let Some(r) = role {
                body["role"] = json!(r);
            }
            match client.post("/users", body).await {
                Ok(v) => {
                    let id = v.get("id").and_then(|i| i.as_i64()).unwrap_or(0);
                    let name = v.get("username").and_then(|s| s.as_str()).unwrap_or("?");
                    let role = v.get("role").and_then(|s| s.as_str()).unwrap_or("?");
                    println!("Created user #{} (username: {}, role: {})", id, name, role);
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        UserCommands::List { include_inactive } => {
            let path = if *include_inactive {
                "/users?include_inactive=true".to_string()
            } else {
                "/users".to_string()
            };
            match client.get(&path).await {
                Ok(v) => {
                    let users = v.get("users").and_then(|u| u.as_array());
                    match users {
                        Some(users) if !users.is_empty() => {
                            // Print a compact table: ID, username, role, status.
                            for u in users {
                                let id = u.get("id").and_then(|i| i.as_i64()).unwrap_or(0);
                                let name =
                                    u.get("username").and_then(|s| s.as_str()).unwrap_or("?");
                                let role = u.get("role").and_then(|s| s.as_str()).unwrap_or("?");
                                let active = u
                                    .get("is_active")
                                    .and_then(|b| b.as_bool())
                                    .unwrap_or(false);
                                let status = if active { "active" } else { "inactive" };
                                println!("#{:<4} {:<20} {:<10} [{}]", id, name, role, status);
                            }
                        }
                        _ => println!("No users found."),
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
    }
}

/// Dispatches artifact subcommands (upload, download, list, delete).
async fn handle_artifact_command(client: &Client, cmd: &ArtifactCommands) {
    match cmd {
        ArtifactCommands::Upload {
            memory_id,
            file,
            name,
            artifact_type,
            agent,
        } => {
            let path = std::path::Path::new(file);
            if !path.exists() {
                eprintln!("Error: file not found: {}", file);
                return;
            }
            let data = match std::fs::read(path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Error reading file: {}", e);
                    return;
                }
            };
            let filename = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let mime = match path.extension().and_then(|e| e.to_str()) {
                Some("md") => "text/markdown",
                Some("txt") => "text/plain",
                Some("json") => "application/json",
                Some("yaml" | "yml") => "application/yaml",
                Some("toml") => "application/toml",
                Some("rs") => "text/x-rust",
                Some("py") => "text/x-python",
                Some("js") => "application/javascript",
                Some("ts") => "application/typescript",
                Some("html") => "text/html",
                Some("css") => "text/css",
                Some("png") => "image/png",
                Some("jpg" | "jpeg") => "image/jpeg",
                Some("pdf") => "application/pdf",
                _ => "application/octet-stream",
            }
            .to_string();
            let display_name = name.clone().unwrap_or_else(|| filename.clone());

            let file_part = reqwest::multipart::Part::bytes(data)
                .file_name(filename)
                .mime_str(&mime)
                .unwrap_or_else(|_| reqwest::multipart::Part::bytes(vec![]));

            let mut form = reqwest::multipart::Form::new()
                .part("file", file_part)
                .text("name", display_name)
                .text("agent", agent.clone());

            if let Some(at) = artifact_type {
                form = form.text("artifact_type", at.clone());
            }

            let api_path = format!("/artifacts/{}", memory_id);
            match client.post_multipart(&api_path, form).await {
                Ok(v) => {
                    let id = v.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
                    let size = v.get("size_bytes").and_then(|x| x.as_i64()).unwrap_or(0);
                    println!(
                        "Uploaded artifact #{} ({} bytes) -> memory #{}",
                        id, size, memory_id
                    );
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ArtifactCommands::List { memory_id } => {
            match client.get(&format!("/artifacts/{}", memory_id)).await {
                Ok(v) => {
                    let artifacts = v.get("artifacts").and_then(|a| a.as_array());
                    match artifacts {
                        Some(arts) if !arts.is_empty() => {
                            println!("Artifacts for memory #{}:", memory_id);
                            for a in arts {
                                let id = a.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
                                let fname =
                                    a.get("filename").and_then(|x| x.as_str()).unwrap_or("?");
                                let mime =
                                    a.get("mime_type").and_then(|x| x.as_str()).unwrap_or("?");
                                let size =
                                    a.get("size_bytes").and_then(|x| x.as_i64()).unwrap_or(0);
                                println!("  #{} {} ({}, {} bytes)", id, fname, mime, size);
                            }
                        }
                        _ => println!("No artifacts for memory #{}", memory_id),
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ArtifactCommands::Get { id, output } => {
            match client.get_bytes(&format!("/artifact/{}", id)).await {
                Ok((data, filename, _content_type)) => {
                    let out_path = match output.as_deref() {
                        Some("-") => {
                            use std::io::Write;
                            std::io::stdout().write_all(&data).ok();
                            return;
                        }
                        Some(p) => p.to_string(),
                        None => match sanitize_download_name(&filename) {
                            Some(safe) => safe.to_string_lossy().into_owned(),
                            None => {
                                eprintln!(
                                    "Error: refusing to write server-supplied filename {:?} (unsafe path); pass --output to choose a destination",
                                    filename
                                );
                                return;
                            }
                        },
                    };
                    match std::fs::write(&out_path, &data) {
                        Ok(_) => println!(
                            "Downloaded artifact #{} -> {} ({} bytes)",
                            id,
                            out_path,
                            data.len()
                        ),
                        Err(e) => eprintln!("Error writing file: {}", e),
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ArtifactCommands::Delete { id } => {
            match client.delete(&format!("/artifact/{}", id)).await {
                Ok(_) => println!("Deleted artifact #{}", id),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ArtifactCommands::Search { query, limit } => {
            let body = serde_json::json!({ "query": query, "limit": limit });
            match client.post("/artifacts/search", body).await {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ArtifactCommands::Stats => match client.get("/artifacts/stats").await {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(e) => eprintln!("Error: {}", e),
        },
    }
}

/// Build a `FileOrContentBody`-compatible JSON value for the comment-check and
/// challenge-code endpoints.
///
/// When `content_file` is given, reads the file and sends its text as `content`.
/// When `path` is given, sends it as the server-visible `path` field.
/// Returns `Err` when neither is provided or the local file cannot be read.
fn build_file_or_content_body(
    path: &Option<String>,
    content_file: &Option<std::path::PathBuf>,
    extension: &Option<String>,
) -> Result<Value, String> {
    if let Some(cf) = content_file {
        let text = std::fs::read_to_string(cf)
            .map_err(|e| format!("cannot read --content-file {}: {}", cf.display(), e))?;
        let mut body = json!({ "content": text });
        if let Some(ext) = extension {
            body["extension"] = json!(ext);
        }
        Ok(body)
    } else if let Some(p) = path {
        Ok(json!({ "path": p }))
    } else {
        Err("supply either --path or --content-file".to_string())
    }
}

/// Dispatch `kleos-cli forge <op>` subcommands to the server `/forge/*` endpoints.
///
/// Each arm builds a JSON body from CLI arguments and calls `client.post` or
/// `client.get`, then pretty-prints the response. Error handling mirrors the
/// existing subcommand families (e.g. jobs, handoff, skill).
async fn handle_forge_command(client: &Client, cmd: &ForgeCommands) {
    // Pretty-print a successful JSON response to stdout.
    let pretty = |v: Value| println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());

    match cmd {
        ForgeCommands::SpecTask {
            task_description,
            task_type,
            acceptance_criteria,
            interface_contract,
            edge_cases,
            session_id,
            files_to_touch,
            dependencies,
        } => {
            let mut body = json!({
                "task_description": task_description,
                "task_type": task_type,
                "acceptance_criteria": acceptance_criteria,
                "interface_contract": interface_contract,
                "edge_cases": edge_cases,
            });
            if let Some(s) = session_id {
                body["session_id"] = json!(s);
            }
            if !files_to_touch.is_empty() {
                body["files_to_touch"] = json!(files_to_touch);
            }
            if let Some(d) = dependencies {
                body["dependencies"] = json!(d);
            }
            match client.post("/forge/spec-task", body).await {
                Ok(v) => pretty(v),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ForgeCommands::UpdateSpec {
            spec_id,
            status,
            note,
        } => {
            let mut body = json!({
                "spec_id": spec_id,
                "status": status,
            });
            if let Some(n) = note {
                body["note"] = json!(n);
            }
            match client.post("/forge/update-spec", body).await {
                Ok(v) => pretty(v),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ForgeCommands::ListSpecs { status, limit } => {
            let mut path = format!("/forge/specs?limit={}", limit);
            if let Some(s) = status {
                path.push_str(&format!("&status={}", s));
            }
            match client.get(&path).await {
                Ok(v) => pretty(v),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ForgeCommands::GetSpec { id } => match client.get(&format!("/forge/spec/{}", id)).await {
            Ok(v) => pretty(v),
            Err(e) => eprintln!("Error: {}", e),
        },

        ForgeCommands::LogHypothesis {
            bug_description,
            hypothesis,
            session_id,
            confidence,
            spec_id,
        } => {
            let mut body = json!({
                "bug_description": bug_description,
                "hypothesis": hypothesis,
            });
            if let Some(s) = session_id {
                body["session_id"] = json!(s);
            }
            if let Some(c) = confidence {
                body["confidence"] = json!(c);
            }
            if let Some(s) = spec_id {
                body["spec_id"] = json!(s);
            }
            match client.post("/forge/log-hypothesis", body).await {
                Ok(v) => pretty(v),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ForgeCommands::LogOutcome {
            hypothesis_id,
            outcome,
            notes,
        } => {
            let mut body = json!({
                "hypothesis_id": hypothesis_id,
                "outcome": outcome,
            });
            if let Some(n) = notes {
                body["notes"] = json!(n);
            }
            match client.post("/forge/log-outcome", body).await {
                Ok(v) => pretty(v),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ForgeCommands::RecallErrors { query, limit } => {
            let mut path = format!("/forge/recall-errors?limit={}", limit);
            if let Some(q) = query {
                let encoded = utf8_percent_encode(q, NON_ALPHANUMERIC).to_string();
                path.push_str(&format!("&query={}", encoded));
            }
            match client.get(&path).await {
                Ok(v) => pretty(v),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ForgeCommands::ConsiderApproaches {
            problem,
            approaches,
            spec_id,
            chosen_index,
        } => {
            // Each approach is supplied as a raw JSON string on the CLI.
            let parsed: Vec<Value> = approaches
                .iter()
                .map(|s| {
                    serde_json::from_str(s).unwrap_or_else(|_| json!({"name": s, "description": s}))
                })
                .collect();
            let mut body = json!({
                "problem": problem,
                "approaches": parsed,
            });
            if let Some(s) = spec_id {
                body["spec_id"] = json!(s);
            }
            if let Some(i) = chosen_index {
                body["chosen_index"] = json!(i);
            }
            match client.post("/forge/consider-approaches", body).await {
                Ok(v) => pretty(v),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ForgeCommands::Verify {
            command,
            exit_code,
            success,
            spec_id,
            duration_ms,
            criteria_index,
            stdout,
            stderr,
        } => {
            let mut body = json!({
                "command": command,
                "exit_code": exit_code,
                "success": success,
            });
            if let Some(s) = spec_id {
                body["spec_id"] = json!(s);
            }
            if let Some(d) = duration_ms {
                body["duration_ms"] = json!(d);
            }
            if let Some(c) = criteria_index {
                body["criteria_index"] = json!(c);
            }
            if let Some(o) = stdout {
                body["stdout"] = json!(o);
            }
            if let Some(e) = stderr {
                body["stderr"] = json!(e);
            }
            match client.post("/forge/verify", body).await {
                Ok(v) => pretty(v),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ForgeCommands::SessionLearn {
            discovery,
            context,
            tags,
            spec_id,
        } => {
            let mut body = json!({
                "discovery": discovery,
            });
            if let Some(c) = context {
                body["context"] = json!(c);
            }
            if !tags.is_empty() {
                body["tags"] = json!(tags);
            }
            if let Some(s) = spec_id {
                body["spec_id"] = json!(s);
            }
            match client.post("/forge/session-learn", body).await {
                Ok(v) => pretty(v),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ForgeCommands::SessionRecall { query, limit } => {
            let mut path = format!("/forge/session-recall?limit={}", limit);
            if let Some(q) = query {
                let encoded = utf8_percent_encode(q, NON_ALPHANUMERIC).to_string();
                path.push_str(&format!("&query={}", encoded));
            }
            match client.get(&path).await {
                Ok(v) => pretty(v),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ForgeCommands::Think {
            problem,
            constraints,
            context,
        } => {
            let mut body = json!({});
            if let Some(p) = problem {
                body["problem"] = json!(p);
            }
            if !constraints.is_empty() {
                body["constraints"] = json!(constraints);
            }
            if let Some(c) = context {
                body["context"] = json!(c);
            }
            match client.post("/forge/think", body).await {
                Ok(v) => pretty(v),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ForgeCommands::DeclareUnknowns { unknowns } => {
            // Each unknown is supplied as a raw JSON string on the CLI.
            let parsed: Vec<Value> = unknowns
                .iter()
                .map(|s| {
                    serde_json::from_str(s)
                        .unwrap_or_else(|_| json!({"description": s, "blocking": false}))
                })
                .collect();
            let body = json!({ "unknowns": parsed });
            match client.post("/forge/declare-unknowns", body).await {
                Ok(v) => pretty(v),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ForgeCommands::CommentCheck {
            path,
            content_file,
            extension,
        } => {
            let body = build_file_or_content_body(path, content_file, extension);
            match body {
                Ok(b) => match client.post("/forge/comment-check", b).await {
                    Ok(v) => pretty(v),
                    Err(e) => eprintln!("Error: {}", e),
                },
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ForgeCommands::ChallengeCode {
            path,
            content_file,
            extension,
        } => {
            let body = build_file_or_content_body(path, content_file, extension);
            match body {
                Ok(b) => match client.post("/forge/challenge-code", b).await {
                    Ok(v) => pretty(v),
                    Err(e) => eprintln!("Error: {}", e),
                },
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ForgeCommands::RepoMap {
            path,
            focus,
            max_tokens,
        } => {
            let mut body = json!({ "path": path });
            if !focus.is_empty() {
                body["focus"] = json!(focus);
            }
            if let Some(mt) = max_tokens {
                body["max_tokens"] = json!(mt);
            }
            match client.post("/forge/repo-map", body).await {
                Ok(v) => pretty(v),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ForgeCommands::SearchCode {
            query,
            path,
            symbol_type,
            limit,
        } => {
            let mut body = json!({ "path": path });
            if let Some(q) = query {
                body["query"] = json!(q);
            }
            if let Some(st) = symbol_type {
                body["symbol_type"] = json!(st);
            }
            if let Some(l) = limit {
                body["limit"] = json!(l);
            }
            match client.post("/forge/search-code", body).await {
                Ok(v) => pretty(v),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        ForgeCommands::ImportLocal {
            db,
            session_id,
            include_completed,
        } => {
            // Resolve the SQLite path: use --db or fall back to ~/.agent-forge/forge.db.
            let db_path = if let Some(p) = db.as_deref() {
                p.to_string()
            } else {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                format!("{}/.agent-forge/forge.db", home)
            };

            // Fail gracefully when the file does not exist rather than returning
            // a confusing rusqlite "unable to open database" error.
            if !std::path::Path::new(&db_path).exists() {
                println!("No agent-forge database found at {}", db_path);
                return;
            }

            // Open the SQLite database in read-only mode.
            let conn = match rusqlite::Connection::open_with_flags(
                &db_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            ) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error opening {}: {}", db_path, e);
                    return;
                }
            };

            // Build the query: active-only by default; all statuses with --include-completed.
            let sql = if *include_completed {
                "SELECT id, task_description, task_type, acceptance_criteria, interface_contract, \
                 edge_cases, files_to_touch, dependencies, status FROM specs"
                    .to_string()
            } else {
                "SELECT id, task_description, task_type, acceptance_criteria, interface_contract, \
                 edge_cases, files_to_touch, dependencies, status FROM specs WHERE status = 'active'"
                    .to_string()
            };

            // Collect rows into a Vec so we are done with the connection before
            // we begin the async HTTP loop (rusqlite Connection is not Send).
            struct SpecRow {
                /// Row primary key from the local SQLite.
                id: String,
                /// Human-readable task description.
                task_description: String,
                /// Category of work (feature, bugfix, etc.).
                task_type: String,
                /// JSON-array text of acceptance criteria.
                acceptance_criteria: Vec<String>,
                /// Stable public interface description.
                interface_contract: String,
                /// JSON-array text of edge cases.
                edge_cases: Vec<String>,
                /// JSON-array text of files to touch.
                files_to_touch: Vec<String>,
                /// Free-text external dependencies or blockers.
                dependencies: Option<String>,
            }

            /// Parse a nullable JSON-array TEXT column into Vec<String>, tolerating
            /// NULL, empty string, and invalid JSON gracefully.
            fn parse_json_array(raw: Option<String>) -> Vec<String> {
                raw.and_then(|s| {
                    if s.trim().is_empty() {
                        None
                    } else {
                        match serde_json::from_str::<Vec<String>>(&s) {
                            Ok(v) => Some(v),
                            Err(e) => {
                                // Surface malformed rows instead of silently
                                // rendering them as empty lists.
                                eprintln!(
                                    "warning: malformed JSON array in spec row ({}): {}",
                                    e,
                                    s.chars().take(80).collect::<String>()
                                );
                                None
                            }
                        }
                    }
                })
                .unwrap_or_default()
            }

            let mut stmt = match conn.prepare(&sql) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error preparing query: {}", e);
                    return;
                }
            };

            let rows_result: Result<Vec<SpecRow>, rusqlite::Error> = stmt
                .query_map([], |row| {
                    Ok(SpecRow {
                        id: row.get::<_, String>(0)?,
                        task_description: row.get::<_, String>(1)?,
                        task_type: row.get::<_, String>(2)?,
                        acceptance_criteria: parse_json_array(row.get::<_, Option<String>>(3)?),
                        interface_contract: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                        edge_cases: parse_json_array(row.get::<_, Option<String>>(5)?),
                        files_to_touch: parse_json_array(row.get::<_, Option<String>>(6)?),
                        dependencies: row.get::<_, Option<String>>(7)?,
                    })
                })
                .and_then(|mapped| mapped.collect());

            let rows = match rows_result {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error reading specs table: {}", e);
                    return;
                }
            };

            if rows.is_empty() {
                println!("No specs to import from {}", db_path);
                return;
            }

            // The session ID used on every imported spec.
            let sid = session_id.as_deref().unwrap_or("import-local").to_string();

            // Track import outcomes: (local_id, reason) for skipped rows.
            let mut imported = 0usize;
            let mut skipped: Vec<(String, String)> = Vec::new();

            for row in rows {
                let mut body = json!({
                    "session_id": sid,
                    "task_description": row.task_description,
                    "task_type": row.task_type,
                    "acceptance_criteria": row.acceptance_criteria,
                    "interface_contract": row.interface_contract,
                    "edge_cases": row.edge_cases,
                    "files_to_touch": row.files_to_touch,
                    "dependencies": serde_json::Value::Null,
                });
                if let Some(ref d) = row.dependencies {
                    body["dependencies"] = json!(d);
                }

                match client.post("/forge/spec-task", body).await {
                    Ok(_) => {
                        imported += 1;
                    }
                    Err(e) => {
                        // Count as skipped; continue with remaining rows.
                        skipped.push((row.id.clone(), e.to_string()));
                    }
                }
            }

            // Print the final import summary.
            println!(
                "Import complete: {} imported, {} skipped",
                imported,
                skipped.len()
            );
            for (id, reason) in &skipped {
                println!("  SKIPPED {} -- {}", id, reason);
            }
        }

        ForgeCommands::SessionDiff { base } => {
            // Validate the optional base ref to prevent flag injection or shell
            // metacharacter injection. Mirrors agent-forge's validate_git_ref logic.
            if let Some(ref b) = base {
                if b.len() > 100 {
                    eprintln!("Error: git base ref too long");
                    return;
                }
                let all_safe = b
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.~/^:@{}".contains(c));
                if !all_safe {
                    eprintln!("Error: git base ref contains disallowed characters");
                    return;
                }
                if b.starts_with('-') {
                    eprintln!("Error: git base ref must not start with '-'");
                    return;
                }
            }

            // Build the argument list for both git invocations.
            let stat_args: Vec<&str> = if let Some(ref b) = base {
                vec!["diff", "--stat", b.as_str()]
            } else {
                vec!["diff", "--stat"]
            };

            let names_args: Vec<&str> = if let Some(ref b) = base {
                vec!["diff", "--name-only", b.as_str()]
            } else {
                vec!["diff", "--name-only"]
            };

            // Run git diff --stat and print its output directly.
            match std::process::Command::new("git").args(&stat_args).output() {
                Ok(out) => {
                    let stat = String::from_utf8_lossy(&out.stdout);
                    if stat.trim().is_empty() {
                        println!("No changes.");
                    } else {
                        println!("{}", stat.trim());
                    }
                    if !out.stderr.is_empty() {
                        eprintln!("{}", String::from_utf8_lossy(&out.stderr).trim());
                    }
                }
                Err(e) => {
                    eprintln!("Error running git diff --stat: {}", e);
                    return;
                }
            }

            // Run git diff --name-only and print the changed file list.
            match std::process::Command::new("git").args(&names_args).output() {
                Ok(out) => {
                    let names = String::from_utf8_lossy(&out.stdout);
                    let files: Vec<&str> = names.lines().filter(|l| !l.is_empty()).collect();
                    if !files.is_empty() {
                        println!("\nChanged files ({}):", files.len());
                        for f in &files {
                            println!("  {}", f);
                        }
                    }
                    if !out.stderr.is_empty() {
                        eprintln!("{}", String::from_utf8_lossy(&out.stderr).trim());
                    }
                }
                Err(e) => eprintln!("Error running git diff --name-only: {}", e),
            }
        }
    }
}

/// Tests for CLI-side input sanitization helpers.
#[cfg(test)]
mod tests {
    use super::{
        detect_project_at_path, dump_scope, is_safe_materialization_path, project_from_remote,
        resolve_credential_authority_url, restore_requires_exact_session, sanitize_download_name,
    };
    use kleos_lib::config::DEFAULT_CREDENTIAL_AUTHORITY_URL;

    /// Dematerialize only deletes .md files with no traversal component,
    /// and absolute paths only inside ~/.claude/.
    #[test]
    fn safe_materialization_path_guards_deletion() {
        let home = Some("/home/u");
        assert!(is_safe_materialization_path(
            "/home/u/.claude/agents/foo.md",
            home
        ));
        assert!(is_safe_materialization_path("agents/bar.md", home));
        // Wrong extension or traversal is refused.
        assert!(!is_safe_materialization_path("/etc/cron.d/evil", home));
        assert!(!is_safe_materialization_path("/home/u/.bashrc", home));
        assert!(!is_safe_materialization_path("../../etc/passwd.md", home));
        assert!(!is_safe_materialization_path("agents/../../x.md", home));
        // Absolute .md OUTSIDE ~/.claude is refused: a poisoned record must
        // not aim deletion at arbitrary user documents.
        assert!(!is_safe_materialization_path("/home/u/notes/real.md", home));
        assert!(!is_safe_materialization_path(
            "/home/other/.claude/agents/foo.md",
            home
        ));
        // No HOME resolvable: refuse all absolute paths.
        assert!(!is_safe_materialization_path(
            "/home/u/.claude/agents/foo.md",
            None
        ));
    }

    /// A server-supplied filename is reduced to its final, CWD-relative component.
    #[test]
    fn sanitize_download_name_strips_paths() {
        assert_eq!(
            sanitize_download_name("../../etc/passwd")
                .unwrap()
                .to_str()
                .unwrap(),
            "passwd"
        );
        let shadow = sanitize_download_name("/etc/shadow").unwrap();
        assert!(shadow.is_relative());
        assert_eq!(shadow.to_str().unwrap(), "shadow");
        assert_eq!(
            sanitize_download_name("~/.ssh/authorized_keys")
                .unwrap()
                .to_str()
                .unwrap(),
            "authorized_keys"
        );
        // A plain name is unchanged.
        assert_eq!(
            sanitize_download_name("report.pdf")
                .unwrap()
                .to_str()
                .unwrap(),
            "report.pdf"
        );
        // Names with no usable final component are refused.
        assert!(sanitize_download_name("").is_none());
        assert!(sanitize_download_name(".").is_none());
        assert!(sanitize_download_name("..").is_none());
        assert!(sanitize_download_name("/").is_none());
    }

    /// Non-Git folders, including date-slug session directories, never become
    /// inferred project identities.
    #[test]
    fn project_detection_rejects_ordinary_directories() {
        let unique = format!(
            "kleos-handoff-non-git-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::create_dir(&path).expect("create isolated test directory");
        assert_eq!(detect_project_at_path(&path), None);
        std::fs::remove_dir(&path).expect("remove isolated empty test directory");
    }

    /// Repository names are parsed consistently from common Git remote forms.
    #[test]
    fn project_detection_parses_remote_names() {
        assert_eq!(
            project_from_remote("https://github.com/example/Kleos.git").as_deref(),
            Some("Kleos")
        );
        assert_eq!(
            project_from_remote("git@github.com:example/Kleos.git").as_deref(),
            Some("Kleos")
        );
        assert_eq!(project_from_remote(""), None);
    }

    /// A project label does not make a non-Git restore safe; callers outside
    /// Git still need an exact handoff id or stable session id.
    #[test]
    fn standalone_restore_requires_stable_session() {
        assert!(restore_requires_exact_session(false, None));
        assert!(!restore_requires_exact_session(false, Some("thread-123")));
        assert!(!restore_requires_exact_session(true, None));
    }

    /// Dump scope depends on Git detection, not an explicit compatibility
    /// project label supplied while outside a worktree.
    #[test]
    fn standalone_dump_scope_cannot_be_overridden_by_project_label() {
        let explicit_project = Some("legacy-project".to_string());
        let detected_project: Option<String> = None;
        let resolved_project = explicit_project.or(detected_project.clone());

        assert_eq!(resolved_project.as_deref(), Some("legacy-project"));
        assert_eq!(dump_scope(detected_project.is_some()), "standalone");
        assert_eq!(dump_scope(true), "repository");
    }

    /// PHYLAXD_URL input wins over legacy CREDD_URL input.
    #[test]
    fn resolve_credential_authority_url_prefers_phylaxd() {
        assert_eq!(
            resolve_credential_authority_url(
                Some("http://127.0.0.1:3100"),
                Some("http://127.0.0.1:4400")
            ),
            "http://127.0.0.1:3100"
        );
    }

    /// CREDD_URL input remains the transition fallback.
    #[test]
    fn resolve_credential_authority_url_uses_legacy_credd_fallback() {
        assert_eq!(
            resolve_credential_authority_url(None, Some("http://127.0.0.1:4401")),
            "http://127.0.0.1:4401"
        );
    }

    /// Missing authority inputs resolve to the shared local default.
    #[test]
    fn resolve_credential_authority_url_uses_default() {
        assert_eq!(
            resolve_credential_authority_url(None, None),
            DEFAULT_CREDENTIAL_AUTHORITY_URL
        );
    }
}
