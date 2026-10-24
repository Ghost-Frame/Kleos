use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// Default URL for the local credential authority during the Phylax transition.
pub const DEFAULT_CREDENTIAL_AUTHORITY_URL: &str = "http://127.0.0.1:4400";

/// Shim: for every `KLEOS_X` env var found, set `ENGRAM_X` if not already set.
///
/// Call this once at binary startup (before any config loading) so that the
/// new `KLEOS_*` prefix works transparently alongside existing `ENGRAM_*` vars.
pub fn migrate_env_prefix() {
    let pairs: Vec<(String, String)> = std::env::vars()
        .filter_map(|(k, v)| {
            k.strip_prefix("KLEOS_")
                .map(|suffix| (format!("ENGRAM_{}", suffix), v))
        })
        .collect();

    for (engram_key, value) in pairs {
        if std::env::var(&engram_key).is_err() {
            std::env::set_var(&engram_key, &value);
        }
    }
}

/// Resolve the actual DB path to open, applying a legacy fallback.
///
/// Rules:
/// 1. If `configured` path exists on disk, use it as-is.
/// 2. If `configured` filename is `kleos.db` and that file does NOT exist,
///    check whether `engram.db` in the same directory exists. If so, warn and
///    return that legacy path so existing deployments keep working without
///    renaming anything.
/// 3. Otherwise return `configured` unchanged (the caller will create it).
pub fn resolve_db_path(configured: &std::path::Path) -> std::path::PathBuf {
    if configured.exists() {
        return configured.to_path_buf();
    }

    // Only attempt legacy fallback when the configured name is kleos.db.
    if configured.file_name().and_then(|n| n.to_str()) == Some("kleos.db") {
        let legacy = configured
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("engram.db");
        if legacy.exists() {
            tracing::warn!(
                legacy = %legacy.display(),
                "kleos.db not found -- falling back to legacy engram.db"
            );
            return legacy;
        }
    }

    configured.to_path_buf()
}

/// Resolve the credential authority URL from preferred and legacy env vars.
pub fn resolve_credential_authority_url() -> String {
    credential_authority_url_from_env()
        .unwrap_or_else(|| DEFAULT_CREDENTIAL_AUTHORITY_URL.to_string())
}

/// Resolve a credential authority URL override from the environment.
fn credential_authority_url_from_env() -> Option<String> {
    std::env::var("PHYLAXD_URL")
        .or_else(|_| std::env::var("CREDD_URL"))
        .ok()
}

/// How the at-rest encryption key is sourced.
///
/// Default is `None` (no encryption). When set, every SQLite connection
/// issues `PRAGMA key` as its first statement so the database file is
/// encrypted via SQLCipher.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EncryptionMode {
    /// No encryption -- database opens without PRAGMA key.
    #[default]
    None,
    /// Read a raw 32-byte key from `~/.config/engram/dbkey`.
    Keyfile,
    /// Hex-decode the `ENGRAM_DB_KEY` env var (64 hex chars = 32 bytes).
    Env,
    /// YubiKey HMAC-SHA1 challenge-response on slot 2, derived via Argon2id.
    Yubikey,
    /// Phylax custody profile: the same YubiKey HMAC derivation as `Yubikey`,
    /// but from OTP slot 1 with the challenge persisted at
    /// `/var/lib/phylax/challenge` (override: `PHYLAX_CHALLENGE_PATH`). There
    /// is no fallback to slot 2; an unprogrammed slot 1 is a hard error.
    Custody,
}

/// Encryption settings for the main SQLite database.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EncryptionConfig {
    #[serde(default)]
    pub mode: EncryptionMode,
}

/// A server entry used for SSH validation and reboot protection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerEntry {
    /// Canonical name used to identify this server.
    pub name: String,
    /// Alternate hostnames / aliases for this server.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Human-readable role description.
    #[serde(default)]
    pub role: String,
    /// SSH user to use when connecting.
    #[serde(default)]
    pub ssh_user: String,
    /// SSH port (default 22).
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    /// When true, a non-default port is required.
    #[serde(default)]
    pub custom_port_required: bool,
    /// When true, reboot/shutdown commands targeting this server are blocked.
    #[serde(default)]
    pub no_reboot: bool,
    /// Operational notes shown to the agent on SSH enrichment.
    #[serde(default)]
    pub notes: String,
}

/// Default SSH port used when a server entry omits one.
fn default_ssh_port() -> u16 {
    22
}

/// Default number of daily backups to retain.
fn default_backup_retention_daily() -> usize {
    30
}

/// Default pre-authentication per-IP rate limit (requests per minute).
/// Kept in sync with the historical hardcoded value so behaviour is unchanged
/// unless an operator overrides `KLEOS_PREAUTH_IP_RPM`.
fn default_preauth_ip_rpm() -> i64 {
    60
}

/// Default switch for the background dreamer task.
fn default_dreamer_enabled() -> bool {
    true
}

/// Default interval between dreamer ticks.
fn default_dream_interval_secs() -> u64 {
    300
}

/// Default interval between scheduled community-detection cycles (6h; communities change slowly).
fn default_community_detection_interval_secs() -> u64 {
    21600
}

/// Default idle window before dreamer work starts.
fn default_dream_idle_threshold_secs() -> u64 {
    60
}

/// Default switch for the associative auto-linker (restored after a regression
/// left memories unlinked). Enabled so new memories rejoin the graph.
fn default_auto_link_enabled() -> bool {
    true
}

/// Default number of unlinked memories the auto-linker processes per dreamer
/// cycle. Bounds per-tick work so a large backlog drains gradually.
fn default_auto_link_batch() -> usize {
    50
}

/// Default switch for autonomous skill evolution.
fn default_skill_evolution_enabled() -> bool {
    true
}

/// Default minimum interval between skill-evolution runs.
fn default_skill_evolution_interval_secs() -> u64 {
    1800
}

/// Default per-tick limit for skill fixes.
fn default_skill_evolution_max_fixes_per_tick() -> u32 {
    3
}

/// Default per-tick limit for skill captures.
fn default_skill_evolution_max_captures_per_tick() -> u32 {
    2
}

/// Default per-tick limit for skill derivations.
fn default_skill_evolution_max_derives_per_tick() -> u32 {
    1
}

/// Default failure-rate threshold for skill repair.
fn default_skill_evolution_failure_threshold() -> f32 {
    0.3
}

/// Default minimum executions before skill repair is considered.
fn default_skill_evolution_min_executions() -> u32 {
    5
}

/// Default cooldown before a repaired skill can be repaired again.
fn default_skill_evolution_refix_cooldown_secs() -> u64 {
    86_400
}

/// Default memory tag that marks a skill-capture candidate.
fn default_skill_evolution_capture_tag() -> String {
    "skill_candidate".to_string()
}

/// Default minimum tag similarity for skill derivation.
fn default_skill_evolution_derive_similarity() -> f32 {
    0.7
}

/// Default switch for session-end Thymus auto-evaluation.
fn default_thymus_autoeval_enabled() -> bool {
    true
}

/// Default minimum turn count below which Thymus auto-evaluation is skipped.
fn default_thymus_autoeval_min_turns() -> i32 {
    3
}

/// Default local SearXNG endpoint for web search.
fn default_web_search_url() -> String {
    "http://127.0.0.1:8888".to_string()
}

/// Default upstream timeout for web search requests.
fn default_web_search_timeout_ms() -> u64 {
    8000
}

/// Default result limit for web search requests.
fn default_web_search_limit() -> u32 {
    10
}

/// Gate policy configuration for command validation and approvals.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GateConfig {
    pub blocked_patterns: Vec<String>,
    pub reserved_targets: Vec<String>,
    pub approval_timeout_secs: u64,
    /// Services that must not be stopped or restarted without explicit confirmation.
    #[serde(default)]
    pub protected_services: Vec<String>,
    /// Known server inventory used for SSH validation and reboot protection.
    #[serde(default)]
    pub servers: Vec<ServerEntry>,
}

/// Default gate policy values used when config files omit the gate section.
impl Default for GateConfig {
    /// Builds a conservative default gate configuration.
    fn default() -> Self {
        Self {
            blocked_patterns: vec![
                "rm -rf /".to_string(),
                "rm -rf ~".to_string(),
                "mkfs".to_string(),
                "dd if=".to_string(),
                ":(){ :|:& };:".to_string(),
                "reboot".to_string(),
                "shutdown".to_string(),
                "halt".to_string(),
                "> /dev/sda".to_string(),
                "chmod -R 777 /".to_string(),
            ],
            reserved_targets: Vec::new(),
            approval_timeout_secs: 300,
            protected_services: Vec::new(),
            servers: Vec::new(),
        }
    }
}

/// Growth-loop configuration for observation and reflection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GrowthConfig {
    pub reflection_interval_secs: u64,
    pub observation_limit: usize,
}

/// Default growth-loop limits and intervals.
impl Default for GrowthConfig {
    /// Builds default growth-loop settings.
    fn default() -> Self {
        Self {
            reflection_interval_secs: 3600,
            observation_limit: 100,
        }
    }
}

/// Session streaming and secret-scrubbing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionsConfig {
    pub max_concurrent: usize,
    pub buffer_size: usize,
    pub stream_timeout_secs: u64,
    pub scrub_secrets: bool,
    /// Behavior when scrubbing is enabled but the secret list cannot be loaded
    /// AND no prior list is cached to fall back on (e.g. credd down at cold
    /// start). `true` (the default) fails OPEN: persist the message and log,
    /// avoiding a hard dependency on credd for message writes (credd is
    /// optional, and scrub_secrets defaults on). `false` fails CLOSED: reject
    /// the write so a fault cannot persist an unscrubbed secret -- appropriate
    /// for deployments that always run credd. Note: a transient outage with a
    /// warm cache still scrubs using the last-known secret list, so this policy
    /// only governs the cold-cache case.
    pub scrub_fail_open: bool,
}

/// Default session streaming configuration.
impl Default for SessionsConfig {
    /// Builds default session streaming limits.
    fn default() -> Self {
        Self {
            max_concurrent: 64,
            buffer_size: 4096,
            stream_timeout_secs: 1800,
            scrub_secrets: true,
            // Fail open by default in the cold-cache case so message writes do
            // not hard-depend on credd (which is optional). A warm cache still
            // scrubs via the stale-list fallback; strict deployments set false.
            scrub_fail_open: true,
        }
    }
}

/// Prompt-generation limits and inclusion toggles.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PromptConfig {
    pub default_max_tokens: usize,
    pub personality_weight: f32,
    pub default_include_memories: bool,
    pub default_include_personality: bool,
    pub max_tokens_cap: usize,
}

/// Default prompt-generation configuration.
impl Default for PromptConfig {
    /// Builds default prompt-generation limits.
    fn default() -> Self {
        Self {
            default_max_tokens: 4000,
            personality_weight: 0.3,
            default_include_memories: true,
            default_include_personality: true,
            max_tokens_cap: 128000,
        }
    }
}

/// Credential authority client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CreddConfig {
    pub url: String,
    pub agent_key_env: String,
    pub allow_raw: bool,
    pub cache_ttl_secs: u64,
}

/// Default credential authority client settings.
impl Default for CreddConfig {
    /// Builds default credential authority settings.
    fn default() -> Self {
        Self {
            url: DEFAULT_CREDENTIAL_AUTHORITY_URL.to_string(),
            agent_key_env: "CREDD_AGENT_KEY".to_string(),
            allow_raw: false,
            cache_ttl_secs: 60,
        }
    }
}

/// Eidolon integration configuration nested under the main server config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EidolonConfig {
    pub enabled: bool,
    pub url: Option<String>,
    #[serde(skip, default)]
    pub api_key: Option<SecretString>,
    #[serde(default)]
    pub credd: CreddConfig,
    #[serde(default)]
    pub gate: GateConfig,
    #[serde(default)]
    pub growth: GrowthConfig,
    #[serde(default)]
    pub sessions: SessionsConfig,
    #[serde(default)]
    pub prompt: PromptConfig,
}

/// Constructors and environment layering for Eidolon configuration.
impl EidolonConfig {
    /// Builds Eidolon configuration from defaults plus environment overrides.
    pub fn from_env() -> Self {
        Self::default().apply_env()
    }

    /// Apply environment-variable overrides on top of `self`. Used to layer
    /// env on top of a TOML-loaded base so env always wins.
    pub fn apply_env(mut self) -> Self {
        if let Ok(v) = crate::kleos_env("EIDOLON_ENABLED") {
            self.enabled = matches!(v.as_str(), "1" | "true" | "TRUE" | "yes");
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_URL") {
            self.url = Some(v);
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_API_KEY") {
            self.api_key = Some(SecretString::new(v));
        }
        let c = &mut self;
        if let Some(v) = credential_authority_url_from_env() {
            c.credd.url = v;
        }
        if let Ok(v) = crate::kleos_env("CREDD_AGENT_KEY_ENV") {
            c.credd.agent_key_env = v;
        }
        if let Ok(v) = crate::kleos_env("CREDD_ALLOW_RAW") {
            c.credd.allow_raw = matches!(v.as_str(), "1" | "true" | "TRUE" | "yes");
        }
        if let Ok(v) = crate::kleos_env("CREDD_CACHE_TTL_SECS") {
            if let Ok(n) = v.parse() {
                c.credd.cache_ttl_secs = n;
            }
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_GATE_APPROVAL_TIMEOUT") {
            if let Ok(n) = v.parse() {
                c.gate.approval_timeout_secs = n;
            }
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_GATE_BLOCKED_PATTERNS") {
            c.gate.blocked_patterns = v.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_GATE_RESERVED_TARGETS") {
            c.gate.reserved_targets = v.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_GROWTH_INTERVAL") {
            if let Ok(n) = v.parse() {
                c.growth.reflection_interval_secs = n;
            }
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_GROWTH_OBSERVATION_LIMIT") {
            if let Ok(n) = v.parse() {
                c.growth.observation_limit = n;
            }
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_SESSIONS_MAX") {
            if let Ok(n) = v.parse() {
                c.sessions.max_concurrent = n;
            }
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_SESSIONS_BUFFER") {
            if let Ok(n) = v.parse() {
                c.sessions.buffer_size = n;
            }
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_SESSIONS_STREAM_TIMEOUT") {
            if let Ok(n) = v.parse() {
                c.sessions.stream_timeout_secs = n;
            }
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_SESSIONS_SCRUB_SECRETS") {
            c.sessions.scrub_secrets = matches!(v.as_str(), "1" | "true" | "TRUE" | "yes");
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_SESSIONS_SCRUB_FAIL_OPEN") {
            c.sessions.scrub_fail_open = matches!(v.as_str(), "1" | "true" | "TRUE" | "yes");
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_PROMPT_MAX_TOKENS") {
            if let Ok(n) = v.parse() {
                c.prompt.default_max_tokens = n;
            }
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_PROMPT_MAX_TOKENS_CAP") {
            if let Ok(n) = v.parse() {
                c.prompt.max_tokens_cap = n;
            }
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_PROMPT_PERSONALITY_WEIGHT") {
            if let Ok(n) = v.parse() {
                c.prompt.personality_weight = n;
            }
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_PROMPT_INCLUDE_MEMORIES") {
            c.prompt.default_include_memories = matches!(v.as_str(), "1" | "true" | "TRUE" | "yes");
        }
        if let Ok(v) = crate::kleos_env("EIDOLON_PROMPT_INCLUDE_PERSONALITY") {
            c.prompt.default_include_personality =
                matches!(v.as_str(), "1" | "true" | "TRUE" | "yes");
        }
        self
    }
}

/// Safety constraints injected into living prompts as mandatory rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SafetyConfig {
    #[serde(default)]
    pub rules: Vec<String>,
}

/// Top-level server configuration loaded from defaults, TOML, and environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub db_path: String,
    pub host: String,
    pub port: u16,
    #[serde(skip, default)]
    pub api_key: Option<SecretString>,
    pub embedding_dim: usize,
    pub default_retention: f32,
    pub embedding_model: String,
    pub embedding_max_seq: usize,
    pub embedding_model_dir: Option<String>,
    pub embedding_onnx_file: String,
    /// When true, refuse to download model weights from HuggingFace at
    /// boot. Files must already exist in `embedding_model_dir`. Use this
    /// for air-gapped deployments or to stop a restart storm from
    /// quietly pulling the wrong model.
    pub embedding_offline_only: bool,
    pub embedding_chunk_max_chars: usize,
    pub embedding_chunk_overlap: usize,
    pub embedding_chunk_max_chunks: usize,
    pub reranker_enabled: bool,
    pub reranker_top_k: usize,
    pub reranker_model_dir: Option<String>,
    /// Reranker model identifier. Selects the download URL set and the on-disk
    /// model subdir. "granite-embedding-reranker-english-r2" (English) or
    /// "bge-reranker-v2-m3" (multilingual). Override: KLEOS_RERANKER_MODEL_NAME.
    pub reranker_model: String,
    pub data_dir: String,
    pub lance_index_path: Option<String>,
    pub vector_dimensions: usize,
    pub use_lance_index: bool,
    pub use_chunk_vector_search: bool,
    /// L5: enable `structured_facts` as an RRF retrieval channel in `hybrid_search`.
    /// Default false -- this changes ranked output, so per the rollout gate it is opt-in via
    /// `KLEOS_FACTS_CHANNEL_ENABLED` and only after the per-tenant mis-scoped-row guard passes.
    pub facts_channel_enabled: bool,
    /// Whether the GUI is enabled. Set via KLEOS_GUI_PASSWORD or the legacy
    /// ENGRAM_GUI_PASSWORD (any non-empty value enables the GUI).
    /// A separate gui_password field can be added later
    /// when an actual password gate is needed; for now the field is a bool.
    #[serde(skip, default)]
    pub gui_enabled: bool,
    pub gui_build_dir: Option<String>,
    /// Optional directory of audio files served same-origin at /media/music/*
    /// for the GUI music player. Unset means the player stays hidden. Set via
    /// KLEOS_GUI_MUSIC_DIR (or legacy ENGRAM_GUI_MUSIC_DIR).
    pub gui_music_dir: Option<String>,
    pub pagerank_refresh_interval_secs: u64,
    pub pagerank_dirty_threshold: u32,
    pub pagerank_max_concurrent: usize,
    pub pagerank_enabled: bool,
    /// L4b: run the scheduled community-detection job that keeps `community_id` fresh for
    /// the community retrieval channel. Default false (periodic compute + ranked-output change
    /// once the channel is enabled).
    #[serde(default)]
    pub community_detection_enabled: bool,
    /// Interval between scheduled community-detection cycles, in seconds. Default 21600 (6h).
    #[serde(default = "default_community_detection_interval_secs")]
    pub community_detection_interval_secs: u64,
    /// Whether consolidation endpoints are available. Default false --
    /// consolidation merges memories into vague summaries and hides the
    /// originals, degrading search quality.
    #[serde(default)]
    pub consolidation_enabled: bool,
    /// Whether to run the background dreamer/consolidation task.
    #[serde(default = "default_dreamer_enabled")]
    pub dreamer_enabled: bool,
    /// Interval between dreamer cycles in seconds. Default: 300 (5 min).
    #[serde(default = "default_dream_interval_secs")]
    pub dream_interval_secs: u64,
    /// Seconds of HTTP idle required before a dreamer tick actually runs.
    /// Protects active request traffic from CPU contention with consolidation
    /// work. Set to 0 to disable idle gating. Default: 60.
    #[serde(default = "default_dream_idle_threshold_secs")]
    pub dream_idle_threshold_secs: u64,
    /// Whether the dreamer's associative auto-linker runs. When true, each cycle
    /// links a batch of unlinked memories to their nearest neighbours
    /// (`similarity` links), reviving the dedup/consolidation passes that read
    /// them. Default: true.
    #[serde(default = "default_auto_link_enabled")]
    pub auto_link_enabled: bool,
    /// Unlinked memories the auto-linker processes per dreamer cycle. Default: 50.
    #[serde(default = "default_auto_link_batch")]
    pub auto_link_batch: usize,
    /// Run the hermes-style autonomous skill evolution phase inside the
    /// dreamer tick. Gates fix/capture/derive passes together.
    #[serde(default = "default_skill_evolution_enabled")]
    pub skill_evolution_enabled: bool,
    /// Minimum seconds between skill-evolution runs. The dreamer ticks more
    /// often (dream_interval_secs); this sub-interval gates the evolution
    /// phase independently. Default: 1800 (30 min).
    #[serde(default = "default_skill_evolution_interval_secs")]
    pub skill_evolution_interval_secs: u64,
    /// Upper bound on fix_skill calls per tick per user.
    #[serde(default = "default_skill_evolution_max_fixes_per_tick")]
    pub skill_evolution_max_fixes_per_tick: u32,
    /// Upper bound on capture_skill calls per tick per user.
    #[serde(default = "default_skill_evolution_max_captures_per_tick")]
    pub skill_evolution_max_captures_per_tick: u32,
    /// Upper bound on derive_skill calls per tick per user.
    #[serde(default = "default_skill_evolution_max_derives_per_tick")]
    pub skill_evolution_max_derives_per_tick: u32,
    /// Skills whose success_rate falls below this are eligible for auto-fix.
    #[serde(default = "default_skill_evolution_failure_threshold")]
    pub skill_evolution_failure_threshold: f32,
    /// Skills with fewer executions than this are ignored by the fix pass.
    #[serde(default = "default_skill_evolution_min_executions")]
    pub skill_evolution_min_executions: u32,
    /// Cooldown (seconds) after a fix to avoid re-fixing the same parent.
    /// Tracked via child skill_records.created_at + parent_skill_id, since
    /// skill_tags has no timestamp column.
    #[serde(default = "default_skill_evolution_refix_cooldown_secs")]
    pub skill_evolution_refix_cooldown_secs: u64,
    /// Memory `tags` entry (JSON array element) that marks a memory as a
    /// skill candidate the dreamer should capture.
    #[serde(default = "default_skill_evolution_capture_tag")]
    pub skill_evolution_capture_tag: String,
    /// Minimum tag-Jaccard similarity between two skills before they become
    /// candidates for derivation.
    #[serde(default = "default_skill_evolution_derive_similarity")]
    pub skill_evolution_derive_similarity: f32,
    /// Master switch for session-end Thymus auto-evaluation.
    #[serde(default = "default_thymus_autoeval_enabled")]
    pub thymus_autoeval_enabled: bool,
    /// Minimum session turn count below which auto-evaluation is skipped.
    #[serde(default = "default_thymus_autoeval_min_turns")]
    pub thymus_autoeval_min_turns: i32,
    /// Base URL of the SearXNG instance proxied by the /search/web route.
    /// Must include scheme and port. Default: http://127.0.0.1:8888 (local
    /// SearXNG). Point at your own SearXNG deployment in production.
    #[serde(default = "default_web_search_url")]
    pub web_search_url: String,
    /// Upstream request timeout in milliseconds for /search/web.
    #[serde(default = "default_web_search_timeout_ms")]
    pub web_search_timeout_ms: u64,
    /// Default result limit when the /search/web body omits `limit`.
    /// Hard-capped at 50 regardless of this value.
    #[serde(default = "default_web_search_limit")]
    pub web_search_default_limit: u32,
    /// Whether to run the auto-backup background task.
    pub backup_enabled: bool,
    /// Seconds between scheduled backups. Default: 6 hours.
    pub backup_interval_secs: u64,
    /// Directory for backup files. Relative paths resolve under `data_dir`.
    /// Default: `backups`.
    pub backup_dir: String,
    /// Maximum number of hourly backup files to retain. Older backups are
    /// pruned after each successful run. Default: 14 (kept for back-compat;
    /// the disaster-recovery plan calls for 8 hourly + 30 daily).
    pub backup_retention: usize,
    /// Maximum number of daily backup files to retain in `<backup_dir>/daily`.
    /// After each successful run the verified hourly backup is promoted to
    /// the daily directory if no backup for the current UTC date exists.
    /// Default: 30.
    #[serde(default = "default_backup_retention_daily")]
    pub backup_retention_daily: usize,
    /// Grace period (in hours) for an old key after `POST /keys/rotate`.
    /// During this window the old key continues to authenticate so clients
    /// can cut over without downtime. Default: 24.
    pub auth_key_rotation_grace_hours: i64,
    #[serde(default)]
    pub encryption: EncryptionConfig,
    #[serde(default)]
    pub eidolon: EidolonConfig,
    /// SECURITY: IP addresses of trusted reverse proxies. When the request
    /// originates from one of these IPs, X-Forwarded-For is honoured for
    /// rate-limit keying. When empty (default), XFF is never trusted and
    /// the TCP peer address is always used.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Source networks exempt from BOTH the pre-auth per-IP limit and the
    /// per-user limit. Entries are bare IPs ("192.0.2.1") or CIDRs
    /// ("192.0.2.0/24", "127.0.0.0/8", "::1"). Empty (default) means no
    /// exemption, so any public deployment behaves exactly as before.
    ///
    /// Intended for trusted local/mesh callers -- e.g. a VPN-only server where
    /// a local multi-agent fleet shares one source IP and would otherwise
    /// throttle itself against limits meant to stop internet brute-force.
    #[serde(default)]
    pub rate_limit_exempt_cidrs: Vec<String>,
    /// Pre-authentication per-IP rate limit (requests per minute). High enough
    /// for bursty MCP sessions while still blocking brute-force auth attempts.
    /// Override via `KLEOS_PREAUTH_IP_RPM`.
    #[serde(default = "default_preauth_ip_rpm")]
    pub preauth_ip_rpm: i64,
    /// Optional server reference table shown in living prompts.
    #[serde(default)]
    pub servers: Vec<ServerEntry>,
    /// Safety rules injected into living prompts as mandatory constraints.
    #[serde(default)]
    pub safety: SafetyConfig,
}

/// Default values for a standalone local Kleos server.
impl Default for Config {
    /// Builds a complete default configuration.
    fn default() -> Self {
        Self {
            db_path: "kleos.db".to_string(),
            host: "127.0.0.1".to_string(),
            port: 4200,
            api_key: None,
            embedding_dim: 1024,
            default_retention: 0.9,
            embedding_model: "BAAI/bge-m3".to_string(),
            embedding_max_seq: 512,
            embedding_model_dir: None,
            embedding_onnx_file: "model_quantized.onnx".to_string(),
            embedding_offline_only: false,
            embedding_chunk_max_chars: 1440,
            embedding_chunk_overlap: 160,
            embedding_chunk_max_chunks: 6,
            reranker_enabled: true,
            // SEC-recall-2.1: the reranker now sees a candidate pool sized to this window
            // (see hybrid_search_reranked), so a larger value lets the cross-encoder pull
            // more buried-but-relevant memories into the final top-k. Tunable via
            // RERANKER_TOP_K env.
            reranker_top_k: 24,
            reranker_model_dir: None,
            // Multilingual cross-encoder by default so retrieval is not English-only.
            reranker_model: "bge-reranker-v2-m3".to_string(),
            data_dir: dirs::data_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("kleos")
                .to_string_lossy()
                .into_owned(),
            lance_index_path: None,
            vector_dimensions: 1024,
            use_lance_index: true,
            use_chunk_vector_search: false,
            facts_channel_enabled: false,
            gui_enabled: false,
            gui_build_dir: None,
            gui_music_dir: None,
            pagerank_refresh_interval_secs: 300,
            pagerank_dirty_threshold: 100,
            pagerank_max_concurrent: 2,
            pagerank_enabled: true,
            community_detection_enabled: false,
            community_detection_interval_secs: default_community_detection_interval_secs(),
            consolidation_enabled: false,
            dreamer_enabled: default_dreamer_enabled(),
            dream_interval_secs: default_dream_interval_secs(),
            dream_idle_threshold_secs: default_dream_idle_threshold_secs(),
            auto_link_enabled: default_auto_link_enabled(),
            auto_link_batch: default_auto_link_batch(),
            skill_evolution_enabled: default_skill_evolution_enabled(),
            skill_evolution_interval_secs: default_skill_evolution_interval_secs(),
            skill_evolution_max_fixes_per_tick: default_skill_evolution_max_fixes_per_tick(),
            skill_evolution_max_captures_per_tick: default_skill_evolution_max_captures_per_tick(),
            skill_evolution_max_derives_per_tick: default_skill_evolution_max_derives_per_tick(),
            skill_evolution_failure_threshold: default_skill_evolution_failure_threshold(),
            skill_evolution_min_executions: default_skill_evolution_min_executions(),
            skill_evolution_refix_cooldown_secs: default_skill_evolution_refix_cooldown_secs(),
            skill_evolution_capture_tag: default_skill_evolution_capture_tag(),
            skill_evolution_derive_similarity: default_skill_evolution_derive_similarity(),
            thymus_autoeval_enabled: default_thymus_autoeval_enabled(),
            thymus_autoeval_min_turns: default_thymus_autoeval_min_turns(),
            web_search_url: default_web_search_url(),
            web_search_timeout_ms: default_web_search_timeout_ms(),
            web_search_default_limit: default_web_search_limit(),
            backup_enabled: false,
            backup_interval_secs: 6 * 3600,
            backup_dir: "backups".to_string(),
            backup_retention: 14,
            backup_retention_daily: default_backup_retention_daily(),
            auth_key_rotation_grace_hours: 24,
            encryption: EncryptionConfig::default(),
            eidolon: EidolonConfig::default(),
            trusted_proxies: Vec::new(),
            rate_limit_exempt_cidrs: Vec::new(),
            preauth_ip_rpm: default_preauth_ip_rpm(),
            servers: Vec::new(),
            safety: SafetyConfig::default(),
        }
    }
}

/// Constructors, loaders, and derived-path helpers for [`Config`].
impl Config {
    /// Load a `Config` from a TOML file. Missing fields fall back to
    /// their `Default` values via `#[serde(default)]` on most fields.
    ///
    /// Secret fields (`api_key`, `eidolon.api_key`) are
    /// `#[serde(skip)]` and must be supplied via environment variables.
    /// `gui_enabled` is also `#[serde(skip)]` and controlled by KLEOS_GUI_PASSWORD
    /// with ENGRAM_GUI_PASSWORD as a legacy fallback.
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
        toml::from_str(&text).map_err(|e| format!("parse {}: {}", path.display(), e))
    }

    /// Resolve the TOML config path using (in order):
    /// 1. `KLEOS_CONFIG_FILE` env var (legacy `ENGRAM_CONFIG_FILE` via `kleos_env`)
    /// 2. `./kleos.toml` in the current directory (legacy `./engram.toml`)
    /// 3. `$XDG_CONFIG_HOME/kleos/config.toml` (legacy `.../engram/config.toml`)
    ///
    /// The `kleos`-named locations are preferred; the legacy `engram` names are
    /// still checked so pre-rename installs keep working. Returns `None` if no
    /// config file is found.
    fn resolve_config_path() -> Option<std::path::PathBuf> {
        if let Ok(p) = crate::kleos_env("CONFIG_FILE") {
            let path = std::path::PathBuf::from(p);
            if path.exists() {
                return Some(path);
            } else {
                tracing::warn!(
                    "KLEOS_CONFIG_FILE set but file not found: {}",
                    path.display()
                );
            }
        }
        for name in ["kleos.toml", "engram.toml"] {
            let cwd_path = std::path::PathBuf::from(name);
            if cwd_path.exists() {
                return Some(cwd_path);
            }
        }
        if let Some(cfg_dir) = dirs::config_dir() {
            for app in ["kleos", "engram"] {
                let path = cfg_dir.join(app).join("config.toml");
                if path.exists() {
                    return Some(path);
                }
            }
        }
        None
    }

    /// Load config layered: defaults -> TOML file (if present) -> env var overrides.
    ///
    /// This is the preferred entry point for server startup. Env vars always
    /// win so operators can override file values without editing the file.
    pub fn load() -> Self {
        let base = match Self::resolve_config_path() {
            Some(path) => match Self::from_file(&path) {
                Ok(cfg) => {
                    tracing::info!("loaded config from {}", path.display());
                    cfg
                }
                Err(e) => {
                    tracing::warn!("failed to load config file: {}. Using defaults.", e);
                    Self::default()
                }
            },
            None => Self::default(),
        };
        Self::apply_env(base)
    }

    /// Builds the main configuration from defaults plus environment overrides.
    pub fn from_env() -> Self {
        Self::apply_env(Self::default())
    }

    /// Applies process environment overrides to an existing config value.
    fn apply_env(mut config: Self) -> Self {
        if let Ok(v) = crate::kleos_env("DB_PATH") {
            config.db_path = v;
        }
        if let Ok(v) = crate::kleos_env("HOST") {
            config.host = v;
        }
        if let Ok(v) = crate::kleos_env("PORT") {
            match v.parse() {
                Ok(p) => config.port = p,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_PORT={}, using default {}",
                    v,
                    config.port
                ),
            }
        }
        // Fast-path for tests and explicit overrides. In production, callers should
        // leave these unset and call cred::bootstrap::resolve_api_key() instead.
        if let Ok(v) = std::env::var("KLEOS_API_KEY") {
            config.api_key = Some(SecretString::new(v));
        } else if let Ok(v) = crate::kleos_env("API_KEY") {
            config.api_key = Some(SecretString::new(v));
        }
        // If neither is set, api_key stays None -- callers invoke the resolver.
        if let Ok(v) = crate::kleos_env("EMBEDDING_DIM") {
            match v.parse() {
                Ok(d) => config.embedding_dim = d,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_EMBEDDING_DIM={}, using default {}",
                    v,
                    config.embedding_dim
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("DEFAULT_RETENTION") {
            match v.parse() {
                Ok(r) => config.default_retention = r,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_DEFAULT_RETENTION={}, using default {}",
                    v,
                    config.default_retention
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("EMBEDDING_MODEL") {
            config.embedding_model = v;
        }
        if let Ok(v) = crate::kleos_env("EMBEDDING_MAX_SEQ") {
            match v.parse() {
                Ok(n) => config.embedding_max_seq = n,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_EMBEDDING_MAX_SEQ={}, using default {}",
                    v,
                    config.embedding_max_seq
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("EMBEDDING_MODEL_DIR") {
            config.embedding_model_dir = Some(v);
        }
        if let Ok(v) = crate::kleos_env("ONNX_MODEL_FILE") {
            config.embedding_onnx_file = v;
        }
        if let Ok(v) = crate::kleos_env("EMBEDDING_OFFLINE_ONLY") {
            config.embedding_offline_only = matches!(v.as_str(), "1" | "true" | "TRUE" | "yes");
        }
        if let Ok(v) = crate::kleos_env("EMBEDDING_CHUNK_MAX_CHARS") {
            match v.parse() {
                Ok(n) => config.embedding_chunk_max_chars = n,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_EMBEDDING_CHUNK_MAX_CHARS={}, using default {}",
                    v,
                    config.embedding_chunk_max_chars
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("EMBEDDING_CHUNK_OVERLAP") {
            match v.parse() {
                Ok(n) => config.embedding_chunk_overlap = n,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_EMBEDDING_CHUNK_OVERLAP={}, using default {}",
                    v,
                    config.embedding_chunk_overlap
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("EMBEDDING_CHUNK_MAX_CHUNKS") {
            match v.parse() {
                Ok(n) => config.embedding_chunk_max_chunks = n,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_EMBEDDING_CHUNK_MAX_CHUNKS={}, using default {}",
                    v,
                    config.embedding_chunk_max_chunks
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("RERANKER_ENABLED") {
            config.reranker_enabled = matches!(v.as_str(), "1" | "true" | "TRUE" | "yes");
        } else if let Ok(v) = crate::kleos_env("CROSS_ENCODER") {
            config.reranker_enabled = v != "0";
        }
        if let Ok(v) = crate::kleos_env("RERANKER_MODEL_DIR") {
            config.reranker_model_dir = Some(v);
        }
        // Local-ONNX reranker model selection. Distinct from KLEOS_RERANKER_MODEL,
        // which the HTTP reranker backend uses for a remote endpoint.
        if let Ok(v) = crate::kleos_env("RERANKER_MODEL_NAME") {
            if !v.trim().is_empty() {
                config.reranker_model = v;
            }
        }
        if let Ok(v) = crate::kleos_env("RERANKER_TOP_K") {
            match v.parse() {
                Ok(n) => config.reranker_top_k = n,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_RERANKER_TOP_K={}, using default {}",
                    v,
                    config.reranker_top_k
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("DATA_DIR") {
            config.data_dir = v;
        }
        if let Ok(v) = crate::kleos_env("LANCE_INDEX_PATH") {
            config.lance_index_path = Some(v);
        }
        if let Ok(v) = crate::kleos_env("VECTOR_DIMENSIONS") {
            match v.parse() {
                Ok(n) => config.vector_dimensions = n,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_VECTOR_DIMENSIONS={}, using default {}",
                    v,
                    config.vector_dimensions
                ),
            }
        }
        // Vector safety: the embedder output dimension and the vector-store schema
        // dimension must match. A mismatch otherwise surfaces only later as a runtime
        // InvalidInput that silently drops vectors from the index. Warn loudly at load so
        // the misconfiguration is visible immediately rather than as missing recall.
        if config.embedding_dim != config.vector_dimensions {
            tracing::warn!(
                "embedding_dim ({}) != vector_dimensions ({}); embeddings will fail to \
                 index and semantic recall will silently degrade. Set EMBEDDING_DIM and \
                 VECTOR_DIMENSIONS to the same value.",
                config.embedding_dim,
                config.vector_dimensions
            );
        }
        if let Ok(v) = crate::kleos_env("USE_LANCE_INDEX") {
            config.use_lance_index = v != "0" && !v.eq_ignore_ascii_case("false");
        }
        if let Ok(v) = std::env::var("KLEOS_USE_CHUNK_VECTOR_SEARCH") {
            config.use_chunk_vector_search = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Ok(v) = std::env::var("KLEOS_FACTS_CHANNEL_ENABLED") {
            config.facts_channel_enabled = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Ok(v) = crate::kleos_env("GUI_PASSWORD") {
            config.gui_enabled = !v.is_empty();
        }
        if let Ok(v) = crate::kleos_env("GUI_BUILD_DIR") {
            config.gui_build_dir = Some(v);
        }
        if let Ok(v) = crate::kleos_env("GUI_MUSIC_DIR") {
            config.gui_music_dir = Some(v);
        }
        if let Ok(v) = crate::kleos_env("PAGERANK_REFRESH_INTERVAL") {
            match v.parse() {
                Ok(n) => config.pagerank_refresh_interval_secs = n,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_PAGERANK_REFRESH_INTERVAL={}, using default {}",
                    v,
                    config.pagerank_refresh_interval_secs
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("PAGERANK_DIRTY_THRESHOLD") {
            match v.parse() {
                Ok(n) => config.pagerank_dirty_threshold = n,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_PAGERANK_DIRTY_THRESHOLD={}, using default {}",
                    v,
                    config.pagerank_dirty_threshold
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("PAGERANK_MAX_CONCURRENT") {
            match v.parse() {
                Ok(n) => config.pagerank_max_concurrent = n,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_PAGERANK_MAX_CONCURRENT={}, using default {}",
                    v,
                    config.pagerank_max_concurrent
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("PAGERANK_ENABLED") {
            config.pagerank_enabled = v != "0" && !v.eq_ignore_ascii_case("false");
        }
        if let Ok(v) = crate::kleos_env("COMMUNITY_DETECTION_ENABLED") {
            config.community_detection_enabled = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Ok(v) = crate::kleos_env("COMMUNITY_DETECTION_INTERVAL_SECS") {
            match v.parse() {
                Ok(n) => config.community_detection_interval_secs = n,
                Err(_) => tracing::warn!(
                    "invalid env community detection interval {}, using default {}",
                    v,
                    config.community_detection_interval_secs
                ),
            }
        }
        if let Ok(v) = std::env::var("KLEOS_CONSOLIDATION_ENABLED") {
            config.consolidation_enabled = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Ok(v) = crate::kleos_env("DREAMER_ENABLED") {
            config.dreamer_enabled = v != "0" && !v.eq_ignore_ascii_case("false");
        }
        if let Ok(v) = crate::kleos_env("AUTO_LINK_ENABLED") {
            config.auto_link_enabled = v != "0" && !v.eq_ignore_ascii_case("false");
        }
        if let Ok(v) = crate::kleos_env("AUTO_LINK_BATCH") {
            match v.parse() {
                Ok(n) => config.auto_link_batch = n,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_AUTO_LINK_BATCH={}, using default {}",
                    v,
                    config.auto_link_batch
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("DREAM_INTERVAL_SECS") {
            match v.parse() {
                Ok(n) => config.dream_interval_secs = n,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_DREAM_INTERVAL_SECS={}, using default {}",
                    v,
                    config.dream_interval_secs
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("DREAM_IDLE_THRESHOLD_SECS") {
            match v.parse() {
                Ok(n) => config.dream_idle_threshold_secs = n,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_DREAM_IDLE_THRESHOLD_SECS={}, using default {}",
                    v,
                    config.dream_idle_threshold_secs
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("SKILL_EVOLUTION_ENABLED") {
            config.skill_evolution_enabled = v != "0" && !v.eq_ignore_ascii_case("false");
        }
        if let Ok(v) = crate::kleos_env("SKILL_EVOLUTION_INTERVAL_SECS") {
            match v.parse() {
                Ok(n) => config.skill_evolution_interval_secs = n,
                Err(_) => tracing::warn!(
                    "invalid env KLEOS_SKILL_EVOLUTION_INTERVAL_SECS={}, using default {}",
                    v,
                    config.skill_evolution_interval_secs
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("SKILL_EVOLUTION_MAX_FIXES_PER_TICK") {
            match v.parse() {
                Ok(n) => config.skill_evolution_max_fixes_per_tick = n,
                Err(_) => tracing::warn!(
                    "invalid env KLEOS_SKILL_EVOLUTION_MAX_FIXES_PER_TICK={}, using default {}",
                    v,
                    config.skill_evolution_max_fixes_per_tick
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("SKILL_EVOLUTION_MAX_CAPTURES_PER_TICK") {
            match v.parse() {
                Ok(n) => config.skill_evolution_max_captures_per_tick = n,
                Err(_) => tracing::warn!(
                    "invalid env KLEOS_SKILL_EVOLUTION_MAX_CAPTURES_PER_TICK={}, using default {}",
                    v,
                    config.skill_evolution_max_captures_per_tick
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("SKILL_EVOLUTION_MAX_DERIVES_PER_TICK") {
            match v.parse() {
                Ok(n) => config.skill_evolution_max_derives_per_tick = n,
                Err(_) => tracing::warn!(
                    "invalid env KLEOS_SKILL_EVOLUTION_MAX_DERIVES_PER_TICK={}, using default {}",
                    v,
                    config.skill_evolution_max_derives_per_tick
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("SKILL_EVOLUTION_FAILURE_THRESHOLD") {
            match v.parse() {
                Ok(n) => config.skill_evolution_failure_threshold = n,
                Err(_) => tracing::warn!(
                    "invalid env KLEOS_SKILL_EVOLUTION_FAILURE_THRESHOLD={}, using default {}",
                    v,
                    config.skill_evolution_failure_threshold
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("SKILL_EVOLUTION_MIN_EXECUTIONS") {
            match v.parse() {
                Ok(n) => config.skill_evolution_min_executions = n,
                Err(_) => tracing::warn!(
                    "invalid env KLEOS_SKILL_EVOLUTION_MIN_EXECUTIONS={}, using default {}",
                    v,
                    config.skill_evolution_min_executions
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("SKILL_EVOLUTION_REFIX_COOLDOWN_SECS") {
            match v.parse() {
                Ok(n) => config.skill_evolution_refix_cooldown_secs = n,
                Err(_) => tracing::warn!(
                    "invalid env KLEOS_SKILL_EVOLUTION_REFIX_COOLDOWN_SECS={}, using default {}",
                    v,
                    config.skill_evolution_refix_cooldown_secs
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("SKILL_EVOLUTION_CAPTURE_TAG") {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                config.skill_evolution_capture_tag = trimmed.to_string();
            }
        }
        if let Ok(v) = crate::kleos_env("SKILL_EVOLUTION_DERIVE_SIMILARITY") {
            match v.parse() {
                Ok(n) => config.skill_evolution_derive_similarity = n,
                Err(_) => tracing::warn!(
                    "invalid env KLEOS_SKILL_EVOLUTION_DERIVE_SIMILARITY={}, using default {}",
                    v,
                    config.skill_evolution_derive_similarity
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("THYMUS_AUTOEVAL_ENABLED") {
            config.thymus_autoeval_enabled = v != "0" && !v.eq_ignore_ascii_case("false");
        }
        if let Ok(v) = crate::kleos_env("THYMUS_AUTOEVAL_MIN_TURNS") {
            if let Ok(n) = v.parse() {
                config.thymus_autoeval_min_turns = n;
            }
        }
        if let Ok(v) = crate::kleos_env("WEB_SEARCH_URL") {
            if !v.trim().is_empty() {
                config.web_search_url = v;
            }
        }
        if let Ok(v) = crate::kleos_env("WEB_SEARCH_TIMEOUT_MS") {
            match v.parse() {
                Ok(n) => config.web_search_timeout_ms = n,
                Err(_) => tracing::warn!(
                    "invalid env KLEOS_WEB_SEARCH_TIMEOUT_MS={}, using default {}",
                    v,
                    config.web_search_timeout_ms
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("WEB_SEARCH_DEFAULT_LIMIT") {
            match v.parse() {
                Ok(n) => config.web_search_default_limit = n,
                Err(_) => tracing::warn!(
                    "invalid env KLEOS_WEB_SEARCH_DEFAULT_LIMIT={}, using default {}",
                    v,
                    config.web_search_default_limit
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("BACKUP_ENABLED") {
            config.backup_enabled = matches!(v.as_str(), "1" | "true" | "TRUE" | "yes");
        }
        if let Ok(v) = crate::kleos_env("BACKUP_INTERVAL_SECS") {
            match v.parse() {
                Ok(n) => config.backup_interval_secs = n,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_BACKUP_INTERVAL_SECS={}, using default {}",
                    v,
                    config.backup_interval_secs
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("BACKUP_DIR") {
            config.backup_dir = v;
        }
        if let Ok(v) = crate::kleos_env("BACKUP_RETENTION") {
            match v.parse() {
                Ok(n) => config.backup_retention = n,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_BACKUP_RETENTION={}, using default {}",
                    v,
                    config.backup_retention
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("BACKUP_RETENTION_DAILY") {
            match v.parse() {
                Ok(n) => config.backup_retention_daily = n,
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_BACKUP_RETENTION_DAILY={}, using default {}",
                    v,
                    config.backup_retention_daily
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("AUTH_KEY_ROTATION_GRACE_HOURS") {
            match v.parse() {
                Ok(n) if n > 0 => config.auth_key_rotation_grace_hours = n,
                Ok(_) => tracing::warn!(
                    "ENGRAM_AUTH_KEY_ROTATION_GRACE_HOURS must be > 0, using default {}",
                    config.auth_key_rotation_grace_hours
                ),
                Err(_) => tracing::warn!(
                    "invalid env ENGRAM_AUTH_KEY_ROTATION_GRACE_HOURS={}, using default {}",
                    v,
                    config.auth_key_rotation_grace_hours
                ),
            }
        }
        if let Ok(v) = crate::kleos_env("ENCRYPTION_MODE") {
            config.encryption.mode = match v.to_ascii_lowercase().as_str() {
                "none" => EncryptionMode::None,
                "keyfile" => EncryptionMode::Keyfile,
                "env" => EncryptionMode::Env,
                "yubikey" => EncryptionMode::Yubikey,
                "custody" => EncryptionMode::Custody,
                other => {
                    tracing::warn!("unknown ENGRAM_ENCRYPTION_MODE={}, using none", other);
                    EncryptionMode::None
                }
            };
        }
        // SECURITY: comma-separated list of trusted reverse proxy IPs.
        // Only when the TCP peer matches one of these will X-Forwarded-For
        // be honoured for rate-limit keying.
        if let Ok(v) = crate::kleos_env("TRUSTED_PROXIES") {
            config.trusted_proxies = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !config.trusted_proxies.is_empty() {
                tracing::info!("trusted proxies configured: {:?}", config.trusted_proxies);
            }
        }
        // Source networks (bare IPs or CIDRs) exempt from rate limiting. Lets a
        // trusted local/mesh agent fleet avoid throttling itself.
        if let Ok(v) = crate::kleos_env("RATE_LIMIT_EXEMPT_CIDRS") {
            config.rate_limit_exempt_cidrs = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !config.rate_limit_exempt_cidrs.is_empty() {
                tracing::info!(
                    "rate-limit exempt CIDRs configured: {:?}",
                    config.rate_limit_exempt_cidrs
                );
            }
        }
        if let Ok(v) = crate::kleos_env("PREAUTH_IP_RPM") {
            match v.trim().parse::<i64>() {
                Ok(n) if n > 0 => config.preauth_ip_rpm = n,
                _ => tracing::warn!(
                    "ignoring invalid KLEOS_PREAUTH_IP_RPM={:?} (must be a positive integer)",
                    v
                ),
            }
        }
        config.eidolon = config.eidolon.apply_env();
        config
    }

    /// Returns true when `ip` (a resolved client-IP string) falls within any
    /// configured `rate_limit_exempt_cidrs` entry.
    ///
    /// Entries may be bare IPs ("192.0.2.1") or CIDRs ("192.0.2.0/24").
    /// Unparseable entries and unparseable inputs never match, so a
    /// misconfigured CIDR fails closed (no exemption granted) rather than
    /// silently exempting everything.
    pub fn is_rate_limit_exempt(&self, ip: &str) -> bool {
        if self.rate_limit_exempt_cidrs.is_empty() {
            return false;
        }
        let addr: std::net::IpAddr = match ip.parse() {
            Ok(a) => a,
            Err(_) => return false,
        };
        self.rate_limit_exempt_cidrs.iter().any(|entry| {
            if let Ok(net) = entry.parse::<ipnet::IpNet>() {
                net.contains(&addr)
            } else if let Ok(single) = entry.parse::<std::net::IpAddr>() {
                single == addr
            } else {
                false
            }
        })
    }

    /// Returns the resolved model directory for a given model name.
    ///
    /// For the reranker, checks `reranker_model_dir` first.
    /// For embeddings, checks `embedding_model_dir` first.
    /// Falls back to `<data_dir>/engram/models/<model_short_name>`.
    pub fn model_dir(&self, model_short_name: &str) -> std::path::PathBuf {
        // Reranker gets its own config path
        if model_short_name.contains("reranker") || model_short_name.contains("granite") {
            if let Some(ref dir) = self.reranker_model_dir {
                return std::path::PathBuf::from(dir);
            }
        }

        if let Some(ref dir) = self.embedding_model_dir {
            // If the embedding_model_dir points to a specific model (has model
            // name in it), use its parent as the base and append the short name.
            // This lets /opt/engram/data/models/bge-m3 resolve
            // /opt/engram/data/models/granite-reranker for other models.
            let path = std::path::PathBuf::from(dir);
            if path.file_name().is_some() && model_short_name != "bge-m3" {
                if let Some(parent) = path.parent() {
                    return parent.join(model_short_name);
                }
            }
            return path;
        }

        dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("engram")
            .join("models")
            .join(model_short_name)
    }
}

#[cfg(test)]
/// Tests for configuration defaults, file loading, and env precedence.
mod tests {
    use super::*;

    /// Empty exempt list (the default) never exempts anyone -- preserving the
    /// pre-existing behaviour for public deployments.
    #[test]
    fn rate_limit_exempt_empty_never_matches() {
        let cfg = Config::default();
        assert!(cfg.rate_limit_exempt_cidrs.is_empty());
        assert!(!cfg.is_rate_limit_exempt("192.0.2.4"));
        assert!(!cfg.is_rate_limit_exempt("127.0.0.1"));
    }

    /// CIDR entries match addresses inside the range and reject those outside.
    #[test]
    fn rate_limit_exempt_cidr_and_bare_ip() {
        let cfg = Config {
            rate_limit_exempt_cidrs: vec![
                "127.0.0.0/8".to_string(),
                "192.0.2.0/24".to_string(),
                "::1".to_string(), // bare IPv6 loopback (no prefix)
            ],
            ..Config::default()
        };
        // Loopback + mesh members are exempt.
        assert!(cfg.is_rate_limit_exempt("127.0.0.1"));
        assert!(cfg.is_rate_limit_exempt("192.0.2.4"));
        assert!(cfg.is_rate_limit_exempt("192.0.2.6"));
        assert!(cfg.is_rate_limit_exempt("::1"));
        // Outside the configured ranges -- not exempt.
        assert!(!cfg.is_rate_limit_exempt("198.51.100.1"));
        assert!(!cfg.is_rate_limit_exempt("203.0.113.9"));
    }

    /// Garbage CIDR/IP inputs fail closed (never exempt) instead of panicking
    /// or matching everything.
    #[test]
    fn rate_limit_exempt_invalid_fails_closed() {
        let mut cfg = Config {
            rate_limit_exempt_cidrs: vec!["not-an-ip".to_string(), "10.0.0.0/99".to_string()],
            ..Config::default()
        };
        assert!(!cfg.is_rate_limit_exempt("10.0.0.1"));
        // A non-parseable client IP is never exempt regardless of config.
        cfg.rate_limit_exempt_cidrs = vec!["0.0.0.0/0".to_string()];
        assert!(!cfg.is_rate_limit_exempt("garbage"));
    }

    /// Runs a test body with credential-authority env vars isolated.
    fn with_credential_authority_env(test: impl FnOnce()) {
        let old_phylaxd = std::env::var("PHYLAXD_URL").ok();
        let old_credd = std::env::var("CREDD_URL").ok();
        std::env::remove_var("PHYLAXD_URL");
        std::env::remove_var("CREDD_URL");

        test();

        match old_phylaxd {
            Some(value) => std::env::set_var("PHYLAXD_URL", value),
            None => std::env::remove_var("PHYLAXD_URL"),
        }
        match old_credd {
            Some(value) => std::env::set_var("CREDD_URL", value),
            None => std::env::remove_var("CREDD_URL"),
        }
    }

    #[test]
    /// Verifies nested Eidolon defaults are populated.
    fn eidolon_config_defaults_are_populated() {
        let c = EidolonConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.credd.url, DEFAULT_CREDENTIAL_AUTHORITY_URL);
        assert_eq!(c.credd.agent_key_env, "CREDD_AGENT_KEY");
        assert!(!c.credd.allow_raw);
        assert!(c
            .gate
            .blocked_patterns
            .iter()
            .any(|p| p.contains("rm -rf /")));
        assert_eq!(c.gate.approval_timeout_secs, 300);
        assert_eq!(c.growth.reflection_interval_secs, 3600);
        assert_eq!(c.growth.observation_limit, 100);
        assert_eq!(c.sessions.max_concurrent, 64);
        assert_eq!(c.sessions.buffer_size, 4096);
        assert!(c.sessions.scrub_secrets);
        // Cold-cache scrub policy defaults to fail-open so message writes do
        // not hard-depend on credd; a warm cache still scrubs via stale fallback.
        assert!(c.sessions.scrub_fail_open);
        assert_eq!(c.prompt.default_max_tokens, 4000);
        assert_eq!(c.prompt.max_tokens_cap, 128000);
        assert!(c.prompt.default_include_memories);
    }

    /// Verifies Config exposes the nested Eidolon prompt defaults.
    #[test]
    /// Verifies the top-level config exposes Eidolon prompt settings.
    fn config_exposes_eidolon_field() {
        let c = Config::default();
        assert_eq!(c.eidolon.prompt.default_max_tokens, 4000);
    }

    /// Verifies partial TOML files merge with defaults.
    #[test]
    #[serial_test::serial(credential_authority_env)]
    /// Verifies PHYLAXD_URL wins over legacy CREDD_URL.
    fn credential_authority_prefers_phylaxd_url() {
        with_credential_authority_env(|| {
            std::env::set_var("PHYLAXD_URL", "http://127.0.0.1:3100");
            std::env::set_var("CREDD_URL", "http://127.0.0.1:4400");

            let c = EidolonConfig::from_env();

            assert_eq!(c.credd.url, "http://127.0.0.1:3100");
        });
    }

    #[test]
    #[serial_test::serial(credential_authority_env)]
    /// Verifies CREDD_URL remains a transition fallback.
    fn credential_authority_uses_credd_url_fallback() {
        with_credential_authority_env(|| {
            std::env::set_var("CREDD_URL", "http://127.0.0.1:4401");

            let c = EidolonConfig::from_env();

            assert_eq!(c.credd.url, "http://127.0.0.1:4401");
        });
    }

    #[test]
    #[serial_test::serial(credential_authority_env)]
    /// Verifies env layering preserves a file-provided authority URL.
    fn credential_authority_preserves_existing_url_without_env() {
        with_credential_authority_env(|| {
            let c = EidolonConfig {
                credd: CreddConfig {
                    url: "http://configured.example:4400".to_string(),
                    ..CreddConfig::default()
                },
                ..EidolonConfig::default()
            }
            .apply_env();

            assert_eq!(c.credd.url, "http://configured.example:4400");
        });
    }

    #[test]
    /// Verifies partial TOML files inherit defaults.
    fn from_file_parses_partial_toml_and_uses_defaults() {
        let dir = std::env::temp_dir().join(format!("engram-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("engram.toml");
        std::fs::write(
            &path,
            r#"
host = "0.0.0.0"
port = 8080
pagerank_enabled = false

[eidolon]
enabled = true

[eidolon.prompt]
default_max_tokens = 8000
"#,
        )
        .unwrap();

        let c = Config::from_file(&path).expect("parse toml");
        assert_eq!(c.host, "0.0.0.0");
        assert_eq!(c.port, 8080);
        assert!(!c.pagerank_enabled);
        // unspecified fields fall back to defaults
        assert_eq!(c.db_path, "kleos.db");
        assert_eq!(c.embedding_dim, 1024);
        assert!(c.eidolon.enabled);
        assert_eq!(c.eidolon.prompt.default_max_tokens, 8000);
        // nested default still applied for unspecified sub-field
        assert_eq!(c.eidolon.prompt.max_tokens_cap, 128000);

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    /// Verifies malformed TOML produces a parse error.
    #[test]
    /// Verifies malformed TOML returns a parse error.
    fn from_file_rejects_malformed_toml() {
        let dir = std::env::temp_dir().join(format!("engram-cfg-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("engram.toml");
        std::fs::write(&path, "port = \"not-a-number\"\n").unwrap();
        let err = Config::from_file(&path).unwrap_err();
        assert!(err.contains("parse"));
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    /// gui_music_dir must default to None so the music player stays hidden
    /// unless the operator explicitly sets KLEOS_GUI_MUSIC_DIR.
    #[test]
    fn gui_music_dir_defaults_none() {
        let c = Config::default();
        assert!(c.gui_music_dir.is_none(), "music dir must default to None");
    }
}
