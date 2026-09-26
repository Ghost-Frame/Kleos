//! Read-only client diagnostics for `kleos-cli doctor`.
//!
//! Every check inspects local state or performs a read-only server request and
//! returns a named result with an optional human-applied fix. Nothing here
//! writes files, mutates the server, or prints credential values.

use kleos_client::Client;
use serde::Serialize;
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Timeout applied to each server request made by doctor.
const SERVER_TIMEOUT: Duration = Duration::from_secs(5);

/// Outcome of one diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The checked property holds.
    Ok,
    /// The property is degraded or suspicious but not broken.
    Warn,
    /// The property is broken and blocks normal use.
    Fail,
    /// The check could not run because a prerequisite is absent.
    Skip,
}

/// Presentation helpers for check statuses.
impl Status {
    /// Returns the fixed-width label used by the text renderer.
    fn label(self) -> &'static str {
        match self {
            Status::Ok => " OK ",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
            Status::Skip => "SKIP",
        }
    }
}

/// One diagnostic result with an optional human-applied fix.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// Stable machine-readable check identifier.
    pub id: &'static str,
    /// Result of the check.
    pub status: Status,
    /// Human-readable observation backing the status.
    pub detail: String,
    /// Suggested manual remediation; never applied automatically.
    pub fix: Option<String>,
}

/// Constructors for diagnostic results.
impl Check {
    /// Builds a check with no suggested fix.
    fn new(id: &'static str, status: Status, detail: impl Into<String>) -> Self {
        Self {
            id,
            status,
            detail: detail.into(),
            fix: None,
        }
    }

    /// Attaches a suggested manual fix to this check.
    fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

/// Ordered collection of checks produced by one doctor run.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    /// Checks in execution order.
    pub checks: Vec<Check>,
}

/// Exit-code and rendering behavior for a completed doctor run.
impl Report {
    /// Returns 1 if any check failed, otherwise 0.
    pub fn exit_code(&self) -> i32 {
        if self.checks.iter().any(|c| c.status == Status::Fail) {
            1
        } else {
            0
        }
    }

    /// Renders the report as one line per check with indented fixes.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        for check in &self.checks {
            out.push_str(&format!(
                "[{}] {}: {}\n",
                check.status.label(),
                check.id,
                check.detail
            ));
            if let Some(fix) = &check.fix {
                out.push_str(&format!("       fix: {}\n", fix));
            }
        }
        out
    }
}

/// Inputs gathered by the caller so local checks stay deterministic in tests.
pub struct LocalInputs {
    /// Version of the running CLI.
    pub version: &'static str,
    /// Path of the running executable, if resolvable.
    pub current_exe: Option<PathBuf>,
    /// Raw `PATH` value.
    pub path_env: Option<std::ffi::OsString>,
    /// Effective server URL.
    pub server_url: String,
    /// Project the repository at the target directory resolves to.
    pub repo_project: Option<String>,
    /// Non-empty `SESSION_HANDOFF_PROJECT` override, if set.
    pub env_project: Option<String>,
    /// Home directory used to locate agent client configuration.
    pub home: Option<PathBuf>,
    /// Directory doctor diagnoses, used for project-scope MCP config lookup.
    pub dir: PathBuf,
}

/// Runs every local check in a fixed order.
pub fn local_checks(inputs: &LocalInputs) -> Vec<Check> {
    vec![
        check_binary(
            inputs.version,
            inputs.current_exe.as_deref(),
            inputs.path_env.as_deref(),
        ),
        check_url(&inputs.server_url),
        check_project(
            inputs.repo_project.as_deref(),
            inputs.env_project.as_deref(),
        ),
        check_mcp_registration(inputs.home.as_deref(), &inputs.dir),
        check_hooks(inputs.home.as_deref()),
    ]
}

/// Reports the CLI version and warns when `PATH` resolves `kleos-cli` to a
/// different file than the running executable.
fn check_binary(
    version: &str,
    current_exe: Option<&Path>,
    path_env: Option<&std::ffi::OsStr>,
) -> Check {
    let Some(exe) = current_exe else {
        return Check::new(
            "binary",
            Status::Warn,
            format!("v{version}, executable path unknown"),
        );
    };
    let exe_canon = std::fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
    let on_path = path_env.and_then(|p| {
        std::env::split_paths(p)
            .map(|dir| dir.join(binary_name()))
            .find(|candidate| candidate.is_file())
    });
    match on_path {
        None => Check::new(
            "binary",
            Status::Warn,
            format!("v{version} at {}; kleos-cli is not on PATH", exe.display()),
        )
        .with_fix("add the install directory (usually ~/.local/bin) to PATH"),
        Some(found) => {
            let found_canon = std::fs::canonicalize(&found).unwrap_or_else(|_| found.clone());
            if found_canon == exe_canon {
                Check::new(
                    "binary",
                    Status::Ok,
                    format!("v{version} at {}", exe.display()),
                )
            } else {
                Check::new(
                    "binary",
                    Status::Warn,
                    format!(
                        "running v{version} at {}, but PATH resolves kleos-cli to {}",
                        exe.display(),
                        found.display()
                    ),
                )
                .with_fix("remove or update the stale binary earlier on PATH")
            }
        }
    }
}

/// Returns the platform executable file name for the CLI.
fn binary_name() -> &'static str {
    if cfg!(windows) {
        "kleos-cli.exe"
    } else {
        "kleos-cli"
    }
}

/// Returns true for private-network IPv4 addresses: RFC 1918 ranges and the
/// RFC 6598 shared address space used by overlay VPNs.
fn is_private_net_ip(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    ip.is_private() || (a == 100 && (64..=127).contains(&b))
}

/// Classifies one server URL: invalid is a failure, plaintext HTTP to a host
/// that is neither loopback nor on a private network is a warning.
fn classify_url(url: &str) -> (Status, String) {
    let parsed = match reqwest::Url::parse(url) {
        Ok(parsed) => parsed,
        Err(e) => return (Status::Fail, format!("{url} is not a valid URL: {e}")),
    };
    let host = parsed.host_str().unwrap_or_default();
    if parsed.scheme() == "https" {
        return (Status::Ok, format!("{url} (TLS)"));
    }
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    let trusted = host.eq_ignore_ascii_case("localhost")
        || match trimmed.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => v4.is_loopback() || is_private_net_ip(v4),
            Ok(IpAddr::V6(v6)) => v6.is_loopback(),
            Err(_) => false,
        };
    if trusted {
        (Status::Ok, format!("{url} (loopback or private network)"))
    } else {
        (
            Status::Warn,
            format!("{url} uses plaintext HTTP to a public host"),
        )
    }
}

/// Validates the server URL, which may be a comma-separated failover list,
/// and reports the most severe classification across its entries.
fn check_url(urls: &str) -> Check {
    let mut status = Status::Skip;
    let mut parts = Vec::new();
    for url in urls.split(',').map(str::trim).filter(|u| !u.is_empty()) {
        let (s, detail) = classify_url(url);
        status = worse(status, s);
        parts.push(detail);
    }
    if parts.is_empty() {
        return Check::new("url", Status::Fail, "server URL is empty")
            .with_fix("set KLEOS_URL or --server to http(s)://host:port");
    }
    let check = Check::new("url", status, parts.join("; "));
    match status {
        Status::Fail => {
            check.with_fix("set KLEOS_URL or --server to http(s)://host:port[,fallback]")
        }
        Status::Warn => check.with_fix("use https or a private VPN address"),
        _ => check,
    }
}

/// Explains which project this directory resolves to and why.
fn check_project(repo_project: Option<&str>, env_project: Option<&str>) -> Check {
    match (repo_project, env_project) {
        (None, _) => Check::new(
            "project",
            Status::Warn,
            "not inside a Git worktree; no project is inferred",
        )
        .with_fix("run from the repository or pass --project explicitly"),
        (Some(repo), Some(env)) if env != repo => Check::new(
            "project",
            Status::Warn,
            format!("{env} (from SESSION_HANDOFF_PROJECT, overriding repository identity {repo})"),
        )
        .with_fix("unset SESSION_HANDOFF_PROJECT if the override is stale"),
        (Some(_), Some(env)) => Check::new(
            "project",
            Status::Ok,
            format!("{env} (SESSION_HANDOFF_PROJECT matches repository)"),
        ),
        (Some(repo), None) => Check::new(
            "project",
            Status::Ok,
            format!("{repo} (from Git origin remote or repository root)"),
        ),
    }
}

/// Returns true when any `mcpServers` object in the JSON tree has a key that
/// mentions kleos.
fn json_has_kleos_mcp(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, child)| {
            (key == "mcpServers"
                && child.as_object().is_some_and(|servers| {
                    servers.keys().any(|k| k.to_lowercase().contains("kleos"))
                }))
                || json_has_kleos_mcp(child)
        }),
        Value::Array(items) => items.iter().any(json_has_kleos_mcp),
        _ => false,
    }
}

/// Result of inspecting one agent client's configuration file.
enum ClientConfig {
    /// File does not exist.
    Absent,
    /// File exists but could not be parsed.
    Unreadable(String),
    /// File parsed; the flag records whether a kleos MCP server is registered.
    Parsed(bool),
}

/// Inspects one Claude Code JSON config file for a kleos MCP server.
fn claude_json_mcp(path: &Path) -> ClientConfig {
    match std::fs::read_to_string(path) {
        Err(_) => ClientConfig::Absent,
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(v) => ClientConfig::Parsed(json_has_kleos_mcp(&v)),
            Err(e) => ClientConfig::Unreadable(format!("{}: {e}", path.display())),
        },
    }
}

/// Inspects Claude Code's user config (`~/.claude.json`) and every
/// project-scope `.mcp.json` from `dir` up to the filesystem root. Any
/// registration wins; otherwise an unreadable file outranks a clean miss.
fn claude_mcp(home: &Path, dir: &Path) -> ClientConfig {
    let mut candidates = vec![home.join(".claude.json")];
    candidates.extend(dir.ancestors().map(|d| d.join(".mcp.json")));
    let mut result = ClientConfig::Absent;
    for path in candidates {
        match claude_json_mcp(&path) {
            ClientConfig::Parsed(true) => return ClientConfig::Parsed(true),
            ClientConfig::Absent => {}
            unreadable @ ClientConfig::Unreadable(_) => result = unreadable,
            ClientConfig::Parsed(false) => {
                if matches!(result, ClientConfig::Absent) {
                    result = ClientConfig::Parsed(false);
                }
            }
        }
    }
    result
}

/// Inspects Codex's `~/.codex/config.toml` for a kleos MCP server.
fn codex_mcp(home: &Path) -> ClientConfig {
    let path = home.join(".codex").join("config.toml");
    match std::fs::read_to_string(&path) {
        Err(_) => ClientConfig::Absent,
        Ok(text) => match text.parse::<toml::Table>() {
            Ok(table) => ClientConfig::Parsed(
                table
                    .get("mcp_servers")
                    .and_then(|v| v.as_table())
                    .is_some_and(|servers| {
                        servers.keys().any(|k| k.to_lowercase().contains("kleos"))
                    }),
            ),
            Err(e) => ClientConfig::Unreadable(e.to_string()),
        },
    }
}

/// Reports whether Claude Code and Codex register a kleos MCP server. Only
/// registration presence is reported, never commands, headers, or tokens.
fn check_mcp_registration(home: Option<&Path>, dir: &Path) -> Check {
    let Some(home) = home else {
        return Check::new("mcp_registration", Status::Skip, "home directory unknown");
    };
    let clients = [
        ("claude-code", claude_mcp(home, dir)),
        ("codex", codex_mcp(home)),
    ];
    let mut parts = Vec::new();
    let mut status = Status::Skip;
    for (name, config) in &clients {
        let (part, s) = match config {
            ClientConfig::Absent => (format!("{name}: no config"), Status::Skip),
            ClientConfig::Unreadable(e) => {
                (format!("{name}: config unreadable ({e})"), Status::Warn)
            }
            ClientConfig::Parsed(true) => (format!("{name}: registered"), Status::Ok),
            ClientConfig::Parsed(false) => (format!("{name}: not registered"), Status::Warn),
        };
        parts.push(part);
        status = worse(status, s);
    }
    let check = Check::new("mcp_registration", status, parts.join(", "));
    if status == Status::Warn {
        check.with_fix(
            "register the kleos MCP server in the listed client (see the operations manual)",
        )
    } else {
        check
    }
}

/// Combines two statuses, keeping the more severe one. Skip is least severe.
fn worse(a: Status, b: Status) -> Status {
    /// Severity rank used for comparison.
    fn rank(s: Status) -> u8 {
        match s {
            Status::Skip => 0,
            Status::Ok => 1,
            Status::Warn => 2,
            Status::Fail => 3,
        }
    }
    if rank(b) > rank(a) {
        b
    } else {
        a
    }
}

/// Collects every hook `command` string in a Claude Code settings tree.
fn hook_commands(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "command" {
                    if let Some(cmd) = child.as_str() {
                        out.push(cmd.to_string());
                    }
                } else {
                    hook_commands(child, out);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| hook_commands(item, out)),
        _ => {}
    }
}

/// Resolves the executable token of a hook command to a path when it is
/// absolute or home-relative; bare names are left to the shell and ignored.
fn hook_executable(command: &str, home: &Path) -> Option<PathBuf> {
    let token = command.split_whitespace().find(|t| !t.contains('='))?;
    let token = token.trim_matches(|c| c == '"' || c == '\'');
    let home_str = home.to_string_lossy();
    let expanded = if let Some(rest) = token.strip_prefix("~/") {
        home.join(rest)
    } else if let Some(rest) = token
        .strip_prefix("$HOME/")
        .or_else(|| token.strip_prefix("${HOME}/"))
    {
        home.join(rest)
    } else {
        PathBuf::from(token.replace("$HOME", &home_str))
    };
    expanded.is_absolute().then_some(expanded)
}

/// Lists Claude Code hooks that mention kleos and warns when a referenced
/// executable path does not exist.
fn check_hooks(home: Option<&Path>) -> Check {
    let Some(home) = home else {
        return Check::new("hooks", Status::Skip, "home directory unknown");
    };
    let path = home.join(".claude").join("settings.json");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(_) => return Check::new("hooks", Status::Skip, "no Claude Code settings.json"),
    };
    let settings: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            return Check::new(
                "hooks",
                Status::Warn,
                format!("settings.json unreadable: {e}"),
            )
            .with_fix("repair ~/.claude/settings.json JSON syntax")
        }
    };
    let mut commands = Vec::new();
    if let Some(hooks) = settings.get("hooks") {
        hook_commands(hooks, &mut commands);
    }
    let kleos: Vec<&String> = commands
        .iter()
        .filter(|c| c.to_lowercase().contains("kleos"))
        .collect();
    let missing: Vec<String> = kleos
        .iter()
        .filter_map(|c| hook_executable(c, home))
        .filter(|p| !p.exists())
        .map(|p| p.display().to_string())
        .collect();
    if !missing.is_empty() {
        Check::new(
            "hooks",
            Status::Warn,
            format!(
                "{} kleos hook(s); missing executable(s): {}",
                kleos.len(),
                missing.join(", ")
            ),
        )
        .with_fix("reinstall the hooks or remove the stale entries from settings.json")
    } else if kleos.is_empty() {
        Check::new(
            "hooks",
            Status::Warn,
            "no kleos hooks registered in Claude Code",
        )
        .with_fix("install the Kleos hooks if session integration is expected")
    } else {
        Check::new(
            "hooks",
            Status::Ok,
            format!("{} kleos hook(s), all executables present", kleos.len()),
        )
    }
}

/// Returns the `major.minor` prefix of a semantic version string.
fn major_minor(version: &str) -> Option<(&str, &str)> {
    let mut parts = version.trim_start_matches('v').split('.');
    Some((parts.next()?, parts.next()?))
}

/// Compares the CLI version against the version reported by `/health`.
fn check_version(cli_version: &str, health: &Value) -> Check {
    let Some(server) = health.get("version").and_then(|v| v.as_str()) else {
        return Check::new(
            "version_compat",
            Status::Warn,
            "server /health did not report a version",
        );
    };
    if major_minor(server) == major_minor(cli_version) {
        Check::new(
            "version_compat",
            Status::Ok,
            format!("cli v{cli_version}, server v{server}"),
        )
    } else {
        Check::new(
            "version_compat",
            Status::Warn,
            format!("cli v{cli_version}, server v{server} differ in major.minor"),
        )
        .with_fix("upgrade whichever side is older")
    }
}

/// Classifies an authenticated-read error, treating 401/403 as failure.
fn classify_auth_error(err: &str) -> Check {
    if err.starts_with("HTTP 401") || err.starts_with("HTTP 403") {
        Check::new(
            "auth",
            Status::Fail,
            "server rejected credentials (401/403)",
        )
        .with_fix("re-authenticate: check the API key source, signing identity, or session token")
    } else {
        Check::new(
            "auth",
            Status::Warn,
            format!(
                "authenticated read failed: {}",
                kleos_client::truncate(err, 200)
            ),
        )
    }
}

/// Runs read-only server checks. Dependent checks are skipped when the
/// server is unreachable.
pub async fn server_checks(client: &Client, cli_version: &str) -> Vec<Check> {
    let url = client.base_url().to_string();
    let health = match client.get_with_timeout("/health", SERVER_TIMEOUT).await {
        Ok(v) => v,
        Err(e) => {
            return vec![
                Check::new(
                    "reachability",
                    Status::Fail,
                    kleos_client::truncate(&e, 300).to_string(),
                )
                .with_fix(
                    "check KLEOS_URL or --server; a comma-separated failover list is supported",
                ),
                Check::new("version_compat", Status::Skip, "server unreachable"),
                Check::new("auth", Status::Skip, "server unreachable"),
            ]
        }
    };
    let reach_status = health
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let reach = if reach_status == "ok" {
        Check::new("reachability", Status::Ok, format!("{url} status ok"))
    } else {
        Check::new(
            "reachability",
            Status::Warn,
            format!("{url} reachable, status {reach_status}"),
        )
    };
    let auth =
        match tokio::time::timeout(SERVER_TIMEOUT, client.get("/list?limit=1&offset=0")).await {
            Err(_) => Check::new("auth", Status::Warn, "authenticated read timed out"),
            Ok(Ok(_)) => Check::new("auth", Status::Ok, "authenticated read succeeded"),
            Ok(Err(e)) => classify_auth_error(&e),
        };
    vec![reach, check_version(cli_version, &health), auth]
}

/// Unit tests for doctor checks and report rendering.
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Builds a check with the given id and status for report tests.
    fn c(id: &'static str, status: Status) -> Check {
        Check::new(id, status, "d")
    }

    /// Exit code is nonzero only when a check fails.
    #[test]
    fn exit_code_is_one_only_on_fail() {
        let ok = Report {
            checks: vec![
                c("a", Status::Ok),
                c("b", Status::Warn),
                c("s", Status::Skip),
            ],
        };
        assert_eq!(ok.exit_code(), 0);
        let bad = Report {
            checks: vec![c("a", Status::Ok), c("b", Status::Fail)],
        };
        assert_eq!(bad.exit_code(), 1);
    }

    /// JSON output preserves every check id and lowercase status names.
    #[test]
    fn json_lists_every_check_id() {
        let report = Report {
            checks: vec![c("one", Status::Ok), c("two", Status::Fail).with_fix("x")],
        };
        let v: Value = serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        let ids: Vec<&str> = v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["one", "two"]);
        assert_eq!(v["checks"][1]["status"], "fail");
    }

    /// Text output shows the status label and an indented fix.
    #[test]
    fn text_render_includes_fix_line() {
        let report = Report {
            checks: vec![c("two", Status::Fail).with_fix("do x")],
        };
        let text = report.render_text();
        assert!(text.contains("[FAIL] two: d"));
        assert!(text.contains("fix: do x"));
    }

    /// URL entries are classified by scheme, host trust, and validity, including failover lists.
    #[test]
    fn url_classification() {
        assert_eq!(check_url("http://127.0.0.1:4200").status, Status::Ok);
        assert_eq!(check_url("http://localhost:4200").status, Status::Ok);
        assert_eq!(check_url("http://10.0.0.5:4200").status, Status::Ok);
        assert_eq!(check_url("http://100.100.1.2:4200").status, Status::Ok);
        assert_eq!(check_url("https://example.com").status, Status::Ok);
        assert_eq!(check_url("http://example.com:4200").status, Status::Warn);
        assert_eq!(check_url("http://8.8.8.8:4200").status, Status::Warn);
        assert_eq!(check_url("not a url").status, Status::Fail);
        assert_eq!(
            check_url("http://10.0.0.5:4200,http://192.168.1.9:4200").status,
            Status::Ok
        );
        assert_eq!(
            check_url("http://10.0.0.5:4200, http://example.com").status,
            Status::Warn
        );
        assert_eq!(check_url(" , ").status, Status::Fail);
    }

    /// Project check names the winning source and flags stale overrides.
    #[test]
    fn project_explains_source() {
        assert_eq!(check_project(None, None).status, Status::Warn);
        assert_eq!(check_project(Some("Kleos"), None).status, Status::Ok);
        assert_eq!(
            check_project(Some("Kleos"), Some("Kleos")).status,
            Status::Ok
        );
        let over = check_project(Some("Kleos"), Some("other"));
        assert_eq!(over.status, Status::Warn);
        assert!(over.detail.contains("overriding repository identity Kleos"));
    }

    /// MCP registration is found in nested Claude JSON and Codex TOML without leaking values.
    #[test]
    fn mcp_detection_in_nested_json_and_toml() {
        let dir = tempdir();
        assert_eq!(
            check_mcp_registration(Some(&dir), &dir).status,
            Status::Skip
        );
        std::fs::write(
            dir.join(".claude.json"),
            json!({"projects": {"/x": {"mcpServers": {"kleos": {"command": "k", "env": {"KEY": "sekrit"}}}}}}).to_string(),
        )
        .unwrap();
        std::fs::create_dir_all(dir.join(".codex")).unwrap();
        std::fs::write(
            dir.join(".codex/config.toml"),
            "[mcp_servers.other]\ncommand = \"x\"\n",
        )
        .unwrap();
        let check = check_mcp_registration(Some(&dir), &dir);
        assert_eq!(check.status, Status::Warn);
        assert!(check.detail.contains("claude-code: registered"));
        assert!(check.detail.contains("codex: not registered"));
        assert!(!check.detail.contains("sekrit"));
    }

    /// A `.mcp.json` in an ancestor directory counts as Claude Code registration.
    #[test]
    fn mcp_detection_via_ancestor_project_file() {
        let home = tempdir();
        let repo = home.join("projects").join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(
            home.join(".claude.json"),
            json!({"mcpServers": {"github": {}}}).to_string(),
        )
        .unwrap();
        assert!(check_mcp_registration(Some(&home), &repo)
            .detail
            .contains("claude-code: not registered"));
        std::fs::write(
            home.join(".mcp.json"),
            json!({"mcpServers": {"kleos": {"type": "http"}}}).to_string(),
        )
        .unwrap();
        assert!(check_mcp_registration(Some(&home), &repo)
            .detail
            .contains("claude-code: registered"));
    }

    /// Hooks referencing missing absolute executables are reported.
    #[test]
    fn hooks_flag_missing_executables() {
        let dir = tempdir();
        std::fs::create_dir_all(dir.join(".claude/hooks")).unwrap();
        std::fs::write(dir.join(".claude/hooks/present.sh"), "").unwrap();
        let settings = json!({"hooks": {"SessionStart": [{"hooks": [
            {"type": "command", "command": "bash ~/.claude/hooks/kleos-start.sh"},
            {"type": "command", "command": "~/.claude/hooks/present.sh kleos"},
            {"type": "command", "command": "KLEOS_X=1 $HOME/.claude/hooks/gone-kleos.sh"}
        ]}]}});
        std::fs::write(dir.join(".claude/settings.json"), settings.to_string()).unwrap();
        let check = check_hooks(Some(&dir));
        assert_eq!(check.status, Status::Warn, "{}", check.detail);
        assert!(check.detail.contains("gone-kleos.sh"));
        assert!(!check.detail.contains("present.sh"));
    }

    /// Version skew and auth errors map to the expected statuses.
    #[test]
    fn version_and_auth_classification() {
        assert_eq!(
            check_version("1.10.0", &json!({"version": "1.10.3"})).status,
            Status::Ok
        );
        assert_eq!(
            check_version("1.10.0", &json!({"version": "1.9.0"})).status,
            Status::Warn
        );
        assert_eq!(check_version("1.10.0", &json!({})).status, Status::Warn);
        assert_eq!(
            classify_auth_error("HTTP 401 Unauthorized x: no").status,
            Status::Fail
        );
        assert_eq!(classify_auth_error("HTTP 500 x: boom").status, Status::Warn);
        assert_eq!(
            classify_auth_error("HTTP 500 Internal Server Error http://h:4010/list: boom").status,
            Status::Warn
        );
    }

    /// A different kleos-cli earlier on PATH is reported as stale.
    #[test]
    fn binary_detects_stale_path_entry() {
        let dir = tempdir();
        let bin_a = dir.join("a");
        let bin_b = dir.join("b");
        std::fs::create_dir_all(&bin_a).unwrap();
        std::fs::create_dir_all(&bin_b).unwrap();
        std::fs::write(bin_a.join(binary_name()), "").unwrap();
        std::fs::write(bin_b.join(binary_name()), "").unwrap();
        let path = std::env::join_paths([&bin_a, &bin_b]).unwrap();
        let exe = bin_b.join(binary_name());
        assert_eq!(
            check_binary("1.0.0", Some(&exe), Some(&path)).status,
            Status::Warn
        );
        let exe = bin_a.join(binary_name());
        assert_eq!(
            check_binary("1.0.0", Some(&exe), Some(&path)).status,
            Status::Ok
        );
    }

    /// Creates a unique empty directory under the system temp dir.
    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        /// Per-process counter that keeps test directories distinct.
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "kleos-doctor-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
