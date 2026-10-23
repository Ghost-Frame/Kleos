//! End-to-end tests for the `cred` custody thin client.
//!
//! The custody-profile credd + Phylax router is served in-process on an
//! ephemeral 127.0.0.1 port (built directly, bypassing the daemon's bind
//! preflight, like `kleos-credd/tests/custody.rs`). A fixture secret with a
//! distinctive value is seeded into its vault, then the built `cred` binary is
//! driven against it. Every byte the binary writes (stdout, stderr) and every
//! file left in the scratch directory is scanned for the fixture value in raw,
//! hex, base64, percent-encoded and JSON-escaped forms.
//!
//! The binary runs with a cleared environment pointing at a nonexistent config
//! root, so it can never read or write a real user's `~/.config`.

mod common;

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Once};

use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::Response;
use tokio::task::JoinHandle;

use kleos_cred::agent_keys::{create_agent_key, AgentKeyPermissions};
use kleos_cred::crypto::derive_key;
use kleos_cred::storage::{get_secret, list_secrets, store_secret};
use kleos_cred::types::SecretData;
use kleos_cred::CredError;
use kleos_credd::auth::IsUnixSocket;
use kleos_credd::profile::RunProfile;
use kleos_credd::state::AppState;
use kleos_lib::db::Database;
use kleos_phylax::router::compose_router_with_phylax_state;
use kleos_phylax::ssh_ca_signer::{MintedSshCertificate, SignedSshCertificate, SshCaSigner};
use kleos_phylax::state::PhylaxState;

use common::{Canary, CANARY_SECRET};

/// Config root handed to the daemon and the binary; it does not exist.
const ISOLATED_CONFIG_ROOT: &str = "/nonexistent-cred-thin-client-test";

/// Category and name of the seeded fixture secret.
const FIXTURE_CATEGORY: &str = "prod";
/// Name of the seeded fixture secret.
const FIXTURE_NAME: &str = "db-pass";

/// Certificate text returned by the fixture signer (public material).
const FIXTURE_CERT: &str = "ssh-ed25519-cert-v01@openssh.com FIXTURECERTIFICATE fixture";

/// Guard so the process environment is rewritten exactly once.
static ISOLATE: Once = Once::new();

/// Point every config-root lookup at a nonexistent directory and drop the
/// variables that could make the in-process daemon reach a real Kleos.
fn isolate_environment() {
    ISOLATE.call_once(|| {
        std::env::set_var("XDG_CONFIG_HOME", ISOLATED_CONFIG_ROOT);
        std::env::set_var("HOME", ISOLATED_CONFIG_ROOT);
        for var in [
            "KLEOS_URL",
            "ENGRAM_URL",
            "CREDD_AGENT_KEYS_FILE",
            "KLEOS_SSH_CA_ALLOWED_PRINCIPALS",
        ] {
            std::env::remove_var(var);
        }
    });
}

/// SSH CA signer that returns fixed public material, so no test shells out.
struct FixtureSigner;

/// Fixed-output signer implementation.
impl SshCaSigner for FixtureSigner {
    /// Return the fixture certificate.
    fn sign(
        &self,
        _identity: &str,
        _principal: &str,
        _ttl: &str,
        _public_key: &str,
    ) -> Result<SignedSshCertificate, CredError> {
        Ok(SignedSshCertificate {
            cert_public_key: FIXTURE_CERT.to_string(),
        })
    }

    /// Return the fixture certificate with daemon-side paths that must never
    /// reach the client.
    fn mint(
        &self,
        _agent: &str,
        _principal: &str,
        _ttl: &str,
    ) -> Result<MintedSshCertificate, CredError> {
        Ok(MintedSshCertificate {
            key_path: PathBuf::from("/daemon-only/agent"),
            cert_path: PathBuf::from("/daemon-only/agent-cert.pub"),
            cert_public_key: FIXTURE_CERT.to_string(),
        })
    }
}

/// Mark every request as arriving on the Unix socket (test-only simulation of
/// the 0600 socket listener, the only place the master bearer is honoured).
async fn mark_unix(mut request: Request, next: Next) -> Response {
    request.extensions_mut().insert(IsUnixSocket(true));
    next.run(request).await
}

/// A custody-profile daemon serving on a loopback port.
struct TestServer {
    /// `127.0.0.1:<port>`, the value for `CRED_CUSTODY`.
    target: String,
    /// Hex master bearer (only ever used against the simulated-unix server).
    master_token: String,
    /// Raw key of a `prod`-scoped agent created in the vault.
    agent_key: String,
    /// Daemon state, kept to inspect the vault directly.
    state: AppState,
    /// Master key bytes used to open vault rows in assertions.
    master_key: [u8; 32],
    /// Serving task, aborted on drop.
    task: JoinHandle<()>,
}

/// Stops the server when the test ends.
impl Drop for TestServer {
    /// Abort the serving task.
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Server construction.
impl TestServer {
    /// Start a custody daemon. With `simulate_unix` every request carries the
    /// Unix-socket marker, which is how master-only verbs can be exercised.
    async fn start(simulate_unix: bool) -> Self {
        isolate_environment();
        let db = Database::connect_memory().await.expect("in-memory db");
        let master_key = derive_key(1, b"custody-cli-test-master", None);
        let master_token = hex::encode(*master_key);
        let state = AppState::new(db, *master_key).with_run_profile(RunProfile::Custody);

        store_secret(
            &state.db,
            1,
            FIXTURE_CATEGORY,
            FIXTURE_NAME,
            &SecretData::Note {
                content: CANARY_SECRET.to_string(),
            },
            &master_key,
        )
        .await
        .expect("seed fixture secret");
        let (agent_key, _) = create_agent_key(
            &state.db,
            1,
            "cli-agent",
            &AgentKeyPermissions::new(vec![FIXTURE_CATEGORY.to_string()], Vec::new()),
        )
        .await
        .expect("create agent key");

        let phylax =
            PhylaxState::from_app_state(state.clone()).with_ssh_ca_signer(Arc::new(FixtureSigner));
        let mut router = compose_router_with_phylax_state(phylax);
        if simulate_unix {
            router = router.layer(middleware::from_fn(mark_unix));
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        let task = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });

        Self {
            target: format!("127.0.0.1:{port}"),
            master_token,
            agent_key,
            state,
            master_key: *master_key,
            task,
        }
    }

    /// Names currently in the vault, as `category/name`.
    async fn vault_names(&self) -> Vec<String> {
        list_secrets(&self.state.db, 1, None)
            .await
            .expect("list vault")
            .into_iter()
            .map(|row| format!("{}/{}", row.category, row.name))
            .collect()
    }
}

/// Everything one `cred` invocation produced.
struct Run {
    /// Arguments after the program name.
    args: Vec<String>,
    /// Exit code (`None` if killed by a signal).
    code: Option<i32>,
    /// Captured stdout.
    stdout: Vec<u8>,
    /// Captured stderr.
    stderr: Vec<u8>,
}

/// Output helpers.
impl Run {
    /// Stdout as lossy text.
    fn out(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Stderr as lossy text.
    fn err(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// True on exit code 0.
    fn ok(&self) -> bool {
        self.code == Some(0)
    }
}

/// Run the built `cred` binary with a cleared environment.
///
/// `custody` becomes `CRED_CUSTODY` and `key` becomes `CREDD_AGENT_KEY` when
/// given; `stdin` is written to the child and then closed.
fn run_cred(custody: Option<&str>, key: Option<&str>, args: &[&str], stdin: &str) -> Run {
    use std::io::Write;

    let mut command = Command::new(env!("CARGO_BIN_EXE_cred"));
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", ISOLATED_CONFIG_ROOT)
        .env("XDG_CONFIG_HOME", ISOLATED_CONFIG_ROOT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(custody) = custody {
        command.env("CRED_CUSTODY", custody);
    }
    if let Some(key) = key {
        command.env("CREDD_AGENT_KEY", key);
    }
    let mut child = command.spawn().expect("spawn cred");
    {
        let mut pipe = child.stdin.take().expect("stdin pipe");
        let _ = pipe.write_all(stdin.as_bytes());
    }
    let output = child.wait_with_output().expect("wait for cred");
    Run {
        args: args.iter().map(|a| a.to_string()).collect(),
        code: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

/// Every regular file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(files_under(&path));
        } else {
            found.push(path);
        }
    }
    found
}

/// Assert the canary appears in no output of any run and no file under `dir`.
fn assert_no_leak(runs: &[Run], dir: &Path) {
    let canary = Canary::new(CANARY_SECRET);
    assert!(
        canary.find_leak(CANARY_SECRET.as_bytes()).is_some(),
        "detector self-check: the raw value must be seen"
    );
    for run in runs {
        for (stream, bytes) in [("stdout", &run.stdout), ("stderr", &run.stderr)] {
            if let Some(label) = canary.find_leak(bytes) {
                panic!(
                    "fixture secret ({label}) leaked on {stream} of `cred {:?}`",
                    run.args
                );
            }
        }
    }
    for file in files_under(dir) {
        let bytes = std::fs::read(&file).expect("read scratch file");
        if let Some(label) = canary.find_leak(&bytes) {
            panic!("fixture secret ({label}) found in {}", file.display());
        }
    }
}

/// Fixture control: the seeded vault really holds the canary, so a clean scan
/// proves the client withheld it rather than the vault being empty.
async fn assert_fixture_is_seeded(server: &TestServer) {
    let (_, data) = get_secret(
        &server.state.db,
        1,
        FIXTURE_CATEGORY,
        FIXTURE_NAME,
        &server.master_key,
    )
    .await
    .expect("fixture present");
    match data {
        SecretData::Note { content } => assert_eq!(content, CANARY_SECRET),
        _ => panic!("fixture is a note"),
    }
}

/// An agent-key client can list but never see the value; master-only verbs are
/// refused by the daemon with a clean error; exec reports phase 2 with exit 2;
/// every plaintext-handling subcommand is rejected by clap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_key_client_never_sees_the_secret() {
    let server = TestServer::start(false).await;
    assert_fixture_is_seeded(&server).await;
    let scratch = tempfile::tempdir().expect("scratch dir");
    let target = server.target.as_str();
    let key = server.agent_key.as_str();
    let mut runs = Vec::new();

    let list = run_cred(Some(target), Some(key), &["list"], "");
    assert!(list.ok(), "list failed: {}", list.err());
    assert!(list.out().contains(FIXTURE_CATEGORY));
    assert!(list.out().contains(FIXTURE_NAME));
    assert!(
        !list.err().contains("unlocking"),
        "custody mode must not unlock a vault"
    );
    runs.push(list);

    // The daemon restricts mutation to the master identity; an agent key gets
    // a 403 that the client reports without crashing or leaking.
    let out_path = scratch.path().join("agent.key");
    let out_str = out_path.to_str().expect("utf8 path");
    for args in [
        vec!["store", "prod", "agent-written", "-t", "note"],
        vec!["delete", "prod", FIXTURE_NAME, "-y"],
        vec!["agent-key", "generate", "denied", "--out", out_str],
        vec!["agent-key", "list"],
        vec!["agent-key", "revoke", "cli-agent", "-y"],
    ] {
        let run = run_cred(Some(target), Some(key), &args, "agent supplied value\n");
        assert!(!run.ok(), "{args:?} should be refused for an agent key");
        assert!(run.err().contains("403"), "{args:?}: {}", run.err());
        runs.push(run);
    }
    assert!(
        !out_path.exists(),
        "a refused generate must not leave a key file"
    );
    assert!(
        server
            .vault_names()
            .await
            .contains(&format!("{FIXTURE_CATEGORY}/{FIXTURE_NAME}")),
        "the refused delete must leave the fixture in place"
    );

    // Exec is not available under custody (phase 2): exact message, exit 2,
    // and no network or key lookup is needed to say so.
    let exec = run_cred(
        Some(target),
        Some(key),
        &[
            "exec",
            FIXTURE_CATEGORY,
            FIXTURE_NAME,
            "--env",
            "V",
            "--",
            "true",
        ],
        "",
    );
    assert_eq!(exec.code, Some(2));
    assert!(
        exec.err()
            .contains("custody exec is not available until the credential issuer lands (phase 2)"),
        "{}",
        exec.err()
    );
    assert!(exec.stdout.is_empty());
    runs.push(exec);
    let exec_no_key = run_cred(Some(target), None, &["exec", "a", "b", "--", "true"], "");
    assert_eq!(exec_no_key.code, Some(2));
    runs.push(exec_no_key);

    // The same via the --custody flag instead of the environment.
    let flag = run_cred(
        None,
        Some(key),
        &["--custody", target, "list", "--service", FIXTURE_CATEGORY],
        "",
    );
    assert!(flag.ok(), "{}", flag.err());
    runs.push(flag);

    // Local unlock flags are ignored with a warning, never acted on.
    let ignored = run_cred(
        Some(target),
        Some(key),
        &[
            "--auth-mode",
            "password",
            "--master-password",
            "--keyfile",
            "/nonexistent/master.key",
            "list",
        ],
        "this must not be read as a password\n",
    );
    assert!(ignored.ok(), "{}", ignored.err());
    let warnings = ignored.err();
    assert!(warnings.contains("--auth-mode"), "{warnings}");
    assert!(warnings.contains("--master-password"), "{warnings}");
    assert!(warnings.contains("--keyfile"), "{warnings}");
    assert!(!warnings.contains("unlocking"), "{warnings}");
    runs.push(ignored);

    // Plaintext-handling verbs do not exist in the custody tree.
    for verb in [
        "get",
        "export",
        "export-key",
        "session",
        "bootstrap",
        "tui",
        "import",
        "init",
        "recover",
        "kdf-salt-init",
    ] {
        let run = run_cred(Some(target), Some(key), &[verb], "");
        assert!(!run.ok(), "`{verb}` must fail under custody");
        assert_eq!(run.code, Some(2), "`{verb}`: clap usage error expected");
        assert!(
            run.err().contains("unrecognized subcommand"),
            "`{verb}`: {}",
            run.err()
        );
        runs.push(run);
    }

    assert_no_leak(&runs, scratch.path());
}

/// With the master identity on the (simulated) Unix socket every custody verb
/// completes, and still nothing the client prints or writes carries the value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn master_on_unix_socket_completes_every_verb_without_leaking() {
    let server = TestServer::start(true).await;
    assert_fixture_is_seeded(&server).await;
    let scratch = tempfile::tempdir().expect("scratch dir");
    let target = server.target.as_str();
    let key = server.master_token.as_str();
    let mut runs = Vec::new();

    // store: the value goes up on stdin; the response is only an id.
    let store = run_cred(
        Some(target),
        Some(key),
        &["store", "prod", "thin-note", "-t", "note"],
        "value written through the thin client\n",
    );
    assert!(store.ok(), "{}", store.err());
    assert!(
        store.err().contains("stored: prod/thin-note"),
        "{}",
        store.err()
    );
    assert!(server
        .vault_names()
        .await
        .contains(&"prod/thin-note".to_string()));
    runs.push(store);

    let list = run_cred(Some(target), Some(key), &["list"], "");
    assert!(list.ok(), "{}", list.err());
    assert!(list.out().contains("thin-note"));
    assert!(list.out().contains(FIXTURE_NAME));
    runs.push(list);

    // agent-key generate: the daemon writes the key; only name + fingerprint
    // come back.
    let key_file = scratch.path().join("new-agent.key");
    let key_arg = key_file.to_str().expect("utf8 path");
    let generate = run_cred(
        Some(target),
        Some(key),
        &[
            "agent-key",
            "generate",
            "cli-made",
            "--category",
            "prod",
            "--out",
            key_arg,
        ],
        "",
    );
    assert!(generate.ok(), "{}", generate.err());
    assert!(
        generate.out().contains("name: cli-made"),
        "{}",
        generate.out()
    );
    let fingerprint = generate
        .out()
        .lines()
        .find_map(|l| l.strip_prefix("fingerprint: ").map(str::to_string))
        .expect("fingerprint line");
    assert_eq!(fingerprint.len(), 16);
    assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    let written = std::fs::read_to_string(&key_file).expect("key file");
    assert_eq!(written.trim().len(), 64, "32-byte hex key on disk");
    assert_eq!(
        std::fs::metadata(&key_file)
            .expect("stat")
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    assert!(
        !generate.out().contains(written.trim()) && !generate.err().contains(written.trim()),
        "the generated key must never be printed"
    );
    runs.push(generate);

    // The daemon refuses to overwrite the key file.
    let again = run_cred(
        Some(target),
        Some(key),
        &["agent-key", "generate", "cli-made-2", "--out", key_arg],
        "",
    );
    assert!(!again.ok());
    assert_eq!(std::fs::read_to_string(&key_file).expect("reread"), written);
    runs.push(again);

    // A relative --out is refused client-side.
    let relative = run_cred(
        Some(target),
        Some(key),
        &["agent-key", "generate", "rel", "--out", "relative.key"],
        "",
    );
    assert!(!relative.ok());
    assert!(relative.err().contains("absolute"), "{}", relative.err());
    runs.push(relative);

    let agents = run_cred(Some(target), Some(key), &["agent-key", "list"], "");
    assert!(agents.ok(), "{}", agents.err());
    assert!(agents.out().contains("cli-made"));
    assert!(agents.out().contains("cli-agent"));
    runs.push(agents);

    let revoke = run_cred(
        Some(target),
        Some(key),
        &["agent-key", "revoke", "cli-made", "-y"],
        "",
    );
    assert!(revoke.ok(), "{}", revoke.err());
    runs.push(revoke);

    // ssh-ca: the certificate is public; daemon-side key paths never surface.
    let pubkey = scratch.path().join("agent.pub");
    std::fs::write(&pubkey, "ssh-ed25519 AAAAFIXTUREPUBLICKEY fixture\n").expect("write pubkey");
    let pubkey_arg = pubkey.to_str().expect("utf8 path");
    let sign = run_cred(
        Some(target),
        Some(key),
        &["ssh-ca", "sign", "-I", "cli-agent", pubkey_arg],
        "",
    );
    assert!(sign.ok(), "{}", sign.err());
    let cert_path = scratch.path().join("agent-cert.pub");
    assert_eq!(sign.out().trim(), cert_path.to_str().expect("utf8 path"));
    assert_eq!(
        std::fs::read_to_string(&cert_path).expect("cert file"),
        FIXTURE_CERT
    );
    runs.push(sign);

    let mint = run_cred(
        Some(target),
        Some(key),
        &["ssh-ca", "mint", "--agent", "cli-agent"],
        "",
    );
    assert!(mint.ok(), "{}", mint.err());
    assert_eq!(mint.out().trim(), FIXTURE_CERT);
    assert!(!mint.out().contains("daemon-only") && !mint.err().contains("daemon-only"));
    runs.push(mint);

    let delete = run_cred(
        Some(target),
        Some(key),
        &["delete", "prod", "thin-note", "-y"],
        "",
    );
    assert!(delete.ok(), "{}", delete.err());
    assert!(!server
        .vault_names()
        .await
        .contains(&"prod/thin-note".to_string()));
    runs.push(delete);

    assert_no_leak(&runs, scratch.path());
}

/// A client with no agent key anywhere fails with an error naming both places
/// it looked, before any network traffic.
#[test]
fn missing_agent_key_error_names_both_sources() {
    isolate_environment();
    let run = run_cred(Some("127.0.0.1:9"), None, &["list"], "");
    assert!(!run.ok());
    let err = run.err();
    assert!(err.contains("CREDD_AGENT_KEY"), "{err}");
    assert!(err.contains("credd-agent-key.token"), "{err}");
}

/// Plaintext http to a non-loopback host is refused before anything is sent,
/// and so is a target carrying credentials.
#[test]
fn unsafe_custody_targets_are_refused() {
    isolate_environment();
    for target in ["http://10.50.0.1:3100", "https://user:pw@example.com"] {
        let run = run_cred(Some(target), Some("agent-key-value"), &["list"], "");
        assert!(!run.ok(), "{target} must be refused");
        assert!(
            run.err().contains("invalid custody target"),
            "{}",
            run.err()
        );
        assert!(!run.err().contains("agent-key-value"));
    }
}
