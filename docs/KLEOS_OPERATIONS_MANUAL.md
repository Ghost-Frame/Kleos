# Kleos Operations Manual

Canonical operator reference for the command-line tools that ship with Kleos.
This is the source of truth for what each command is for, how it authenticates,
what side effects it has, and when an agent should use it.

## Scope

This manual covers the operator-facing binaries installed by the `agent-host`
and `full` profiles in [dist/install.sh](../dist/install.sh):

- `kleos-cli`
- `kleos-sh`
- `kr`, `kw`, `ke`
- `agent-forge`
- `cred`
- `credd`
- `kleos-sidecar`
- `kleos-server`
- `kleos-mcp`
- `eidolon-supervisor`

## Quick routing

Use this table when choosing the right command:

| Need | Command |
|---|---|
| Store, search, recall, or hand off knowledge | `kleos-cli` |
| Report a task lifecycle event (started/progress/completed/blocked/error) | `kleos-cli activity` |
| Run a shell command through Kleos gate checks | `kleos-sh` |
| Read code or files safely | `kr` |
| Write file contents from stdin inside approved roots | `kw` |
| Check whether an edit is allowed for a file | `ke` |
| Create a spec, log a bug hypothesis, verify a change, or map code | `agent-forge` |
| Read or write secrets in the local vault | `cred` |
| Broker per-agent Kleos bearers and resolve secrets for clients | `credd` |
| Batch observations from hooks or sessions | `kleos-sidecar` |
| Run the HTTP API server | `kleos-server` |
| Expose Kleos as an MCP server | `kleos-mcp` |
| Watch Claude session logs for drift and violations | `eidolon-supervisor` |

## Shared conventions

- `KLEOS_URL` defaults to `http://127.0.0.1:4200` for most client tools.
- Kleos auth usually resolves in this order: explicit CLI key, signing identity,
  then per-agent bearer bootstrap via `credd`.
- Secrets should be injected into child processes with `cred exec` or
  `kleos-cli cred exec`. Do not print secrets into stdout.
- `kr`, `kw`, and `ke` are wrappers for agent use. They are not general shell
  replacements.
- Claude hook handlers fail open on transport failures by design. Direct shell
  execution paths default to fail closed unless configured otherwise.

## `kleos-cli`

Synopsis:

```bash
kleos-cli [--server URL] [--phylaxd-url URL] [--credd-url URL] [--key API_KEY] COMMAND ...
```

Purpose:

- Main human and agent client for the Kleos HTTP API.
- Covers memory, search, ingestion, jobs, skills, credentials, handoffs,
  Claude hooks, identity enrollment, bearer/API key management, MCP token
  management, multi-user enrollment helpers, artifacts, and admin workflows.

Authentication model:

- Request signing identity, if configured, takes precedence for normal requests.
- `--key` overrides everything for bearer auth.
- If no key is passed, `kleos-cli` resolves the current agent slot and asks the
  bootstrap path for a per-agent Kleos bearer.
- `hook` commands are special: they use direct env-based auth instead of the
  normal bootstrap flow.

### Core memory commands

#### `kleos-cli store CONTENT [--category CAT] [--importance N] [--tags csv] [--source SRC]`

- Stores one memory via `POST /store`.
- `tags` are split on commas and trimmed.
- If the server returns `existing_id`, the CLI reports it as a duplicate.

Use for:

- Durable facts, decisions, issues, state, references, and task notes.

#### `kleos-cli search QUERY [--limit N]`

- Searches via `POST /search`.
- Prints each hit with final score plus channel breakdown when returned:
  final score, cosine score, and BM25/FTS score.

Use for:

- Fast recall before asking a human, opening a broad investigation, or editing.

#### `kleos-cli context QUERY [--limit N]`

- Calls `POST /recall` with both `query` and `context`.
- Returns richer JSON context than `search`.

Use for:

- Turn-level context injection or deeper retrieval where surrounding detail
  matters more than a flat result list.

#### `kleos-cli recall ID`

- Fetches one memory via `GET /memory/{id}`.

#### `kleos-cli list [--limit N] [--offset N]`

- Lists memories via `GET /list`.

#### `kleos-cli delete ID`

- Deletes one memory via `DELETE /memory/{id}`.

#### `kleos-cli guard CONTENT`

- Evaluates a proposed action through `POST /guard`.
- Prints matched rules and exits `2` on `warn` or `block`.

Use for:

- Preflight checks when you want a direct rule evaluation without running
  through `kleos-sh`.

#### `kleos-cli recall-due TOPIC [--limit N] [--session ID]`

- Calls `GET /fsrs/recall-due`.
- Surfaces memories with low retrievability that should be reinforced.

Use for:

- Review loops and reinforcement passes.

#### `kleos-cli ingest [--text TEXT | --file PATH] [--mode raw|extract] [--source SRC] [--category CAT]`

How it works:

- Text input goes directly to `POST /ingest`.
- Binary-like files go through the chunked upload flow:
  `POST /ingest/upload/init`, repeated `POST /ingest/upload/chunk`,
  then `POST /ingest/upload/complete`.
- Upload chunks are 1 MiB and hashed with SHA-256.

Use for:

- Markdown, text, HTML, CSV, JSONL, PDF, DOCX, ZIP, and similar source imports.

#### `kleos-cli health`

- Fetches `GET /health`.

#### `kleos-cli doctor [--json] [--dir PATH]`

- Diagnoses the client installation and server access in one pass. Every
  check reports `ok`, `warn`, `fail`, or `skip`, with a suggested manual fix
  where one applies. Nothing is repaired automatically.
- Local checks: `binary` (version, and whether `PATH` resolves `kleos-cli`
  to a different file), `url` (every entry of the `KLEOS_URL` failover list;
  plaintext HTTP to a public, non-loopback host warns), `project`
  (the identity `--dir` resolves to, and whether `SESSION_HANDOFF_PROJECT`
  overrides it), `mcp_registration` (Claude Code `~/.claude.json` plus every
  ancestor `.mcp.json`, and Codex `~/.codex/config.toml`), `hooks` (Claude
  Code hooks mentioning kleos whose executable path is missing).
- Server checks: `reachability` (`GET /health`), `version_compat` (CLI
  versus server `major.minor`), `auth` (one authenticated `GET /list?limit=1`).
  They are skipped when the server is unreachable.
- Exits `1` if any check fails, otherwise `0`. `--json` emits the full report.
- Never prints credential values, MCP commands, or headers. The only possible
  side effect is the standard client session-token cache, which the `auth`
  probe may refresh or clear exactly like any other authenticated command.

#### `kleos-cli activity --action ACT --summary TEXT [--project P] [--agent A] [--metadata JSON]`

- Posts a lifecycle event to `POST /activity`.
- Signed with the local PIV or Ed25519 identity through the standard `Client`
  auth path -- no bearer token or `cred exec` wrapper required.
- The single call fans out to Chiasm (tasks), Axon (events), Broca (actions),
  Thymus (metrics), Skills, and Memory.
- `--action` is one of `task.started`, `task.progress`, `task.completed`,
  `task.blocked`, `error.raised`, or any custom event name.
- `--agent` defaults to `claude-code`.
- `--metadata` accepts a JSON object string and is mapped onto the
  `metadata`/`details` field server-side.
- This is the recommended path for activity reporting; `cred exec curl`
  remains as a fallback for hosts without an enrolled identity.

Use for:

- Per sub-task lifecycle reporting from agent sessions.

#### `kleos-cli bootstrap`

- Calls `POST /bootstrap`.
- Used once to claim the initial API key after server bootstrap is enabled.

### Jobs

#### `kleos-cli jobs stats`

- Calls `GET /jobs/stats`.

#### `kleos-cli jobs list [--status pending|running|failed] [--limit N] [--offset N]`

- Calls `GET /jobs`.

#### `kleos-cli jobs retry ID`

- Calls `POST /jobs/{id}/retry`.

#### `kleos-cli jobs retry --all`

- There is no server-side retry-all endpoint.
- The CLI emulates it by listing failed jobs and retrying each one individually.

#### `kleos-cli jobs purge [--older-than-days N]`

- Calls `POST /jobs/purge`.
- Removes old failed jobs.

#### `kleos-cli jobs cleanup [--older-than-days N]`

- Calls `POST /jobs/cleanup`.
- Removes old completed jobs.

### Skills

#### `kleos-cli skill search QUERY [--limit N]`

- Calls `POST /skills/search`.

#### `kleos-cli skill list [--limit N] [--offset N] [--agent NAME]`

- Calls `GET /skills`.

#### `kleos-cli skill get ID`

- Calls `GET /skills/{id}`.

#### `kleos-cli skill execute ID --success [--duration-ms N] [--error-type T] [--error-message MSG]`

- Calls `POST /skills/{id}/execute`.
- Records whether a skill run worked and how long it took.

#### `kleos-cli skill capture DESCRIPTION [--agent NAME]`

- Calls `POST /skills/capture`.
- Used to turn a description into a new skill record.

#### `kleos-cli skill fix ID [--direction TEXT] [--agent NAME]`

- Calls `POST /skills/{id}/fix`.

#### `kleos-cli skill derive PARENT_ID ... --direction TEXT [--agent NAME]`

- Calls `POST /skills/derive`.

#### `kleos-cli skill stats`

- Calls `GET /skills/dashboard/overview`.

#### `kleos-cli skill lineage ID`

- Calls `GET /skills/{id}/lineage`.

#### `kleos-cli skill evolve [--hours N] [--limit N]`

- Calls `GET /skills/evolution/recent`.

### Credentials through Phylax

These commands talk to the credential authority, not directly to the main
Kleos server. `PHYLAXD_URL` is preferred. `CREDD_URL` remains a transition
fallback, and both default to `http://127.0.0.1:4400` when unset.

Endpoint resolution:

1. `--phylaxd-url` or `--credential-authority-url`
2. `PHYLAXD_URL`
3. `--credd-url`
4. `CREDD_URL`
5. `http://127.0.0.1:4400`

Token resolution:

- `CREDD_AGENT_KEY`
- `~/.config/cred/credd-agent-key.token`
- fallback to the current Kleos bearer if neither exists

#### `kleos-cli cred get CATEGORY NAME [--raw]`

- Calls `GET /secret/{category}/{name}` on the credential authority.
- `--raw` extracts the primary value field from the secret object.

#### `kleos-cli cred set CATEGORY NAME [--secret-type TYPE] [--value V] [--username U] [--url URL]`

- Calls `POST /secret/{category}/{name}` on the credential authority.
- If `--value` is omitted, the CLI prompts on stdin without echoing.

Supported types:

- `api_key`
- `login`
- `oauth_app`
- `ssh_key`
- `note`

#### `kleos-cli cred list [--category CAT]`

- Calls `GET /secrets`.

#### `kleos-cli cred delete CATEGORY NAME`

- Calls `DELETE /secret/{category}/{name}`.

#### `kleos-cli cred agent-create NAME [--categories csv] [--allow-raw]`

- Calls `POST /agents`.
- Prints the generated agent key once. It cannot be re-read later.

#### `kleos-cli cred agent-list`

- Calls `GET /agents`.

#### `kleos-cli cred agent-revoke NAME`

- Calls `POST /agents/{name}/revoke`.

#### `kleos-cli cred exec CATEGORY NAME --env VAR -- COMMAND ...`

How it works:

- For `CATEGORY` equal to `kleos` or `engram-rust`, this uses the bootstrap
  bearer path to fetch a per-agent Kleos key for `NAME`.
- For all other categories, it reads the secret object from `credd` and
  extracts either the requested `--field` or the primary value.
- The secret is injected into the child environment and never printed by the CLI.

Use for:

- `curl`, SDKs, deployment tools, or any child process that needs a secret.

### Attention notes

Think Post-its on a monitor, not memories. Attention notes are not ingested,
ranked, embedded, or decayed -- they just sit there and stare at you until you
explicitly delete them. Use them for short "don't forget to …" items that need
to survive session boundaries without getting buried in recall noise.

Priority range is 1 (low) to 10 (high), default 5. The list is always returned
sorted by priority descending, then creation time ascending (oldest high-priority
note first).

**HTTP API**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/attention` | Create a note |
| `GET` | `/attention` | List all open notes |
| `PATCH` | `/attention/{id}` | Update content and/or priority |
| `DELETE` | `/attention/{id}` | Delete a note (mark as done) |

**POST /attention**

```json
{ "content": "rebase the watcher fix onto main", "priority": 8 }
```

Returns the created note (201). `priority` is optional; defaults to 5.

**GET /attention**

```
GET /attention?limit=50
```

Returns `{ "notes": [...], "count": N }`. `limit` defaults to 50, max 200.

**PATCH /attention/{id}**

Both fields are optional; omit what you don't want to change.

```json
{ "priority": 10 }
```

Returns the updated note.

**DELETE /attention/{id}**

Returns 204 on success, 404 if the note does not exist or belongs to another
tenant.

**Typical agent workflow**

1. On session start: `GET /attention` -- review open reminders.
2. During work: `POST /attention` -- pin a new reminder for next time.
3. When a task is done: `DELETE /attention/{id}` -- remove the note.

### Handoffs

Handoff identity has three independent parts:

- `scope`: `repository` or `standalone` for new writes; migrated rows retain
  `legacy`.
- `workstream`: the logical subject that groups related sessions.
- `session_id`: the stable identity of one agent thread within a workstream.

`project` remains a compatibility and repository label. `directory` is
provenance only and is never promoted to identity outside a Git worktree.

#### `kleos-cli handoff dump [--project P] [--workstream W] [--title TEXT] [--branch B] [--agent A] [--handoff-type T] [--session S] [--model M] [--host H] [--content TEXT] [--dir PATH]`

- Stores a handoff via `POST /handoffs`.
- If `--content` is omitted, reads stdin.
- Inside Git, detects a repository project from `SESSION_HANDOFF_PROJECT`, the
  origin URL, or the Git root name.
- Outside Git, stores a semantic `standalone` handoff and requires a logical
  workstream plus a stable session id. The CLI resolves session identity from
  `--session`, `SESSION_ID`, or `CODEX_THREAD_ID`.
- `SESSION_HANDOFF_WORKSTREAM` supplies a reusable default workstream.

#### `kleos-cli handoff restore [filters...]`

- `--id ID` calls `GET /handoffs/{id}` for an exact restore.
- Filtered restore calls `GET /handoffs`.
- Prints only the handoff content bodies.
- Outside Git, restore requires an exact handoff id or stable session id. It
  never guesses from the global newest row.

#### `kleos-cli handoff latest [--project P] [--dir PATH]`

- Calls `GET /handoffs/latest`.
- Requires a repository project. A missing exact project match returns not
  found instead of falling back to a different project.

#### `kleos-cli handoff mechanical [--project P] [--agent A] [--dir PATH] [--session S] [--model M] [--host H]`

How it works:

- Collects git status, recent commits, diff stats, stashes, and recently
  modified files from the working tree.
- Stores that bundle as a `mechanical` handoff via `POST /handoffs`.
- Refuses to run outside a Git worktree, even when `--project` is supplied.

Use for:

- Mechanical state capture at session boundaries.

#### `kleos-cli handoff list [--limit N] [--project P] [--scope S] [--workstream W] [--agent A] [--handoff-type T]`

- Calls `GET /handoffs`.
- Prints a summary table.

#### `kleos-cli handoff candidates [--limit N] [--scope S] [--workstream W] [--agent A] [--since TIME]`

- Calls `GET /handoffs/candidates`.
- Returns only the newest checkpoint for each stable session id.
- Prints complete ids and session identities so an ambiguous standalone
  restore can be selected explicitly with `handoff restore --id ID`.

#### `kleos-cli handoff search QUERY [--project P] [--limit N]`

- Calls `GET /handoffs/search`.

#### `kleos-cli handoff stats`

- Calls `GET /handoffs/stats`.

#### `kleos-cli handoff gc [--tiered] [--keep N]`

- Calls `POST /handoffs/gc`.

### Claude hook handlers

#### `kleos-cli hook session-start`

- Registers session start with `POST /activity`.
- Fetches growth context from `/growth/materialize`.
- Emits Claude hook JSON on stdout.

#### `kleos-cli hook user-prompt`

- Reads Claude hook JSON from stdin.
- Checks supervisor pending injections through `/supervisor/pending`.
- Emits deny if a supervisor violation is pending; otherwise no output.

#### `kleos-cli hook stop`

- Records session end via `POST /activity`.

#### `kleos-cli hook pre-tool`

- Reads the proposed tool use from stdin.
- Derives a normalized command string.
- Sends it to `POST /gate/check`.
- Emits deny or additional context in Claude hook format.
- Fails open if the gate cannot be reached.

#### `kleos-cli hook post-tool`

- Reports completion to `/activity`.
- Closes the latest gate with `POST /gate/complete-latest`.

#### `kleos-cli hook post-bash`

- Back-compat alias for `post-tool`.

### Identity keys

#### `kleos-cli identity init [--label TEXT] [--software]`

How it works:

- Prefers a PIV YubiKey signer if present.
- Falls back to generating a software Ed25519 key if no YubiKey is detected,
  or immediately uses software when `--software` is passed.
- Signs an enrollment proof and posts it to `/identity-keys/enroll`.

#### `kleos-cli identity status`

- Prints the active local signing identity.

#### `kleos-cli identity list`

- Calls `GET /identity-keys/mine`.

#### `kleos-cli identity revoke ID [--reason TEXT]`

- Calls `POST /identity-keys/{id}/revoke`.

### Bearer API keys

#### `kleos-cli api-key list`

- Lists bearer API keys visible to the current caller.
- Admin callers can see all keys; non-admin callers see their own.

#### `kleos-cli api-key create --name NAME [--scopes csv] [--rate-limit N]`

- Creates a new bearer API key.
- `--scopes` defaults to `read,write`; admin-scoped keys require admin scope on
  the caller.
- `--rate-limit` overrides the inherited requests-per-minute cap.

Use for:

- Long-lived HTTP/API access where bearer auth is the right fit.

#### `kleos-cli api-key revoke ID`

- Revokes a bearer API key by numeric ID.
- Revoking other users' keys requires admin scope.

### MCP direct-auth tokens

#### `kleos-cli mcp-token mint --name NAME [--scopes csv] [--ttl DURATION]`

How it works:

- Mints an identity-signed bearer token in the `kleos.<payload>.<sig>` format.
- Registers the token with the server and prints the bearer string once.
- Scopes are strict (`read`, `write`, `admin` only); wildcards are rejected.
- Default TTL is 30 days; the server enforces the configured maximum TTL cap.

Use for:

- MCP clients that can only send a static `Authorization: Bearer ...` header.

#### `kleos-cli mcp-token list`

- Lists registered MCP direct-auth tokens for the current caller.

#### `kleos-cli mcp-token info JTI`

- Shows metadata for a single MCP token by `jti`.

#### `kleos-cli mcp-token revoke JTI`

- Revokes one MCP token by `jti`.

#### `kleos-cli mcp-token revoke-all`

- Revokes every MCP token for the current caller.

### Multi-user enrollment helpers

#### `kleos-cli user create`

- Creates a new user account on a multi-user Kleos server.
- Admin-only.

#### `kleos-cli user list`

- Lists server user accounts.
- Admin-only.

#### `kleos-cli invite create`

- Generates a one-time enrollment invite token for FIDO2 key registration.
- Intended for multi-user setups where an operator is onboarding another user.

### Artifacts

#### `kleos-cli artifact upload MEMORY_ID FILE [--name TEXT] [--artifact-type TYPE] [--agent NAME]`

- Uploads a file and attaches it to an existing memory record.
- Defaults the display name to the filename and the artifact type to `file`.

#### `kleos-cli artifact list MEMORY_ID`

- Lists artifacts attached to one memory.

#### `kleos-cli artifact get ARTIFACT_ID`

- Downloads one artifact by ID.

#### `kleos-cli artifact delete ARTIFACT_ID`

- Deletes one artifact by ID.

#### `kleos-cli artifact search QUERY`

- Runs full-text search across artifact names and extracted content.

#### `kleos-cli artifact stats`

- Reports aggregate artifact storage statistics.

### Admin operations

These require admin role, signed requests, and expect long-running maintenance
windows.

#### `kleos-cli admin backfill-chunks`

- Backfills missing primary and chunk embeddings across all tenants.

#### `kleos-cli admin rebuild-fts`

- Rebuilds the FTS5 index across tenant databases.

#### `kleos-cli admin vector-rebuild-index`

- Rebuilds the Lance ANN index over current vectors.

#### `kleos-cli admin vector-chunk-sync`

- Rebuilds the per-chunk LanceDB index from existing SQLite rows.

#### `kleos-cli admin vector-health`

- Reports Lance, FTS, and per-tenant vector health.

#### `kleos-cli admin vector-sync-replay`

- Drains the `vector_sync_pending` ledger.

## `kleos-sh`

Synopsis:

```bash
kleos-sh -c "command"
kleos-sh --gate-only -c "command"
kleos-sh --claude-hook
```

Purpose:

- Universal shell gate for agent commands.
- Runs command proposals through Kleos policy before execution.
- Can act as a normal executor or as a Claude `PreToolUse` hook adapter.

Authentication resolution:

1. `KLEOS_API_KEY`
2. `EIDOLON_KEY`
3. Phylax/credd bootstrap flow using `CREDD_SOCKET` and `CREDD_AGENT_KEY`
4. legacy fallback: `cred get kleos <slot> --raw`

Execution model:

- Normal mode: checks a command, optionally enriches it, then executes it.
- `--gate-only`: checks and exits without execution.
- `--claude-hook`: reads hook JSON from stdin, emits hook JSON to stdout, and
  always exits `0`; the allow or deny decision is carried in JSON.

Failure policy:

- Hook mode defaults to fail open.
- Direct execution mode defaults to fail closed.
- Override with `KLEOS_SH_FAIL_OPEN=1` or `0`.

Important options:

- `-c`: command string
- `--agent`: agent identity label, default `claude-code`
- `--tool-name`: reported tool name, default `Bash`
- `--gate-only`
- `--claude-hook`

Important env:

- `KLEOS_SERVER_URL`, `KLEOS_URL`, `ENGRAM_EIDOLON_URL`, `EIDOLON_URL`
- `KLEOS_SIDECAR_URL`
- `KLEOS_SH_TIMEOUT_SECS`
- `KLEOS_CRED_KEY`
- `KLEOS_AGENT_SLOT`
- `PHYLAXD_URL`
- `CREDD_URL`
- `CREDD_SOCKET`
- `CREDD_AGENT_KEY`

Side effects:

- On allow, executes the resolved command and reports completion to the sidecar.
- On deny in normal mode, exits `2`.
- On deny in hook mode, emits Claude hook deny JSON.

## `kr`, `kw`, `ke`

These are the `kleos-fs` binaries. The behavior depends on the invoked binary name.

### `kr`

Synopsis:

```bash
kr PATH [--symbol NAME]
```

Purpose:

- Read files for agents.
- For large code files, prefer structure-aware output through `agent-forge`.

How it works:

- Resolves `~/` and canonicalizes the path.
- Small files and non-code files are read directly.
- Code files larger than 8192 bytes are routed through `agent-forge`:
  - `repo-map` when reading a file generally
  - `search-code` when `--symbol` is passed
- If `agent-forge` fails, `kr` falls back to raw file output unless
  `KLEOS_FS_NO_FALLBACK` disables that fallback.

Important env:

- `AGENT_FORGE_BIN`
- `KLEOS_FS_TRUST_PATH`

### `kw`

Synopsis:

```bash
kw [--mkdir] PATH < content
```

Purpose:

- Write exact stdin content to a file under approved roots.

How it works:

- Allowed roots come from `KLEOS_FS_ALLOWED_ROOTS`.
- If that env var is unset, the current working directory is the only allowed root.
- New parent directories are created only with `--mkdir`.
- Writes outside allowed roots are blocked.
- On success, reports an observation event.

Use for:

- Direct file replacement from controlled stdin content.

### `ke`

Synopsis:

```bash
ke PATH
```

Purpose:

- Edit permission gate, not an editor.
- Confirms that a file has a matching spec-task ledger entry before editing.

How it works:

- Uses the same root allowlist as `kw`.
- Builds a ledger key from `KLEOS_SESSION_ID` or `CLAUDE_SESSION_ID` plus path.
- Checks the scratchpad ledger for a matching spec-task entry.
- If the ledger is missing, it blocks and instructs you to run
  `agent-forge ... spec-task`.
- If the server is unavailable, it fails closed unless
  `KLEOS_FS_ALLOW_OFFLINE_EDIT=1`.

Use for:

- Pre-edit validation in guarded workflows.

## `agent-forge`

Synopsis:

```bash
agent-forge --input in.json --output out.json [--db ~/.agent-forge/forge.db] COMMAND
```

Purpose:

- Structured reasoning, code review, and workflow enforcement tool.
- All commands read JSON input and write JSON output.

### Local MCP and Fluency

Build the local MCP server with Fluency enabled:

```bash
cargo build -p agent-forge --features fluency --bin agent-forge-mcp
```

Register `agent-forge-mcp --db ~/.agent-forge/forge.db` as a stdio MCP server.
It exposes 19 mandatory code-work tools covering specs, approaches,
hypotheses, learning, verification, review, checkpoint and rollback, and the
completion gates against one local database. `recall_errors` and
`session_recall` make prior failures and reusable discoveries available before
the next implementation decision.
`checkpoint` and `review` remain local because they inspect the active Git
checkout and write `docs/agent-forge/` inside that checkout; the remote Kleos
MCP continues to own shared memory, activity, and coordination.

MCP calls that inspect or mutate a repository require an explicit `repo_root`.
Git snapshots, rollback, emitted slices, reviews, and session diffs all use that
same root even when a client launches the server from another directory. The
database scopes checkpoint names by canonical Git root. Pre-upgrade checkpoint
rows are retained as historical evidence but must be recreated before rollback.
The stdio transport enforces initialization before tool calls, accepts JSON-RPC
batches after initialization, and reports failed Agent-Forge outputs with MCP
`isError: true`.

Fluency emission fails closed when rendered evidence contains a concrete local
user-home path. Verification commands intended for public records must use
repository-relative paths.

The MCP binary requires the `fluency` feature. This keeps documentation
emission opt-in for normal `agent-forge` builds while ensuring a configured
local MCP server cannot silently advertise a workflow that lacks `review`.

Output contract:

- The output file always receives a structured result.
- Successful commands usually return `success=true`, a message, and optional `data`.

### Workflow commands

#### `agent-forge spec-task`

Required input:

- `task_description`
- `task_type` in `feature`, `bugfix`, `refactor`, `enhancement`, `test`, `docs`
- at least 2 `acceptance_criteria`
- `interface_contract`
- at least 3 `edge_cases`

What it does:

- Creates a new active spec record.
- Marks the session active against that spec.

Use before:

- New code, non-trivial edits, refactors, and test additions.

#### `agent-forge consider-approaches`

Required input:

- `problem`
- `approaches`: array of 2+ items, each with `name`, `description`, optional `pros`, `cons`, `score`
- optional `spec_id` (links to existing spec)
- optional `chosen_index` (which approach was selected)

What it does:

- Records evaluated approaches in the forge database.
- If `chosen_index` is set, marks that approach as chosen.
- Returns a comparison prompt for the agent to reason through.

#### `agent-forge log-hypothesis`

Required input:

- `bug_description`
- `hypothesis`
- optional `confidence` from `0.0` to `1.0`
- optional `spec_id` (links hypothesis to a spec)

What it does:

- Records a debugging hypothesis.
- If `spec_id` is set, the hypothesis appears in `get-spec` output.

#### `agent-forge log-outcome`

Required input:

- `hypothesis_id`
- `outcome` in `correct`, `incorrect`, `partial`

What it does:

- Marks whether a previous hypothesis was right.

#### `agent-forge recall-errors`

Input:

- optional `query`
- optional `limit`, from 1 to 100

What it does:

- Searches past hypotheses and outcomes.

#### `agent-forge verify`

Required input (one of):

- `command` -- single command to run
- `steps` -- array of `{command, expected_exit_code?, label?}` for multi-step verification
- Both may be provided; `command` runs first, then `steps`

Optional:

- `expected_exit_code`, default `0` (for single `command`)
- `timeout_secs` -- kill the process if it exceeds this duration
- `spec_id` -- link verification results to a spec (records to `verifications` table)
- `criteria_index` -- which acceptance criterion this verification covers
- `skill_id` -- record pass/fail to Kleos skill execution tracking

What it does:

- Executes each step without a shell (SEC-C1).
- Tracks duration_ms per step.
- Records results to the `verifications` table when `spec_id` is provided.
- Returns per-step results with exit code, stdout, stderr, duration.

Use after:

- Code changes or repair attempts.
- Multi-step: run tests AND check types AND lint in one call.

#### `agent-forge challenge-code`

Required input:

- `file_path`
- optional `focus_areas`

What it does:

- Reads a file and returns an adversarial review prompt plus metadata.

#### `agent-forge comment-check`

Required input:

- `file_path`

What it does:

- Scans one source file for declarations missing a leading comment.
- Reports total declarations, documented declarations, missing declarations,
  coverage, and the exact undocumented items.
- Supports Rust, Python, and common C-family extensions used in the Kleos
  workspace.

#### `agent-forge checkpoint`

Required input:

- `name`

What it does:

- Records a checkpoint and current git `HEAD`.

#### `agent-forge rollback`

Required input:

- `checkpoint_name`

What it does:

- Looks up the checkpoint git ref and performs `git checkout` to that ref.

Use with care:

- This is operationally destructive to the current checkout state.

#### `agent-forge session-learn`

Required input:

- `discovery`

Optional:

- `context`
- `tags`
- `spec_id` (links learning to a spec)
- `capture_as_skill` (boolean) -- if true, also captures the discovery as a Kleos skill

What it does:

- Stores a session learning note in the forge database.
- If `spec_id` is set, the learning appears in `get-spec` output.
- If `capture_as_skill` is true and Kleos is reachable, creates a skill from the discovery.

#### `agent-forge session-recall`

Input:

- optional `query`
- optional `limit`

What it does:

- Recalls prior session learnings.

#### `agent-forge session-diff`

Input:

- optional `base`, default `HEAD~10`

What it does:

- Runs `git diff --stat` and `git diff --name-only` against the base ref.

#### `agent-forge think`

Required input:

- `problem`

Optional:

- `constraints`
- `context`

What it does:

- Produces a structured reasoning prompt.

#### `agent-forge declare-unknowns`

Required input:

- `unknowns`: one or more `{description, blocking, resolution_hint?}`

What it does:

- Separates blocking from non-blocking unknowns.
- Explicitly tells the operator to stop if blocking unknowns exist.

### Code-structure commands

#### `agent-forge repo-map`

Required input:

- `path`

Optional:

- `focus`
- `max_tokens`

What it does:

- Walks the repo respecting `.gitignore`.
- Parses supported source files with Tree-sitter.
- Emits a ranked symbol map within a token budget.

#### `agent-forge search-code`

Required input:

- `query`

Optional:

- `path`
- `symbol_type`
- `limit`

What it does:

- Searches symbol names across supported source files.
- Returns file, line, column, symbol kind, and line context.

### Spec lifecycle commands

#### `agent-forge update-spec`

Required input:

- `spec_id`
- `status` in `active`, `completed`, `failed`, `blocked`

Optional:

- `note` -- reason for the status change

What it does:

- Updates the spec status. Sets `completed_at` timestamp for `completed` and `failed`.

Use when:

- A task is done, abandoned, or blocked. Closes the protocol loop.

#### `agent-forge list-specs`

Optional input:

- `status` -- filter by status
- `limit` -- max results, default 20

What it does:

- Lists specs with id, description, type, status, timestamps.

#### `agent-forge get-spec`

Required input:

- `spec_id`

What it does:

- Returns the full spec plus all related hypotheses, approaches, learnings, and verifications.
- This is the cross-reference view -- everything linked to a single task.

### Stats command

#### `agent-forge stats`

Optional input:

- `days` -- look-back window, default 30

What it does:

- Queries across all tables and returns a protocol health dashboard:
  - Spec completion rate (completed/total)
  - Hypothesis accuracy (correct/resolved)
  - Verification pass rate (passed/total)
  - Average hypothesis confidence
  - Average verification duration
  - Top error patterns (most common bug descriptions)
  - Task type distribution
  - Learning, approach, and checkpoint counts

### Skill integration commands

These commands connect agent-forge to the Kleos skill evolution system.
They require a running Kleos server (`KLEOS_URL` and `KLEOS_API_KEY` env vars).

#### `agent-forge skill-search`

Required input:

- `query`

Optional:

- `limit`

What it does:

- Searches Kleos skills by keyword/semantic query.
- Use before `spec-task` to find relevant existing skills.

#### `agent-forge skill-capture`

Required input:

- `description` (max 2000 chars)

Optional:

- `agent`

What it does:

- Creates a new Kleos skill from a freeform workflow description.
- The Kleos LLM generates name, description, and reusable code.

#### `agent-forge skill-record-exec`

Required input:

- `skill_id`
- `success` (boolean)

Optional:

- `duration_ms`
- `error_type`
- `error_message`

What it does:

- Records an execution result against a Kleos skill.
- Builds trust scores over time.

#### `agent-forge skill-fix`

Required input:

- `skill_id`

Optional:

- `hint`

What it does:

- Triggers fix evolution on a failing skill.
- The Kleos LLM analyzes recent failures and generates a fixed version.

#### `agent-forge skill-derive`

Required input:

- `parent_ids` (array of skill IDs, at least one)
- `direction` (max 2000 chars)

Optional:

- `agent`

What it does:

- Combines parent skills into a new derived skill guided by the direction hint.

#### `agent-forge skill-lineage`

Required input:

- `skill_id`

What it does:

- Returns the evolution chain (parent IDs) for a skill.

## `cred`

Synopsis:

```bash
cred COMMAND ...
```

Purpose:

- Local YubiKey-backed credential vault and bootstrap helper.

Core commands:

- `cred init`: first-time YubiKey challenge-response setup and recovery kit creation.
- `cred store SERVICE KEY [-t TYPE]`: interactive secret storage.
- `cred get SERVICE KEY [-f FIELD] [--raw]`: retrieve one secret or field.
- `cred list [--service NAME]`: list redacted secrets.
- `cred delete SERVICE KEY [-y]`: delete one secret.
- `cred import [-n]`: bulk import from stdin.
- `cred export`: export vault data.
- `cred recover [--from PATH]`: recover onto a replacement YubiKey.
- `cred exec SERVICE KEY [--field FIELD] [--env VAR|--stdin] -- COMMAND ...`: inject a secret into a child process.
- `cred agent-key ...`: manage DB-backed and bootstrap-scoped agent keys.
- `cred bootstrap wrap|unwrap`: manage `bootstrap.enc` for `credd`.
- `cred piv ...`: manage YubiKey PIV bootstrap keys.
- `cred ssh-ca ...`: mint or sign short-lived SSH certificates.
- `cred tui`: interactive terminal UI.

How it works:

- Derives the vault master key from a persisted challenge plus YubiKey
  HMAC-SHA1 slot 2 response.
- Uses encrypted local storage plus optional bootstrap blobs and agent-key files.

Deep reference:

- [kleos-cred/MANUAL.md](../kleos-cred/MANUAL.md)

## `credd`

Synopsis:

```bash
credd [--listen ADDR] [--db-path PATH] [--auth-mode yubikey|password]
```

Purpose:

- Credential daemon that brokers per-agent Kleos bearers and serves secrets.

How it works:

- Derives its master key from YubiKey or password.
- Loads `bootstrap.enc` if present.
- Loads bootstrap-scoped file-backed agent keys.
- Opens the credential DB and serves HTTP or socket-based clients.

Important surfaces:

- `GET /bootstrap/kleos-bearer?agent=<slot>`
- `POST /resolve/text`
- `POST /resolve/proxy`
- `POST /resolve/raw`
- `GET /secret/{category}/{name}`
- `GET/POST/DELETE` agent-key management endpoints

Deep reference:

- [kleos-credd/MANUAL.md](../kleos-credd/MANUAL.md)

## `kleos-sidecar`

Synopsis:

```bash
kleos-sidecar [--config sidecar.toml] [--port N] [--host HOST] \
  [--code-context-mode off|shadow|inject] [--code-max-tokens N]
```

Purpose:

- Local batching proxy for observations, session traffic, and deterministic
  repository context selected from Agent-Forge's persistent syntax index.

Config precedence:

- CLI flag
- env var
- config file
- built-in default

Important options:

- `--config`
- `--port`, default `7711`
- `--host`, default `127.0.0.1`
- `--session-id`
- `--source`
- `--user-id`
- `--token`
- `--kleos-url`
- `--kleos-api-key`
- `--code-context-mode`, default `shadow`
- `--code-max-tokens`, default `2000`
- batch sizing, retention, idle TTL, and log format controls

Code-context modes:

- `off` disables index refresh and retrieval.
- `shadow` refreshes and measures selected snippets but does not add them to
  prompt context.
- `inject` adds high-confidence snippets under the separate code token budget.

How it works:

- Generates a bearer token at startup if one is not supplied.
- Queues observations per session and flushes them in batches.
- Uses session-start, post-tool, and user-prompt hooks to refresh changed Git
  repositories and retrieve bounded snippets.
- Serializes refresh writes, coalesces duplicate refreshes for the same
  repository, and serves prompts from the latest completed index revision.
- Revalidates source hashes before direct ranking or relation expansion, so a
  changed file cannot seed stale graph context while refresh is in progress.
- Stores the code index locally in SQLite. Bulk indexed source is never sent to
  Kleos memory endpoints.
- Suppresses unchanged repeated snippets in inject mode unless the prompt names
  the exact symbol or the underlying file changed.

## `kleos-server`

Synopsis:

```bash
kleos-server
```

Purpose:

- Main Kleos HTTP API server and background worker host.

How it works at startup:

1. Loads env-based config.
2. Resolves database encryption mode.
3. Connects to SQLite and tenant shards.
4. Starts metrics.
5. Loads embeddings and reranker in the background.
6. Probes local LLM availability.
7. Starts background jobs, dreamer, cleanup, and replay workers.
8. Serves the HTTP API, GUI, and related routes.

Operational notes:

- Default bind is `127.0.0.1:4200`.
- Initial bootstrap key flow is separate from normal auth.
- Multi-user tenant sharding is enabled by default.
- `KLEOS_SESSION_KEY` -- 32-byte hex HMAC key for the session manager
  (`kleos-lib/src/auth_piv.rs`) that lets a PIV/soft-signed identity avoid
  re-signing every request. If unset, the server generates an ephemeral key at
  startup and logs a warning; sessions minted under that key do not survive a
  restart. Set it explicitly for any deployment that should keep sessions alive
  across restarts. Generate one with `openssl rand -hex 32`.
- A from-source systemd unit template is provided at
  `dist/kleos-server.service` for running the server as a long-lived service.

Optional GUI-population flags (all default-off; behavior is byte-identical to
prior releases when unset):

- `KLEOS_PROJECTS_DERIVE_ENABLED=1` -- the Memory > Projects tab augments the
  explicit `projects` rows with projects derived from distinct `tasks.project`
  values (Chiasm activity), scoped to the caller. Derived cards show the task
  count and are never persisted. Use this when you tag activity with
  `--project` but do not curate explicit project records.
- `KLEOS_REVIEW_GATE_ENABLED=1` plus `KLEOS_REVIEW_GATE_SOURCES=src1,src2,...`
  -- newly stored memories whose `source` is in the comma-separated allowlist
  are written with `status='pending'` so they land in the Memory > Inbox
  (Review) queue for approve/reject instead of being auto-approved. Sources not
  listed (and all stores when the allowlist is empty) stay `approved`, so
  explicit `memory_store` calls are never gated unless you opt their source in.
  While pending, a memory is withheld from recall, search, and listings (the
  `include_pending` opt-in surfaces it for the Inbox view) and only becomes
  recallable once approved. The gate is off by default, so a fresh install
  behaves byte-identically to releases without it: nothing is held for review.

## `kleos-mcp`

Synopsis:

```bash
kleos-mcp [--transport stdio|http]
```

Purpose:

- Exposes Kleos capabilities to LLM clients over MCP.

How it works:

- Loads `KLEOS_URL` and local auth from the normal Kleos client environment.
- Refuses to start unless either a signing identity or `KLEOS_API_KEY` bearer
  fallback is configured.
- Starts stdio transport by default and forwards JSON-RPC requests to the
  server-side `POST /mcp` endpoint.
- When compiled with the `http` feature, also accepts `--listen ADDR` and can
  serve `/mcp` itself as a thin HTTP bridge.

Current MCP model:

- `kleos-mcp` is a transport adapter, not a separate tool implementation layer.
- The curated daily-driver registry is defined in `kleos-mcp/src/tools.rs` and
  reused by both `tools/list` and `GET /mcp/schema`.
- Prefer dotted tool names such as `memory.search` or `activity.report`.
  Underscore and `services.*` variants are compatibility aliases.
- The curated surface intentionally excludes admin, generated long-tail, graph,
  GUI, and stale helper routes such as `mcp_schema.dispatch`.

HTTP transport note:

- The optional HTTP transport has no front-door client auth of its own.
- Reachability is the trust boundary, so bind it only to loopback, private LAN,
  or mesh/VPN interfaces.

## `eidolon-supervisor`

Synopsis:

```bash
eidolon-supervisor
```

Purpose:

- Watches session logs for policy drift, rule violations, and retry loops.

How it works:

- Watches `CLAUDE_SESSIONS_DIR`, default `~/.claude/projects`.
- Loads rules from `EIDOLON_SUPERVISOR_CONFIG` or uses built-in defaults.
- Posts alerts and supervisor injections back to Kleos.

Important env:

- `CLAUDE_SESSIONS_DIR`
- `KLEOS_SERVER_URL`
- `KLEOS_API_KEY`
- `EIDOLON_SUPERVISOR_CONFIG`

## Recommended agent workflow

For day-to-day agent work, default to this sequence:

1. `kleos-cli search` or `kleos-cli context` before asking a human.
2. `agent-forge spec-task` before non-trivial code changes.
3. `agent-forge consider-approaches` when multiple paths exist.
4. `kr` to read code and `kw` only for bounded direct writes.
5. `ke` before an edit path that is supposed to be spec-gated.
6. `kleos-sh` or provider hook integration for shell actions that must go
   through the gate.
7. `agent-forge verify` after code changes (use `steps` for multi-step).
8. `agent-forge update-spec` to mark the spec completed/failed/blocked.
9. `agent-forge session-learn` for reusable discoveries (with `capture_as_skill: true` when appropriate).
10. `kleos-cli store` or `kleos-cli handoff dump/mechanical` at task boundaries.
11. `agent-forge stats` periodically to review protocol health.

## Rule of precedence

If command behavior here and ad hoc prompt instructions disagree, prefer:

1. Actual command implementation
2. This manual
3. Ad hoc prompt text

When in doubt, inspect the source before inventing a new usage pattern.
