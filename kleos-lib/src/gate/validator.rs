use crate::config::Config;

pub fn check_blocked_patterns(command: &str, blocked_patterns: &[String]) -> Option<String> {
    let command_lower = command.to_lowercase();
    for pattern in blocked_patterns {
        let trimmed = pattern.trim();
        if trimmed.is_empty() {
            continue;
        }
        if command_lower.contains(&trimmed.to_lowercase()) {
            return Some(format!("Command matched blocked pattern: {}", trimmed));
        }
    }
    None
}

/// Check a command against static dangerous patterns.
/// Returns Some(reason) if the command is blocked, None if it is allowed.
///
/// Ported from Eidolon gate.rs -- covers destructive rm, force push, hard reset,
/// reboot/shutdown, seed data, protected services, interpreter inline execution,
/// encoding-bypass obfuscation, variable indirection, DROP TABLE, and mkfs.
pub fn check_dangerous_patterns(command: &str, config: &Config) -> Option<String> {
    let cmd_lower = command.to_lowercase();

    // Destructive rm patterns
    if cmd_lower.contains("rm -rf /") && !cmd_lower.contains("rm -rf /tmp") {
        return Some("Destructive rm -rf on critical path - not allowed".to_string());
    }
    if cmd_lower.contains("rm -rf ~/") {
        return Some("Destructive rm -rf on home directory - not allowed".to_string());
    }
    if cmd_lower.contains("rm -rf /home") {
        return Some("Destructive rm -rf on /home - not allowed".to_string());
    }
    if cmd_lower.contains("rm -rf /var") {
        return Some("Destructive rm -rf on /var - not allowed".to_string());
    }
    if cmd_lower.contains("rm -rf /etc") {
        return Some("Destructive rm -rf on /etc - not allowed".to_string());
    }
    if cmd_lower.contains("rm -rf /usr") {
        return Some("Destructive rm -rf on /usr - not allowed".to_string());
    }
    if cmd_lower.contains("rm -rf /opt") {
        return Some("Destructive rm -rf on /opt - not allowed".to_string());
    }
    if cmd_lower.contains("rm -rf /boot") {
        return Some("Destructive rm -rf on /boot - not allowed".to_string());
    }

    // Force push to protected branches
    if cmd_lower.contains("git push")
        && cmd_lower.contains("--force")
        && (cmd_lower.contains("main") || cmd_lower.contains("master"))
    {
        return Some("Force push to main/master branch blocked".to_string());
    }

    // Hard reset
    if cmd_lower.contains("git reset --hard") {
        return Some("git reset --hard is destructive - use git stash instead".to_string());
    }

    // Reboot/shutdown: check servers with no_reboot flag
    if cmd_lower.contains("reboot") || cmd_lower.contains("shutdown") {
        for server in &config.eidolon.gate.servers {
            if server.no_reboot {
                let name_match = cmd_lower.contains(&server.name.to_lowercase());
                let alias_match = server
                    .aliases
                    .iter()
                    .any(|a| cmd_lower.contains(&a.to_lowercase()));
                if name_match || alias_match {
                    let notes = if server.notes.is_empty() {
                        String::new()
                    } else {
                        format!(" - {}", server.notes)
                    };
                    return Some(format!(
                        "Reboot/shutdown of {} blocked{}",
                        server.name, notes
                    ));
                }
            }
        }
        // Generic reboot/shutdown block when no server inventory is configured
        if config.eidolon.gate.servers.is_empty() {
            return Some("Reboot/shutdown commands require explicit confirmation".to_string());
        }
    }

    // Seed data in production -- prevent seeding demo/sample/insert into prod
    if cmd_lower.contains("seed") {
        if cmd_lower.contains("demo") {
            return Some(
                "Seeding demo data blocked - do not seed demo data into any instance without explicit authorization".to_string(),
            );
        }
        if cmd_lower.contains("production") || cmd_lower.contains("prod") {
            return Some(
                "Seeding production data blocked - do not seed real data into production without explicit authorization".to_string(),
            );
        }
    }
    if (cmd_lower.contains("sample") || cmd_lower.contains("demo"))
        && looks_like_sql_seed(&cmd_lower)
    {
        return Some("Inserting sample/demo data requires explicit authorization".to_string());
    }

    // Stop/restart protected services
    if cmd_lower.contains("systemctl stop")
        || cmd_lower.contains("systemctl restart")
        || cmd_lower.contains("podman stop")
        || cmd_lower.contains("docker stop")
    {
        for svc in &config.eidolon.gate.protected_services {
            if cmd_lower.contains(&svc.to_lowercase()) {
                return Some(format!(
                    "Stopping/restarting protected service {} requires explicit confirmation",
                    svc
                ));
            }
        }
    }

    // Secondary interpreter / encoding bypass detection
    // These can be used to smuggle dangerous commands past substring checks
    let tokens: Vec<&str> = cmd_lower.split_whitespace().collect();
    {
        for (i, token) in tokens.iter().enumerate() {
            // python/python3 -c, perl/perl5 -e, ruby -e
            // Also catch full-path invocations like /usr/bin/python3 and env-wrapped calls
            let basename = token.rsplit('/').next().unwrap_or(token);
            let is_interpreter = basename == "python"
                || basename == "python3"
                || basename.starts_with("python3.")
                || basename == "perl"
                || basename == "perl5"
                || basename == "ruby";
            // Also catch: env python3 -c
            let is_env_interpreter = *token == "env" && i + 2 < tokens.len() && {
                let next = tokens[i + 1];
                let next_base = next.rsplit('/').next().unwrap_or(next);
                next_base == "python"
                    || next_base == "python3"
                    || next_base.starts_with("python3.")
                    || next_base == "perl"
                    || next_base == "perl5"
                    || next_base == "ruby"
            };
            if is_interpreter {
                if let Some(flag) = tokens.get(i + 1) {
                    if *flag == "-c" || *flag == "-e" {
                        return Some(format!(
                            "Inline code execution via {} {} blocked - use a script file instead",
                            token, flag
                        ));
                    }
                }
            }
            if is_env_interpreter {
                // env python3 -c => flag is at i+2
                if let Some(flag) = tokens.get(i + 2) {
                    if *flag == "-c" || *flag == "-e" {
                        return Some(format!(
                            "Inline code execution via env {} {} blocked - use a script file instead",
                            tokens[i + 1], flag
                        ));
                    }
                }
            }

            // eval with command substitution or string argument
            if *token == "eval" && i + 1 < tokens.len() {
                return Some(
                    "eval command blocked - potential command injection vector".to_string(),
                );
            }
        }

        // base64 decode piped to sh/bash (base64 -d, base64 --decode, base64 -D)
        let has_base64_decode =
            cmd_lower.contains("base64 -d") || cmd_lower.contains("base64 --decode");
        let has_shell_pipe = cmd_lower.contains("| sh")
            || cmd_lower.contains("| bash")
            || cmd_lower.contains("|sh")
            || cmd_lower.contains("|bash")
            || cmd_lower.contains("| /bin/sh")
            || cmd_lower.contains("| /bin/bash");
        if has_base64_decode && has_shell_pipe {
            return Some(
                "base64 decode piped to shell blocked - potential command obfuscation".to_string(),
            );
        }

        // xxd -r piped to shell
        if cmd_lower.contains("xxd -r") && has_shell_pipe {
            return Some(
                "hex decode piped to shell blocked - potential command obfuscation".to_string(),
            );
        }

        // printf with octal/hex escapes piped to shell
        if cmd_lower.contains("printf")
            && (cmd_lower.contains("\\x") || cmd_lower.contains("\\0"))
            && has_shell_pipe
        {
            return Some(
                "printf escape sequence piped to shell blocked - potential command obfuscation"
                    .to_string(),
            );
        }
    }

    // Variable indirection: assignment of dangerous commands to variables
    // Catches: R="rm"; $R -rf / and CMD=rm; $CMD -rf /
    {
        let dangerous_cmds = ["rm", "mkfs", "dd", "shutdown", "reboot", "kill", "pkill"];
        for cmd in &dangerous_cmds {
            let patterns = [
                format!("=\"{}\"", cmd),
                format!("='{}'", cmd),
                format!("={};", cmd),
                format!("={} ", cmd),
                format!("={}&", cmd),
            ];
            if patterns.iter().any(|p| cmd_lower.contains(p)) && cmd_lower.contains('$') {
                return Some(format!(
                    "Shell variable indirection constructing '{}' command blocked",
                    cmd
                ));
            }
        }

        // Backtick command substitution targeting destructive commands
        if cmd_lower.contains('`') {
            let dangerous_cmds_bt = ["rm", "mkfs", "dd", "shutdown", "reboot"];
            for cmd in &dangerous_cmds_bt {
                if cmd_lower.contains(&format!("`echo {}`", cmd))
                    || cmd_lower.contains(&format!("`printf {}`", cmd))
                {
                    return Some(format!(
                        "Command substitution constructing '{}' blocked",
                        cmd
                    ));
                }
            }
        }
    }

    // Extended interpreter coverage: node, deno, lua, php, etc.
    {
        for (i, token) in tokens.iter().enumerate() {
            let basename = token.rsplit('/').next().unwrap_or(token);

            let is_extra_interpreter = matches!(
                basename,
                "node" | "nodejs" | "deno" | "bun" | "lua" | "luajit" | "php" | "tclsh" | "wish"
            ) || basename.starts_with("lua5.")
                || basename.starts_with("php8.");

            if is_extra_interpreter {
                if let Some(flag) = tokens.get(i + 1) {
                    if *flag == "-e"
                        || *flag == "-r"
                        || *flag == "eval"
                        || *flag == "--eval"
                        || *flag == "-c"
                    {
                        return Some(format!(
                            "Inline code execution via {} {} blocked - use a script file",
                            token, flag
                        ));
                    }
                }
            }
        }
    }

    // Drop table / format destructors
    if cmd_lower.contains("drop table") {
        return Some("DROP TABLE statement requires manual confirmation".to_string());
    }
    if cmd_lower.contains("drop database") {
        return Some("DROP DATABASE statement requires manual confirmation".to_string());
    }
    if cmd_lower.contains("mkfs.") || cmd_lower.contains("mkfs ") {
        return Some("Disk format command blocked - requires manual confirmation".to_string());
    }

    None
}

/// Return whether a lowercased command contains an SQL seeding statement
/// (`insert into`, `create table`, `create database`, `create schema`).
/// The sample/demo rule used to fire on the bare words "insert" and "create",
/// which also match ordinary prose such as "created for" in a runbook being
/// written to disk, so the match is narrowed to statement shapes.
fn looks_like_sql_seed(cmd_lower: &str) -> bool {
    // Shell quoting glues punctuation to the keywords (`"insert`, `'create`),
    // so strip everything that is not a word character before matching.
    let words: Vec<&str> = cmd_lower
        .split_whitespace()
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric() && c != '_'))
        .collect();
    words.windows(2).any(|pair| {
        matches!(
            (pair[0], pair[1]),
            ("insert", "into")
                | ("create", "table")
                | ("create", "database")
                | ("create", "schema")
        )
    })
}
