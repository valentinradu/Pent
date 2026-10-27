//! macOS sandbox implementation using sandbox-exec and SBPL profiles.
//!
//! Uses Apple's Seatbelt sandbox via the `sandbox-exec` command.
//! Generates SBPL (Sandbox Profile Language) profiles at runtime.
//!
//! # SBPL Profile Structure
//!
//! Uses `(allow default)` as baseline with selective denies:
//! ```text
//! (version 1)
//! (allow default)
//! (deny file-read* (subpath "/System"))
//! (deny file-read* (subpath "/Users"))
//! (allow file-read* (subpath "/Users/name/.claude"))
//! (deny file-write* (subpath "/System"))
//! (deny file-write* (subpath "/Users/name/project/.pent"))
//! ```
//!
//! When more than one rule matches an operation, the last rule wins.
//!
//! Each path goes into the profile as a quoted SBPL string. The generator
//! escapes backslashes and double quotes, so a path cannot add rules.
//!
//! # Network
//!
//! In proxy mode the profile denies `network-outbound` and allows only the
//! proxy port on loopback, the `mDNSResponder` socket and the Unix sockets
//! in the writable paths. A program that ignores the proxy variables cannot
//! connect to a remote host.
//!
//! # Watch mode
//!
//! [`generate_watch_profile`] makes a profile that allows each operation
//! with `(with report)` and denies only the guard accesses. The module
//! `macos_log` reads the reports from `log stream`.
//!
//! # Note
//! sandbox-exec is deprecated by Apple but still functional.
//! No lightweight alternative exists for process sandboxing on macOS.

use crate::{LocalhostPorts, NetworkMode, SandboxConfig, SandboxError};
use std::path::{Path, PathBuf};

/// Check if sandbox-exec is available on this system.
///
/// # Errors
/// Returns `SandboxUnavailable` if sandbox-exec is not found.
pub fn check_available() -> Result<(), SandboxError> {
    #[cfg(target_os = "macos")]
    {
        if Path::new("/usr/bin/sandbox-exec").exists() {
            Ok(())
        } else {
            Err(SandboxError::SandboxUnavailable {
                reason: "sandbox-exec not found at /usr/bin/sandbox-exec".to_string(),
                remediation: "This should not happen on macOS. Check system integrity.".to_string(),
            })
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(SandboxError::UnsupportedPlatform)
    }
}

/// Make sure that a path string can go into an SBPL string literal.
///
/// The profile generator quotes and escapes each string (see
/// [`sbpl_string`]), so the SBPL structural characters `(`, `)`, `;`, `"`
/// and `\` are safe in a path. A workspace with the name `proj (copy)` is
/// valid. Only NUL and newline are rejected: the sandbox library reads the
/// profile as a C string, which ends at NUL, and a newline in a path is
/// almost always an error.
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if the text contains NUL or a newline.
fn validate_sbpl_text(text: &str) -> Result<(), SandboxError> {
    if let Some(ch) = text.chars().find(|c| matches!(c, '\0' | '\n')) {
        return Err(SandboxError::InvalidConfig(format!(
            "Path {text:?} contains the character {ch:?}; \
             pent cannot put this path in the sandbox profile"
        )));
    }
    Ok(())
}

/// Quote `text` as an SBPL string literal, with the double quotes.
///
/// SBPL strings use the Scheme escape rules: a backslash starts an escape
/// sequence and a double quote ends the string. This function escapes both
/// characters, so the sandbox library reads back exactly `text`.
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if the text contains NUL or a newline.
fn sbpl_string(text: &str) -> Result<String, SandboxError> {
    validate_sbpl_text(text)?;
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push('"');
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str(r#"\""#),
            other => out.push(other),
        }
    }
    out.push('"');
    Ok(out)
}

/// Translate a glob prefix into an anchored SBPL regex.
///
/// The config loader removes the trailing `*` of a glob entry, so the
/// result matches the pattern and all paths that start with it (there is
/// no `$` anchor). In the remaining text, `**` matches any characters and
/// `*` matches any characters except `/`. All other regex metacharacters
/// are escaped, so they match only themselves.
///
/// The result is a regex, not an SBPL string. Give it to [`sbpl_string`]
/// to escape the backslashes for the SBPL reader.
fn glob_prefix_to_regex(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len().saturating_add(1));
    out.push('^');
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '*' => {
                if chars.peek() == Some(&'*') {
                    chars.next();
                    out.push_str(".*");
                } else {
                    out.push_str("[^/]*");
                }
            }
            '\\' | '.' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

/// The action of one SBPL rule.
#[derive(Clone, Copy)]
enum RuleAction {
    Allow,
    Deny,
}

impl RuleAction {
    const fn keyword(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Add one rule `(<action> <access> (<filter> "<value>"))` to `profile`.
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if `value` contains NUL or a newline.
fn push_rule(
    profile: &mut String,
    action: RuleAction,
    access: &str,
    filter: &str,
    value: &str,
) -> Result<(), SandboxError> {
    push_rule_with(profile, action, access, filter, value, Report::No)
}

/// Add one rule `(<action> <access> (<filter> "<value>")[ (with report)])`
/// to `profile`.
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if `value` contains NUL or a newline.
fn push_rule_with(
    profile: &mut String,
    action: RuleAction,
    access: &str,
    filter: &str,
    value: &str,
    report: Report,
) -> Result<(), SandboxError> {
    let quoted = sbpl_string(value)?;
    profile.push_str(&format!(
        "({} {access} ({filter} {quoted}){})\n",
        action.keyword(),
        report.suffix()
    ));
    Ok(())
}

/// Generate SBPL profile string for the given config.
///
/// Uses `(allow default)` baseline with selective denies, then allows
/// paths from config.paths (traversal, read, read_write).
///
/// # Arguments
/// * `config` - Sandbox configuration with paths
///
/// # Returns
/// SBPL profile as a String
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if a path contains NUL or a newline.
/// All other characters are quoted and escaped, so they cannot change the
/// structure of the profile.
pub fn generate_sbpl_profile(config: &SandboxConfig) -> Result<String, SandboxError> {
    let mut profile = String::new();

    // Header - use allow default as baseline, then selectively deny.
    //
    // We deny file-read-data (file content) globally and re-allow it only for
    // paths the process is permitted to read.  Crucially, we do NOT deny
    // file-read-metadata (stat/lstat/access) globally: the macOS DNS resolution
    // stack (getaddrinfo → mDNSResponder / Network Extension) calls stat() on
    // paths outside the allowlist (VPN sockets, network config databases, etc.)
    // and needs file-read-metadata to succeed everywhere.  Denying all of
    // file-read* broke DNS for every program that uses getaddrinfo().
    //
    // Rule order is important. When more than one rule matches an operation,
    // the last rule in the profile wins. The global denies come first, the
    // allows come after them, and the project-config deny comes last.
    profile.push_str("(version 1)\n");
    profile.push_str("(allow default)\n");
    profile.push_str("(deny file-read-data)\n");
    profile.push_str("(deny file-write*)\n");
    // The child runs only a program in a system directory or in an
    // `execute` path (MAC-4). Without this deny, `(allow default)` lets the
    // child run every program on the machine, and the `execute` list of a
    // profile means nothing. The run of 2026-10-25 on a Mac proved both
    // halves: `(deny process-exec)` after `(allow default)` stops a
    // program, and an `(allow process-exec (subpath ...))` after it lets
    // the programs of that directory run.
    profile.push_str("(deny process-exec)\n");
    // A program that cannot run a file itself can ask another process to
    // run one for it. The two routes out are a launchd job and a Mach
    // service of another program, so the profile closes both (MAC-4).
    add_escape_denies(&mut profile)?;

    // Expand paths from config
    let (traversal, read, execute, read_write) = config.paths.expand_paths();

    // =========================================================================
    // TRAVERSAL PATHS - allow reading the directory entry itself
    // =========================================================================
    for (path, is_glob) in &traversal {
        if *is_glob {
            add_sbpl_glob_rule(&mut profile, path, "file-read-data")?;
        } else {
            push_rule(
                &mut profile,
                RuleAction::Allow,
                "file-read-data",
                "literal",
                &path.to_string_lossy(),
            )?;
        }
    }

    // Add workspace parent directories for realpath traversal
    let mut parent = config.workspace.parent();
    while let Some(p) = parent {
        push_rule(
            &mut profile,
            RuleAction::Allow,
            "file-read-data",
            "literal",
            &canonical_or_original(p),
        )?;
        parent = p.parent();
    }

    // =========================================================================
    // READ PATHS - subpath content access
    // =========================================================================
    for (path, is_glob) in &read {
        if *is_glob {
            add_sbpl_glob_rule(&mut profile, path, "file-read-data")?;
        } else {
            add_sbpl_path_rule(&mut profile, path, "file-read-data")?;
        }
    }

    // =========================================================================
    // EXECUTE PATHS - file content read + process execution
    // =========================================================================
    for (path, is_glob) in &execute {
        if *is_glob {
            add_sbpl_glob_rule(&mut profile, path, "file-read-data")?;
            add_sbpl_glob_rule(&mut profile, path, "process-exec")?;
        } else {
            add_sbpl_path_rule(&mut profile, path, "file-read-data")?;
            // Unconditionally grant process-exec for execute paths (unlike read paths
            // which only add process-exec for individual executable files found on disk).
            let canonical = canonical_or_original(path);
            let original = path.to_string_lossy();
            let modifier = if path.is_file() { "literal" } else { "subpath" };
            push_rule(
                &mut profile,
                RuleAction::Allow,
                "process-exec",
                modifier,
                &canonical,
            )?;
            if original != canonical {
                push_rule(
                    &mut profile,
                    RuleAction::Allow,
                    "process-exec",
                    modifier,
                    &original,
                )?;
            }
        }
    }

    // =========================================================================
    // SYSTEM EXECUTE PATHS - the programs that every command needs
    // =========================================================================
    // With `--trace`, the kernel logs each of these execs. The reader needs
    // them: it checks the name of each report against the program that the
    // process runs, and only an exec report tells it that a process runs a
    // new file (MAC-8). `/bin/sh` runs `/bin/bash` on macOS, so without
    // this report the reader drops each denial of the shell.
    let exec_report = if config.record_events {
        Report::Yes
    } else {
        Report::No
    };
    add_system_exec_allows(&mut profile, exec_report)?;

    // =========================================================================
    // READ-WRITE PATHS - subpath content and write access
    // =========================================================================
    for (path, is_glob) in &read_write {
        if *is_glob {
            add_sbpl_glob_rule(&mut profile, path, "file-read-data file-write*")?;
        } else {
            add_sbpl_path_rule(&mut profile, path, "file-read-data file-write*")?;
        }
    }

    // Workspace - always read/write
    add_sbpl_path_rule(
        &mut profile,
        &config.workspace,
        "file-read-data file-write*",
    )?;

    // TMPDIR if set
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        add_sbpl_path_rule(
            &mut profile,
            Path::new(&tmpdir),
            "file-read-data file-write*",
        )?;
    }

    // =========================================================================
    // PROJECT CONFIG - deny writes to <workspace>/.pent
    // =========================================================================
    // The project config (.pent/pent.toml) controls the sandbox of the next
    // run. The sandboxed process must not change it. These rules come after
    // all allow rules (the workspace, TMPDIR and read_write paths), because
    // the last matching rule wins. Thus they also apply when the workspace
    // is in TMPDIR or a read_write path contains the workspace.
    add_project_config_deny(&mut profile, &config.workspace)?;

    // =========================================================================
    // NETWORK RULES
    // =========================================================================
    let network_rules = generate_network_rules(&config.network, &config.localhost, Report::No);
    if !network_rules.is_empty() {
        profile.push_str(&network_rules);
        profile.push('\n');
    }
    if matches!(config.network, NetworkMode::ProxyOnly { .. }) {
        let tmpdir = std::env::var_os("TMPDIR").map(std::path::PathBuf::from);
        let mut dirs: Vec<&Path> = vec![config.workspace.as_path()];
        dirs.extend(tmpdir.as_deref());
        dirs.extend(
            read_write
                .iter()
                .filter(|(_, is_glob)| !*is_glob)
                .map(|(path, _)| path.as_path()),
        );
        add_unix_socket_allows(&mut profile, &dirs)?;
    }

    Ok(profile)
}

/// The directories of the programs that a command needs, beside the
/// `execute` paths of the profile.
///
/// `(deny process-exec)` stops each program that no rule allows, so the
/// profile must name the directories of the system. The list holds the
/// system program directories, the two Homebrew prefixes, the helper
/// programs of Apple (`/usr/libexec`, among them Rosetta), the programs
/// inside the system frameworks and the developer tools. It is the macOS
/// form of `SYSTEM_PATHS` of the Linux backend, which gets
/// `READ_EXECUTE` there.
///
/// The workspace is not in the list, as on Linux: a program in the
/// workspace runs only with `--execute`.
const SYSTEM_EXEC_PATHS: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/libexec",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/local/libexec",
    "/opt/homebrew",
    "/opt/local",
    "/System",
    "/Library/Apple",
    "/Library/Developer",
    "/Applications/Xcode.app",
];

/// Allow the child to run the programs of the system directories.
///
/// The rules come after `(deny process-exec)`, and the last matching rule
/// wins.
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if a path contains NUL or a
/// newline. Each path of [`SYSTEM_EXEC_PATHS`] is a literal, so the error
/// cannot occur.
fn add_system_exec_allows(profile: &mut String, report: Report) -> Result<(), SandboxError> {
    for dir in SYSTEM_EXEC_PATHS {
        push_rule_with(
            profile,
            RuleAction::Allow,
            "process-exec",
            "subpath",
            dir,
            report,
        )?;
    }
    Ok(())
}

/// The Mach services that the child may look up, and why each one is on
/// the list.
///
/// `(deny mach-lookup)` closes the second route out of the sandbox: the
/// child asks a service of another program to act for it, and that program
/// runs with no profile. The deny is wide, so a program that needs a
/// service of the system stops working. The list therefore holds the
/// services that an ordinary program needs.
///
/// The first group comes from a measurement. The run of 2026-10-25 on
/// `macos-latest` (run 40236253209) ran `/bin/sh`, `/usr/bin/id`,
/// `/bin/ls`, `/usr/bin/curl` and a name lookup of `python3` under
/// `(allow default)(deny mach-lookup)` and read each denial of the unified
/// log. The number in the comment is the count of denials of that service.
/// Each one of the five programs still worked, so the list is a comfort
/// list, not a list of hard needs.
///
/// The second group holds the services that a Mac with a user session and
/// with TLS needs. The runner has no such session, so no denial names
/// them. Each entry says which program needs it.
///
/// A service that is not on the list stays denied, and `pent run -v` prints
/// the profile, so a missing service is one line of a bug report.
const SYSTEM_MACH_SERVICES: &[(&str, &str)] = &[
    // The first group: the services that the measurement named.
    (
        "com.apple.system.opendirectoryd.libinfo",
        "the user and group database (`getpwuid`, `getgrgid`); 12 denials",
    ),
    (
        "com.apple.system.opendirectoryd.membership",
        "the group membership of the user; 6 denials",
    ),
    (
        "com.apple.bsd.dirhelper",
        "the private temporary directory of the user \
         (`confstr(_CS_DARWIN_USER_TEMP_DIR)`); 9 denials",
    ),
    (
        "com.apple.system.notification_center",
        "`notifyd`, which libSystem itself uses; 4 denials",
    ),
    ("com.apple.logd", "the unified log (`os_log`); 3 denials"),
    (
        "com.apple.DiskArbitration.diskarbitrationd",
        "the list of the mounted volumes; 2 denials",
    ),
    (
        "com.apple.SystemConfiguration.configd",
        "the network configuration that `getaddrinfo` reads; 1 denial",
    ),
    (
        "com.apple.CoreServices.coreservicesd",
        "Launch Services and the database of the file types; 1 denial",
    ),
    (
        "com.apple.FSEvents",
        "the stream of the file system events, which a watcher of a \
         project directory reads; 1 denial",
    ),
    (
        "com.apple.distributed_notifications@Uv3",
        "the distributed notification centre; 1 denial. The text after \
         the `@` is a version, so a later macOS can ask for another name.",
    ),
    (
        "com.apple.distributed_notifications@1v3",
        "the earlier version of the name above",
    ),
    // The second group: a Mac with a user session and with TLS. The
    // runner of the pipeline has neither, so no denial names these.
    (
        "com.apple.logd.events",
        "the second port of `logd`, for a program that reads the log",
    ),
    (
        "com.apple.trustd.agent",
        "the trust evaluation of a certificate, which each TLS \
         connection of `git`, of `curl` and of a package manager needs",
    ),
    ("com.apple.trustd", "the system form of the service above"),
    (
        "com.apple.SecurityServer",
        "`securityd` and the Keychain, which `git` reads for a credential",
    ),
    (
        "com.apple.cfprefsd.daemon",
        "the settings of a program (`CFPreferences`)",
    ),
    (
        "com.apple.cfprefsd.agent",
        "the per-user form of the service above",
    ),
];

/// Deny the two routes by which the child makes another process run a
/// program for it.
///
/// `(deny process-exec)` stops the child from running a file itself. Two
/// routes stay open after it:
///
/// - a launchd job. `(deny job-creation)` closes it. The run of 2026-10-25
///   measured that macOS already refuses a job of a sandboxed process,
///   also under a profile with no deny at all, so this rule is the second
///   layer, not the only one.
/// - a Mach service of another program. `(deny mach-lookup)` closes it,
///   and [`SYSTEM_MACH_SERVICES`] names the services that an ordinary
///   program needs.
///
/// The rules go after `(allow default)`, and the last matching rule wins,
/// so each allow of a service comes after the deny.
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if a name contains NUL or a
/// newline. Each name of [`SYSTEM_MACH_SERVICES`] is a literal, so the
/// error cannot occur.
fn add_escape_denies(profile: &mut String) -> Result<(), SandboxError> {
    profile.push_str("(deny job-creation)\n");
    profile.push_str("(deny mach-lookup)\n");
    for (name, _why) in SYSTEM_MACH_SERVICES {
        push_rule(
            profile,
            RuleAction::Allow,
            "mach-lookup",
            "global-name",
            name,
        )?;
    }
    Ok(())
}

/// Allow connections to the Unix sockets in the paths that the process can
/// write (proxy mode only).
///
/// `(deny network-outbound)` also denies a `connect()` to a Unix socket.
/// Programs use Unix sockets for their own IPC (for example a socket in
/// `TMPDIR` between a parent and its child). The process can create a socket
/// in a writable path, so a connection to a socket there gives no new
/// access. The sockets in the other paths (for example the Docker socket or
/// the SSH agent socket) stay denied.
///
/// The Apple profiles use path filters (`literal`, `regex`) on
/// `network-outbound` for Unix sockets. This function uses `subpath` in the
/// same position. Test this on a Mac.
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if a path contains NUL or a newline.
fn add_unix_socket_allows(profile: &mut String, dirs: &[&Path]) -> Result<(), SandboxError> {
    for dir in dirs {
        let original = dir.to_string_lossy();
        let canonical = canonical_or_original(dir);
        push_rule(
            profile,
            RuleAction::Allow,
            "network-outbound",
            "subpath",
            &canonical,
        )?;
        if original != canonical {
            push_rule(
                profile,
                RuleAction::Allow,
                "network-outbound",
                "subpath",
                &original,
            )?;
        }
    }
    Ok(())
}

/// Add rules that deny writes to `<workspace>/.pent`.
///
/// The rules use the canonical workspace path and also the original path
/// if it is different (for example `/var` and `/private/var`).
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if the path contains NUL or a newline.
fn add_project_config_deny(profile: &mut String, workspace: &Path) -> Result<(), SandboxError> {
    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf());
    let canonical = canonical_ws.join(".pent");
    let original = workspace.join(".pent");
    push_rule(
        profile,
        RuleAction::Deny,
        "file-write*",
        "subpath",
        &canonical.to_string_lossy(),
    )?;
    if original != canonical {
        push_rule(
            profile,
            RuleAction::Deny,
            "file-write*",
            "subpath",
            &original.to_string_lossy(),
        )?;
    }
    Ok(())
}

/// The Unix socket of `mDNSResponder`, the system name resolver.
///
/// `getaddrinfo` sends each name query to this socket. On macOS the DNS
/// queries of the child do not go through the pent DNS server: the system
/// resolver (outside the sandbox) resolves the names. The child gets the
/// addresses, but `(deny network-outbound)` stops a direct connection to
/// them. Proxy-aware clients send the name to the proxy (`socks5h://`,
/// HTTP `CONNECT`), and the proxy resolves it and applies the allowlist.
const MDNS_RESPONDER_SOCKET: &str = "/private/var/run/mDNSResponder";

/// Whether an SBPL rule asks the kernel to log each match.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Report {
    /// A normal rule. The kernel logs only denials.
    No,
    /// The rule has the `(with report)` modifier. The kernel logs each
    /// operation that the rule allows. Watch mode reads these log lines.
    Yes,
}

impl Report {
    const fn suffix(self) -> &'static str {
        match self {
            Self::No => "",
            Self::Yes => " (with report)",
        }
    }
}

/// Generate the SBPL rules that let the process reach only the proxy and
/// the open ports on localhost.
///
/// The rules are:
///
/// ```text
/// (deny network-outbound)
/// (allow network-outbound (remote ip "localhost:5432"))     ; a port of the profile
/// (allow network-outbound (remote ip "localhost:<port>"))   ; the proxy
/// (allow network-outbound (literal "/private/var/run/mDNSResponder"))
/// ```
///
/// The rule of the proxy port never has `(with report)`, and it comes after
/// the rules of the open ports. A connection to the proxy thus makes no
/// report also when watch mode opens each port (`localhost:*`): the proxy
/// records each of its requests itself.
///
/// The source of the syntax (from memory; nobody tested these rules on a
/// Mac yet):
///
/// - `(remote ip "localhost:<port>")`: the form that the Anthropic
///   `sandbox-runtime` macOS profile uses for its proxy ports, and the form
///   that the `LocalhostOnly` rules of this file use with the port `*`.
///   Seatbelt accepts only `*` or `localhost` as the host part.
/// - `(literal "<socket path>")` on `network-outbound`: the form that the
///   Apple system profiles (`system.sb`, macro `system-network`) and the
///   Chromium profiles use for `mDNSResponder`. A path filter on
///   `network-outbound` matches only the address of a Unix socket.
///
/// The rules do not deny `network-bind` or `network-inbound`, so the process
/// can open a server socket. It cannot connect to the other loopback ports.
///
/// The rules do not allow the kernel control sockets
/// (`com.apple.netsrc`). Some programs that use `Network.framework` can need
/// them. Test this on a Mac.
fn proxy_network_rules(port: u16, localhost: &LocalhostPorts, report: Report) -> String {
    let rep = report.suffix();
    format!(
        "(deny network-outbound)\n\
         {}\
         (allow network-outbound (remote ip \"localhost:{port}\"))\n\
         (allow network-outbound (literal \"{MDNS_RESPONDER_SOCKET}\"){rep})\n",
        localhost_port_rules(localhost, report)
    )
}

/// Generate the SBPL rules that open the ports on localhost: one rule for
/// each port of the list, or one rule for each port (`localhost:*`).
///
/// With each port open, a deny rule for each control port of the watch
/// guard ([`pent_profile::CONTROL_PORTS`]) comes after the allow, so it
/// wins. The kernel logs the denial, and the reader marks it as blocked.
///
/// Seatbelt has no network namespace, so a server that the process itself
/// runs on the loopback also needs its port in the list.
fn localhost_port_rules(ports: &LocalhostPorts, report: Report) -> String {
    let rep = report.suffix();
    match ports {
        LocalhostPorts::Listed(list) => list
            .iter()
            .map(|port| format!("(allow network-outbound (remote ip \"localhost:{port}\"){rep})\n"))
            .collect(),
        LocalhostPorts::All => {
            let mut rules = format!("(allow network-outbound (remote ip \"localhost:*\"){rep})\n");
            for (port, _) in pent_profile::CONTROL_PORTS {
                rules.push_str(&format!(
                    "(deny network-outbound (remote ip \"localhost:{port}\"))\n"
                ));
            }
            rules
        }
    }
}

/// Generate SBPL network rules based on NetworkMode.
///
/// # Network Rules
/// - Unrestricted: No network rules (allow default permits it)
/// - LocalhostOnly: Deny network, then allow all loopback outbound
/// - ProxyOnly: Deny outbound connections, then allow the open ports on
///   localhost, the proxy port on loopback and the `mDNSResponder` socket
///   (see [`proxy_network_rules`]). [`generate_sbpl_profile`] also allows
///   the Unix sockets in the writable paths.
/// - Blocked: `(deny network*)`, then allow the open ports on localhost.
fn generate_network_rules(
    mode: &NetworkMode,
    localhost: &LocalhostPorts,
    report: Report,
) -> String {
    match mode {
        NetworkMode::Unrestricted => {
            // Allow default already permits network.
            String::new()
        }
        NetworkMode::ProxyOnly { proxy_addr, .. } => {
            proxy_network_rules(proxy_addr.port(), localhost, report)
        }
        NetworkMode::LocalhostOnly => {
            // Deny all network, then allow only loopback.
            // network-outbound to remote localhost: allows TCP/UDP connects to 127.x
            // network-bind to local localhost: allows binding loopback server sockets
            // (local ip "localhost:*") is intentionally omitted — on recent macOS it
            // matches unbound outbound sockets (local addr 0.0.0.0) and would leak.
            r#"(deny network*)
(allow network-outbound (remote ip "localhost:*"))
(allow network-bind (local ip "localhost:*"))"#
                .to_string()
        }
        NetworkMode::Blocked => {
            // Explicit deny since we use allow default. The rules of the
            // open ports come after it, so they win.
            let ports = localhost_port_rules(localhost, report);
            format!("(deny network*)\n{ports}").trim_end().to_string()
        }
    }
}

/// Return the canonical form of `path` as a string, with symlinks resolved.
///
/// SBPL compares the real path, so symlinks like /var -> /private/var must be
/// resolved. Falls back to the original path if canonicalization fails. The
/// result is not escaped; [`push_rule`] quotes it.
fn canonical_or_original(path: &Path) -> String {
    path.canonicalize().map_or_else(
        |_| path.to_string_lossy().into_owned(),
        |p| p.to_string_lossy().into_owned(),
    )
}

/// Add SBPL rules for a glob path (prefix match) using SBPL regex.
///
/// A glob path `~/.claude.json*` (with trailing `*` stripped before calling here)
/// generates a regex rule that matches the path and anything starting with it.
/// See [`glob_prefix_to_regex`] for the translation.
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if the path contains NUL or a newline.
fn add_sbpl_glob_rule(profile: &mut String, path: &Path, access: &str) -> Result<(), SandboxError> {
    let original = glob_prefix_to_regex(&path.to_string_lossy());
    let canonical = path.canonicalize().map_or_else(
        |_| original.clone(),
        |p| glob_prefix_to_regex(&p.to_string_lossy()),
    );

    push_rule(profile, RuleAction::Allow, access, "regex", &canonical)?;
    if original != canonical {
        push_rule(profile, RuleAction::Allow, access, "regex", &original)?;
    }
    Ok(())
}

/// Add SBPL rules for a path, including both original and canonical if they differ.
///
/// macOS has symlinks like /var -> /private/var. File operations may use either path,
/// so we need to allow both in the SBPL profile.
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if the path contains NUL or a newline.
fn add_sbpl_path_rule(profile: &mut String, path: &Path, access: &str) -> Result<(), SandboxError> {
    let original = path.to_string_lossy();
    let canonical = canonical_or_original(path);

    // Use literal for files, subpath for directories
    let is_file = path.is_file();
    let modifier = if is_file { "literal" } else { "subpath" };

    // Always add the canonical path
    push_rule(profile, RuleAction::Allow, access, modifier, &canonical)?;

    // If original differs from canonical (symlink), add it too
    if original != canonical {
        push_rule(profile, RuleAction::Allow, access, modifier, &original)?;
    }

    // For executable files, also allow process-exec
    if is_file && is_executable(path) {
        push_rule(
            profile,
            RuleAction::Allow,
            "process-exec",
            "literal",
            &canonical,
        )?;
        if original != canonical {
            push_rule(
                profile,
                RuleAction::Allow,
                "process-exec",
                "literal",
                &original,
            )?;
        }
    }
    Ok(())
}

/// Check if a file is executable
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Escape all regex metacharacters in `text`, so the regex matches only
/// `text` itself.
///
/// The result is a regex, not an SBPL string. Give it to [`sbpl_string`]
/// to escape the backslashes for the SBPL reader.
fn regex_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len().saturating_add(8));
    for ch in text.chars() {
        if matches!(
            ch,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|'
        ) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// The operations that watch mode logs with `(with report)`.
///
/// Watch mode reports `file-read-data`, not `file-read*`: the metadata
/// reads (`stat`) occur on almost each path and make a large volume of log
/// lines with no value for a profile.
const WATCH_REPORTED_OPERATIONS: &[&str] = &[
    "file-read-data",
    "file-write*",
    "process-exec",
    "network-outbound",
];

/// Generate the SBPL profile of watch mode.
///
/// Watch mode does not sandbox the program. The profile allows all
/// operations, asks the kernel to log each file read, file write, exec and
/// outbound connection, limits the network as in run mode, and adds the deny
/// rules of the guard:
///
/// ```text
/// (version 1)
/// (allow default)
/// (allow file-read-data (with report))
/// (allow file-write* (with report))
/// (allow process-exec (with report))
/// (allow network-outbound (with report))
/// (deny network-outbound)                                   ; proxy mode
/// (allow network-outbound (remote ip "localhost:8080") (with report))
/// (allow network-outbound (literal "/private/var/run/mDNSResponder") (with report))
/// (allow network-outbound (subpath "/") (with report))      ; all Unix sockets
/// (deny file-read-data (regex "^/Users/u/\\.ssh/id_[^/]*$"))
/// (deny file-read-data (regex "^/Users/u/\\.ssh/.*/id_[^/]*$"))
/// (allow file-read-data (regex "^/Users/u/\\.ssh/id_[^/]*\\.pub$") (with report))
/// (allow file-read-data (regex "^/Users/u/\\.ssh/.*/id_[^/]*\\.pub$") (with report))
/// (deny file-read-data (regex "^/Users/u/\\.ssh/[^/]*_rsa$"))
/// (deny file-read-data (regex "^/Users/u/\\.ssh/.*/[^/]*_rsa$"))
/// (deny file-write* (literal "/Users/u/.bashrc"))
/// (deny process-exec (regex "/sudo$"))
/// ```
///
/// The run of 2026-10-25 on a Mac confirmed each of these points:
///
/// - `(with report)` is a valid modifier on an `allow` rule, and the
///   kernel writes one line of the unified log for each operation that
///   such a rule allows. The profile keeps a plain `(allow default)` and
///   adds one reported `allow` rule for each operation of interest, which
///   keeps the volume of reports small.
/// - The modifier comes after the filter. Apple profiles put `(with ...)`
///   before or after the filters.
/// - When more than one rule matches an operation, the last rule wins. The
///   run-mode profile already uses this (the global `(deny file-read-data)`
///   comes before the allow rules), and the `sandbox-runtime` profiles also
///   use it. Thus a guard deny comes after the reported allow, and the
///   `.pub` allow comes after the deny of the SSH key prefix (SBPL regex has
///   no lookahead).
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if a path contains NUL or a newline.
pub fn generate_watch_profile(
    config: &SandboxConfig,
    guard: &[pent_profile::GuardRule],
) -> Result<String, SandboxError> {
    let mut profile = String::from("(version 1)\n(allow default)\n");
    for op in WATCH_REPORTED_OPERATIONS {
        profile.push_str(&format!("(allow {op}{})\n", Report::Yes.suffix()));
    }
    match &config.network {
        NetworkMode::ProxyOnly { proxy_addr, .. } => {
            profile.push_str(&proxy_network_rules(
                proxy_addr.port(),
                &config.localhost,
                Report::Yes,
            ));
            // Watch mode does not limit the Unix sockets. The recorder
            // records each connection.
            push_rule_with(
                &mut profile,
                RuleAction::Allow,
                "network-outbound",
                "subpath",
                "/",
                Report::Yes,
            )?;
        }
        other => {
            let rules = generate_network_rules(other, &config.localhost, Report::Yes);
            if !rules.is_empty() {
                profile.push_str(&rules);
                profile.push('\n');
            }
        }
    }
    add_guard_rules(&mut profile, guard, Report::Yes)?;
    Ok(profile)
}

/// The two forms of the text between a guarded directory and a file name.
///
/// A [`GuardTarget::FilesInDir`](pent_profile::GuardTarget::FilesInDir)
/// rule matches a file at any depth below the directory, as
/// [`pent_profile::classify`] does. The first form is a direct child of the
/// directory, the second form is a file deeper in the tree. The generator
/// makes one rule for each form, because it uses only the regex constructs
/// that the rest of this file already uses (`^`, `$`, `.*` and `[^/]*`).
const GUARD_DEPTH_FORMS: &[&str] = &["", ".*/"];

/// Translate the file name pattern of a
/// [`GuardTarget::FilesInDir`](pent_profile::GuardTarget::FilesInDir) rule
/// into the regex of the file name.
///
/// A pattern without a leading `*` is a file name prefix: `id_` gives
/// `id_[^/]*`. A pattern with a leading `*` is a file name suffix: `*_rsa`
/// gives `[^/]*_rsa`, and `*.pem` gives `[^/]*\.pem`. The fixed part of the
/// pattern goes through [`regex_escape`], so a dot, a plus or a bracket
/// matches only itself.
///
/// This function is the macOS form of `pent_profile::name_matches`. The two
/// must give the same answer for each file name; the unit test
/// `the_watch_profile_and_classify_agree_on_the_key_names` holds this.
fn name_pattern_regex(pattern: &str) -> String {
    pattern.strip_prefix('*').map_or_else(
        || format!("{}[^/]*", regex_escape(pattern)),
        |suffix| format!("[^/]*{}", regex_escape(suffix)),
    )
}

/// Translate the exception of a
/// [`GuardTarget::FilesInDir`](pent_profile::GuardTarget::FilesInDir) rule
/// into the regex of the file names that match the pattern and that end
/// with `suffix`.
///
/// The profile denies the pattern and then allows this regex again, because
/// SBPL regex has no "not" and the last matching rule wins.
///
/// Return `None` when no file name can match the pattern and also end with
/// the suffix. A name that ends with `_rsa` never ends with `.pub`, so the
/// SSH key rules with a suffix pattern need no exception rule.
fn excluded_name_regex(pattern: &str, suffix: &str) -> Option<String> {
    let escaped = regex_escape(suffix);
    match pattern.strip_prefix('*') {
        // A prefix pattern: the name starts with the prefix and ends with
        // the suffix. The form needs the two parts to be separate. A name
        // in which the end of the prefix is also the start of the suffix
        // stays denied. No pattern of the guard list has such an overlap:
        // `id_` and `.pub` have no common text.
        None => Some(format!("{}[^/]*{escaped}", regex_escape(pattern))),
        // A suffix pattern: a name ends with both suffixes only when one
        // suffix ends with the other.
        Some(pattern_suffix) if suffix.ends_with(pattern_suffix) => Some(format!("[^/]*{escaped}")),
        Some(pattern_suffix) if pattern_suffix.ends_with(suffix) => {
            Some(format!("[^/]*{}", regex_escape(pattern_suffix)))
        }
        Some(_) => None,
    }
}

/// Add the SBPL deny rules for the guard rules.
///
/// - [`GuardAccess::Read`](pent_profile::GuardAccess::Read) gives
///   `(deny file-read-data ...)`.
/// - [`GuardAccess::Write`](pent_profile::GuardAccess::Write) gives
///   `(deny file-write* ...)`.
/// - [`GuardAccess::ExecName`](pent_profile::GuardAccess::ExecName) gives
///   `(deny process-exec ...)`.
///
/// An exact path gives a `literal` filter, a subtree gives `subpath`, and a
/// file name pattern gives a `regex`. A binary name gives the regex
/// `/<name>$`. Each path rule is added for the canonical path and also for
/// the original path if it is different. A rule on a directory (a subtree
/// or a file name pattern) is added for the real directory of each
/// symbolic link below it too (see [`guard_dir_variants`]): Seatbelt
/// matches the path that the kernel resolves.
///
/// A file name pattern gives two or four rules for each form of the
/// directory path: a deny for a direct child of the directory, a deny for a
/// file deeper in the tree (see [`GUARD_DEPTH_FORMS`]), and, for an
/// excluded suffix, an allow rule (with `report`) of each form after the
/// two denies. The last matching rule wins, so the exception comes after
/// the denies of the same guard rule.
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if a path contains NUL or a newline.
fn add_guard_rules(
    profile: &mut String,
    guard: &[pent_profile::GuardRule],
    reallow_report: Report,
) -> Result<(), SandboxError> {
    use pent_profile::{GuardAccess, GuardTarget};

    for rule in guard {
        let op = match rule.access {
            GuardAccess::Read => "file-read-data",
            GuardAccess::Write => "file-write*",
            GuardAccess::ExecName => "process-exec",
        };
        match &rule.target {
            GuardTarget::Exact(path) => {
                for variant in path_variants(path) {
                    push_rule(profile, RuleAction::Deny, op, "literal", &variant)?;
                }
            }
            GuardTarget::Subtree(path) => {
                for variant in guard_dir_variants(path) {
                    push_rule(profile, RuleAction::Deny, op, "subpath", &variant)?;
                }
            }
            GuardTarget::FilesInDir {
                dir,
                prefix,
                exclude_suffix,
            } => {
                let name = name_pattern_regex(prefix);
                let excepted = exclude_suffix
                    .as_deref()
                    .and_then(|suffix| excluded_name_regex(prefix, suffix));
                for variant in guard_dir_variants(dir) {
                    let dir_regex = regex_escape(&variant);
                    for depth in GUARD_DEPTH_FORMS {
                        push_rule(
                            profile,
                            RuleAction::Deny,
                            op,
                            "regex",
                            &format!("^{dir_regex}/{depth}{name}$"),
                        )?;
                    }
                    let Some(excepted) = &excepted else { continue };
                    for depth in GUARD_DEPTH_FORMS {
                        push_rule_with(
                            profile,
                            RuleAction::Allow,
                            op,
                            "regex",
                            &format!("^{dir_regex}/{depth}{excepted}$"),
                            reallow_report,
                        )?;
                    }
                }
            }
            GuardTarget::BinaryName(name) => {
                push_rule(
                    profile,
                    RuleAction::Deny,
                    op,
                    "regex",
                    &format!("/{}$", regex_escape(name)),
                )?;
            }
        }
    }
    Ok(())
}

/// The maximum depth of the walk that looks for a symbolic link below a
/// guarded directory.
const GUARD_LINK_DEPTH: u32 = 8;

/// The maximum number of entries that the walk of one guarded directory
/// looks at. A directory with more entries is not a store of credentials,
/// and the walk must not hold the start of the program.
const GUARD_LINK_ENTRIES: usize = 4096;

/// Return the directories that a guard rule on `dir` must cover.
///
/// Seatbelt matches the path that the kernel resolves, so a deny rule on
/// `~/.ssh` does not cover `~/.ssh/linked/id_rsa` when `linked` is a
/// symbolic link to `~/keystore`: the kernel sees `~/keystore/id_rsa`.
/// The list therefore holds the forms of `dir` itself ([`path_variants`])
/// and the real directory of each symbolic link below `dir` that leaves
/// the tree of `dir`.
///
/// The walk reads the filesystem one time, before the child starts. A link
/// that the program makes during the run is not in the list; Seatbelt
/// decides at the time of the access, and the deny rules of `dir` still
/// hold for each name below `dir` that stays in the tree of `dir`.
fn guard_dir_variants(dir: &Path) -> Vec<String> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut budget = GUARD_LINK_ENTRIES;
    let root = canonical_or_original_path(dir);
    collect_link_dirs(dir, &root, GUARD_LINK_DEPTH, &mut budget, &mut dirs);
    let mut variants = path_variants(dir);
    for target in dirs {
        for form in path_variants(&target) {
            if !variants.contains(&form) {
                variants.push(form);
            }
        }
    }
    variants
}

/// Add to `out` the real directory of each symbolic link below `dir` that
/// points outside `root`.
///
/// The walk does not follow a link: it reads the type of each entry with
/// `symlink_metadata`, and it recurses only into a real directory.
/// `budget` limits the number of entries.
fn collect_link_dirs(
    dir: &Path,
    root: &Path,
    depth: u32,
    budget: &mut usize,
    out: &mut Vec<PathBuf>,
) {
    if depth == 0 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *budget == 0 {
            return;
        }
        *budget = budget.saturating_sub(1);
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            collect_link_dirs(&path, root, depth.saturating_sub(1), budget, out);
        } else if meta.is_symlink() {
            let Ok(target) = std::fs::canonicalize(&path) else {
                continue;
            };
            // A link that stays in the tree of the rule needs no own rule.
            if target.starts_with(root) || !target.is_dir() || out.contains(&target) {
                continue;
            }
            out.push(target);
        }
    }
}

/// Return the canonical form of `path`, or `path` itself when pent cannot
/// resolve it.
fn canonical_or_original_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Return the canonical form of `path` and also the original form if it is
/// different.
fn path_variants(path: &Path) -> Vec<String> {
    let original = path.to_string_lossy().into_owned();
    let canonical = canonical_or_original(path);
    if canonical == original {
        vec![original]
    } else {
        vec![canonical, original]
    }
}

/// Return the environment of the child.
///
/// In proxy mode, add the proxy variables. The values are the same as on
/// Linux: `HTTP_PROXY` and `HTTPS_PROXY` use HTTP `CONNECT`, `ALL_PROXY`
/// uses SOCKS5 with name resolution in the proxy (`socks5h`), and
/// `NO_PROXY` names the loopback addresses. The proxy listens on loopback.
pub(crate) fn child_env(config: &SandboxConfig) -> std::collections::HashMap<String, String> {
    let mut e = config.env.clone();
    if let NetworkMode::ProxyOnly { proxy_addr, .. } = &config.network {
        let port = proxy_addr.port();
        let http_url = format!("http://127.0.0.1:{port}");
        let socks_url = format!("socks5h://127.0.0.1:{port}");
        let no_proxy = "localhost,127.0.0.1,::1";
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            e.insert(key.to_string(), http_url.clone());
        }
        for key in ["ALL_PROXY", "all_proxy", "GRPC_PROXY", "grpc_proxy"] {
            e.insert(key.to_string(), socks_url.clone());
        }
        for key in ["NO_PROXY", "no_proxy"] {
            e.insert(key.to_string(), no_proxy.to_string());
        }
        // Send git-over-SSH through the SOCKS5 proxy (nc -X 5 = SOCKS5).
        e.insert(
            "GIT_SSH_COMMAND".to_string(),
            format!("ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:{port} %h %p'"),
        );
        e.insert("SANDBOX_RUNTIME".to_string(), "1".to_string());
    }
    e
}

/// The names of the programs that the root process of a sandboxed run
/// runs.
///
/// Pent starts `/usr/bin/sandbox-exec`, which applies the profile and then
/// runs `cmd` in the same process. The reader of the log checks the name of
/// each report against the program that the PID runs, and the process table
/// misses a process that lives less than one poll interval. These two names
/// come from pent itself, so the reports of a short-lived root process also
/// reach the recorder. See MAC-8 in `docs/security/macos.md`.
fn root_process_names(cmd: &str) -> Vec<String> {
    let command = Path::new(cmd)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or(cmd);
    vec!["sandbox-exec".to_string(), command.to_string()]
}

/// Spawn `cmd` under the run-mode profile of `config`.
///
/// When [`SandboxConfig::record_events`] is set, start the log reader before
/// the spawn and return the denials in [`crate::SandboxChild::events`]. If
/// `log stream` cannot start, the child still runs, without events.
///
/// # Errors
/// Returns `InvalidConfig` for a path that cannot go into the profile, or
/// `SpawnFailed` if the spawn fails.
#[cfg(target_os = "macos")]
pub(crate) fn spawn_run(
    config: &SandboxConfig,
    cmd: &str,
    args: &[String],
) -> Result<crate::SandboxChild, SandboxError> {
    let profile = generate_sbpl_profile(config)?;
    let env = child_env(config);
    let reader = if config.record_events {
        match crate::macos_log::LogReader::start() {
            Ok(reader) => Some(reader),
            Err(e) => {
                tracing::warn!(error = %e, "the trace has no sandbox denials");
                None
            }
        }
    } else {
        None
    };
    let child = spawn_with_sandbox(&profile, cmd, args, &env, &config.cwd)?;
    let events = reader.map(|r| {
        r.attach(
            child.id(),
            &root_process_names(cmd),
            crate::macos_log::RecordMode::Run,
        )
    });
    Ok(crate::SandboxChild { child, events })
}

/// Spawn `cmd` in watch mode.
///
/// Start the log reader, wait until it is ready, then spawn the child under
/// the watch profile (see [`generate_watch_profile`]).
///
/// # Errors
/// Returns `SandboxUnavailable` if `log stream` cannot start, `InvalidConfig`
/// for a path that cannot go into the profile, or `SpawnFailed` if the spawn
/// fails.
#[cfg(target_os = "macos")]
pub(crate) fn spawn_watched(
    config: &SandboxConfig,
    options: &crate::WatchOptions,
    cmd: &str,
    args: &[String],
) -> Result<crate::WatchedChild, SandboxError> {
    let profile = generate_watch_profile(config, &options.guard)?;
    let env = child_env(config);
    let reader = crate::macos_log::LogReader::start()?;
    let child = spawn_with_sandbox(&profile, cmd, args, &env, &config.cwd)?;
    let events = reader.attach(
        child.id(),
        &root_process_names(cmd),
        crate::macos_log::RecordMode::Watch {
            guard: options.guard.clone(),
            ports: config.localhost.clone(),
        },
    );
    Ok(crate::WatchedChild {
        child: crate::SandboxChild {
            child,
            events: None,
        },
        events,
    })
}

/// Spawn a command under sandbox-exec, returning Child handle.
///
/// # Arguments
/// * `profile` - SBPL profile string
/// * `cmd` - Command to execute
/// * `args` - Command arguments
/// * `env` - Environment variables
/// * `cwd` - Working directory
///
/// # Returns
/// Child process handle
///
/// # Errors
/// Returns `SpawnFailed` if spawn fails.
#[cfg(target_os = "macos")]
pub fn spawn_with_sandbox(
    profile: &str,
    cmd: &str,
    args: &[String],
    env: &std::collections::HashMap<String, String>,
    cwd: &Path,
) -> Result<std::process::Child, SandboxError> {
    use std::process::{Command, Stdio};

    // The profile is the whole policy of the run. With `-v` the user, and
    // a test, can read the text that the kernel gets.
    tracing::debug!(%profile, "the Seatbelt profile of the run");

    let mut command = Command::new("/usr/bin/sandbox-exec");
    command.arg("-p");
    command.arg(profile);
    command.arg(cmd);
    command.args(args);
    command.current_dir(cwd);
    command.env_clear();
    for (key, value) in env {
        command.env(key, value);
    }
    command.stdin(Stdio::inherit());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());

    command.spawn().map_err(SandboxError::SpawnFailed)
}

#[cfg(not(target_os = "macos"))]
pub fn spawn_with_sandbox(
    _profile: &str,
    _cmd: &str,
    _args: &[String],
    _env: &std::collections::HashMap<String, String>,
    _cwd: &Path,
) -> Result<std::process::Child, SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::SandboxPaths;
    use std::net::SocketAddr;

    // ========================================================================
    // sbpl_string tests
    // ========================================================================

    fn quoted(text: &str) -> String {
        sbpl_string(text).unwrap()
    }

    #[test]
    fn test_sbpl_string_simple() {
        assert_eq!(quoted("/usr/bin"), r#""/usr/bin""#);
    }

    #[test]
    fn test_sbpl_string_with_spaces() {
        // Spaces don't need escaping in SBPL strings
        assert_eq!(
            quoted("/Users/name/My Documents"),
            r#""/Users/name/My Documents""#
        );
    }

    #[test]
    fn test_sbpl_string_with_quotes() {
        assert_eq!(quoted("/path/with\"quotes"), r#""/path/with\"quotes""#);
    }

    #[test]
    fn test_sbpl_string_with_backslash() {
        assert_eq!(
            quoted(r"/path/with\backslash"),
            r#""/path/with\\backslash""#
        );
    }

    #[test]
    fn test_sbpl_string_backslash_before_quote() {
        // A trailing backslash must not escape the closing quote.
        assert_eq!(quoted(r#"/a\"#), r#""/a\\""#);
        assert_eq!(quoted(r#"/a\""#), r#""/a\\\"""#);
    }

    #[test]
    fn test_sbpl_string_keeps_parens_and_semicolons() {
        assert_eq!(quoted("/w/proj (copy);x"), r#""/w/proj (copy);x""#);
    }

    #[test]
    fn test_sbpl_string_rejects_nul_and_newline() {
        assert!(sbpl_string("/a\0b").is_err());
        assert!(sbpl_string("/a\nb").is_err());
    }

    // ========================================================================
    // glob_prefix_to_regex tests
    // ========================================================================

    #[test]
    fn test_glob_regex_escapes_dot() {
        assert_eq!(
            glob_prefix_to_regex("/h/.claude.json"),
            r"^/h/\.claude\.json"
        );
    }

    #[test]
    fn test_glob_regex_escapes_all_metachars() {
        assert_eq!(
            glob_prefix_to_regex(r"/a+b?c(d)e[f]g{h}i^j$k|l\m"),
            r"^/a\+b\?c\(d\)e\[f\]g\{h\}i\^j\$k\|l\\m"
        );
    }

    #[test]
    fn test_glob_regex_translates_stars() {
        assert_eq!(glob_prefix_to_regex("/a/*/b"), "^/a/[^/]*/b");
        assert_eq!(glob_prefix_to_regex("/a/**/b"), "^/a/.*/b");
    }

    #[test]
    fn test_glob_regex_in_sbpl_string_doubles_backslashes() {
        // The SBPL reader turns "\\." back into "\.", which the regex
        // engine reads as a literal dot.
        let regex = glob_prefix_to_regex("/h/.x");
        assert_eq!(quoted(&regex), r#""^/h/\\.x""#);
    }

    // ========================================================================
    // canonical_or_original tests
    // ========================================================================

    #[test]
    fn test_canonical_or_original_resolves_symlink() {
        // On macOS, /var is a symlink to /private/var
        #[cfg(target_os = "macos")]
        {
            let canonical = canonical_or_original(Path::new("/var"));
            assert!(
                canonical.starts_with("/private/var"),
                "Expected /private/var, got {canonical}"
            );
        }
    }

    #[test]
    fn test_canonical_or_original_nonexistent_fallback() {
        // Non-existent paths fall back to the original path
        let canonical = canonical_or_original(Path::new("/nonexistent/path/12345"));
        assert_eq!(canonical, "/nonexistent/path/12345");
    }

    // ========================================================================
    // generate_network_rules tests
    // ========================================================================

    #[test]
    fn test_network_rules_unrestricted() {
        let rules =
            generate_network_rules(&NetworkMode::Unrestricted, &LocalhostPorts::All, Report::No);
        // Unrestricted = empty (allow default permits network)
        assert!(rules.is_empty());
    }

    #[test]
    fn test_network_rules_localhost_only() {
        let rules = generate_network_rules(
            &NetworkMode::LocalhostOnly,
            &LocalhostPorts::default(),
            Report::No,
        );
        // Should deny all, then allow localhost
        assert!(rules.contains("(deny network*)"));
        assert!(rules.contains("localhost"));
    }

    #[test]
    fn test_network_rules_proxy_only() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let rules = generate_network_rules(
            &NetworkMode::ProxyOnly {
                proxy_addr: addr,
                dns_port: 0,
            },
            &LocalhostPorts::default(),
            Report::No,
        );
        // Only the proxy port on loopback and the system resolver socket.
        assert_eq!(
            rules,
            "(deny network-outbound)\n\
             (allow network-outbound (remote ip \"localhost:8080\"))\n\
             (allow network-outbound (literal \"/private/var/run/mDNSResponder\"))\n"
        );
    }

    fn proxy_mode() -> NetworkMode {
        NetworkMode::ProxyOnly {
            proxy_addr: "127.0.0.1:4321".parse().unwrap(),
            dns_port: 0,
        }
    }

    #[test]
    fn test_sbpl_profile_proxy_allows_unix_sockets_in_writable_paths() {
        let config =
            SandboxConfig::new("/workspace".into(), make_test_paths(), "/workspace".into())
                .with_network(proxy_mode());
        let profile = generate_sbpl_profile(&config).unwrap();
        let deny_at = profile.find("(deny network-outbound)\n").unwrap();
        let unix_at = profile
            .find(r#"(allow network-outbound (subpath "/workspace"))"#)
            .unwrap();
        assert!(profile.contains(r#"(allow network-outbound (remote ip "localhost:4321"))"#));
        assert!(
            profile.contains(r#"(allow network-outbound (subpath "/tmp"))"#) || {
                // On macOS, /tmp is a link to /private/tmp.
                profile.contains(r#"(allow network-outbound (subpath "/private/tmp"))"#)
            }
        );
        // The Unix socket allows come after the deny, so they win.
        assert!(unix_at > deny_at, "{profile}");
        assert!(!profile.contains("(with report)"), "{profile}");
    }

    #[test]
    fn test_child_env_sets_proxy_variables() {
        let config =
            SandboxConfig::new("/workspace".into(), make_test_paths(), "/workspace".into())
                .with_network(proxy_mode());
        let env = child_env(&config);
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            assert_eq!(
                env.get(key).map(String::as_str),
                Some("http://127.0.0.1:4321")
            );
        }
        for key in ["ALL_PROXY", "all_proxy"] {
            assert_eq!(
                env.get(key).map(String::as_str),
                Some("socks5h://127.0.0.1:4321")
            );
        }
        assert_eq!(
            env.get("NO_PROXY").map(String::as_str),
            Some("localhost,127.0.0.1,::1")
        );
        let blocked = SandboxConfig::new("/w".into(), make_test_paths(), "/w".into());
        assert!(!child_env(&blocked).contains_key("HTTP_PROXY"));
    }

    // ========================================================================
    // watch profile tests
    // ========================================================================

    use pent_profile::{GuardAccess, GuardClass, GuardRule, GuardTarget};

    fn rule(access: GuardAccess, target: GuardTarget) -> GuardRule {
        GuardRule {
            class: GuardClass::Credential,
            access,
            target,
        }
    }

    fn watch_profile(guard: &[GuardRule]) -> String {
        let config = SandboxConfig::new("/w".into(), make_test_paths(), "/w".into())
            .with_network(proxy_mode());
        generate_watch_profile(&config, guard).unwrap()
    }

    // ========================================================================
    // A reader of the generated profile.
    //
    // A test on Linux cannot ask Seatbelt what a profile does. The reader
    // below takes the text of the profile and applies the rule of the
    // kernel: the last rule that matches the operation and the path wins.
    // It knows only the rule shapes and the regex constructs that this file
    // writes, and it fails the test on any other shape, so a new shape
    // cannot pass without a check. The test
    // `the_watch_profile_with_the_guard_rules_compiles` and the end-to-end
    // tests are the check against the real kernel.
    // ========================================================================

    /// The result of a profile for one operation on one path.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Verdict {
        Allowed,
        Denied,
    }

    /// One atom of the regex subset that the generator writes.
    #[derive(Debug, Clone, Copy)]
    enum Atom {
        /// One character, with no special meaning.
        Lit(char),
        /// `.*`: any characters.
        AnySeq,
        /// `[^/]*`: any characters of one path part.
        SegmentSeq,
    }

    /// Return the verdict of `profile` for `op` on `path`.
    ///
    /// A test helper: an unknown rule shape panics, so the test fails with
    /// the line that it cannot read.
    #[allow(clippy::panic)]
    fn verdict(profile: &str, op: &str, path: &str) -> Verdict {
        // Before `(allow default)` the Seatbelt default is a denial.
        let mut result = Verdict::Denied;
        for line in profile.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("(version") {
                continue;
            }
            let (action, ops, filter) = parse_rule(line);
            if !ops.iter().any(|o| o == "default" || o == op) {
                continue;
            }
            let hit = match &filter {
                None => true,
                Some((kind, value)) => match kind.as_str() {
                    "literal" => path == value,
                    "subpath" => path == value || path.starts_with(&format!("{value}/")),
                    "regex" => regex_matches(value, path),
                    // A network filter never matches a path.
                    "remote" | "local" => false,
                    other => panic!("the test cannot read the filter {other:?}: {line}"),
                },
            };
            if hit {
                result = action;
            }
        }
        result
    }

    /// Split one rule line into the action, the operations and the filter.
    #[allow(clippy::panic)]
    fn parse_rule(line: &str) -> (Verdict, Vec<String>, Option<(String, String)>) {
        let inner = line
            .strip_prefix('(')
            .and_then(|rest| rest.strip_suffix(')'))
            .unwrap_or_else(|| panic!("not a rule: {line}"));
        let head_end = inner.find('(').unwrap_or(inner.len());
        let mut words = inner.get(..head_end).unwrap_or_default().split_whitespace();
        let action = match words.next() {
            Some("allow") => Verdict::Allowed,
            Some("deny") => Verdict::Denied,
            other => panic!("the test cannot read the action {other:?}: {line}"),
        };
        let ops: Vec<String> = words.map(str::to_string).collect();
        assert!(!ops.is_empty(), "a rule without an operation: {line}");
        let mut filter = None;
        for group in groups(inner.get(head_end..).unwrap_or_default()) {
            let (kind, value) = group.split_once(' ').unwrap_or((group.as_str(), ""));
            match kind {
                // The report modifier does not change the verdict.
                "with" => {}
                "literal" | "subpath" | "regex" => {
                    filter = Some((kind.to_string(), unquote(value, line)));
                }
                "remote" | "local" => filter = Some((kind.to_string(), String::new())),
                other => panic!("the test cannot read the filter {other:?}: {line}"),
            }
        }
        (action, ops, filter)
    }

    /// Return the text of each top-level `( ... )` group of `text`.
    ///
    /// A double-quoted string can hold a parenthesis, so the scan knows the
    /// SBPL string escapes.
    #[allow(clippy::panic)]
    fn groups(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut current = String::new();
        let mut depth: usize = 0;
        let mut in_string = false;
        let mut escaped = false;
        for ch in text.chars() {
            if in_string {
                current.push(ch);
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_string = false;
                }
                continue;
            }
            match ch {
                '(' => {
                    if depth > 0 {
                        current.push(ch);
                    }
                    depth += 1;
                }
                ')' => {
                    assert!(
                        depth > 0,
                        "a rule with too many closing parentheses: {text}"
                    );
                    depth -= 1;
                    if depth == 0 {
                        out.push(std::mem::take(&mut current));
                    } else {
                        current.push(ch);
                    }
                }
                '"' => {
                    in_string = true;
                    current.push(ch);
                }
                _ if depth > 0 => current.push(ch),
                _ => {}
            }
        }
        assert_eq!(depth, 0, "a rule with an open parenthesis: {text}");
        out
    }

    /// Read back the text of an SBPL string literal.
    #[allow(clippy::panic)]
    fn unquote(text: &str, line: &str) -> String {
        let body = text
            .trim()
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or_else(|| panic!("the filter value is not a string: {line}"));
        let mut out = String::new();
        let mut escaped = false;
        for ch in body.chars() {
            if escaped {
                out.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else {
                out.push(ch);
            }
        }
        out
    }

    /// Return true if the regex `pattern` matches `text`.
    #[allow(clippy::panic)]
    fn regex_matches(pattern: &str, text: &str) -> bool {
        let anchored_start = pattern.starts_with('^');
        let anchored_end = pattern.ends_with('$');
        let body = pattern.strip_prefix('^').unwrap_or(pattern);
        let body = body.strip_suffix('$').unwrap_or(body);
        let atoms = parse_regex(body, pattern);
        if anchored_start {
            return match_atoms(&atoms, text, anchored_end);
        }
        std::iter::once(text.len())
            .chain(text.char_indices().map(|(i, _)| i))
            .any(|start| {
                text.get(start..)
                    .is_some_and(|rest| match_atoms(&atoms, rest, anchored_end))
            })
    }

    /// Translate the regex subset of the generator into atoms.
    #[allow(clippy::panic)]
    fn parse_regex(body: &str, pattern: &str) -> Vec<Atom> {
        let mut atoms = Vec::new();
        let mut chars = body.chars().peekable();
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => match chars.next() {
                    Some(escaped) => atoms.push(Atom::Lit(escaped)),
                    None => panic!("a backslash at the end of the regex: {pattern}"),
                },
                '.' if chars.peek() == Some(&'*') => {
                    chars.next();
                    atoms.push(Atom::AnySeq);
                }
                '[' => {
                    let rest: String = chars.by_ref().take(4).collect();
                    assert_eq!(
                        rest, "^/]*",
                        "the test knows only the class [^/]* in the regex: {pattern}"
                    );
                    atoms.push(Atom::SegmentSeq);
                }
                '*' | '+' | '?' | '(' | ')' | ']' | '{' | '}' | '^' | '$' | '|' | '.' => {
                    panic!("the regex has the unescaped metacharacter {ch:?}: {pattern}")
                }
                other => atoms.push(Atom::Lit(other)),
            }
        }
        atoms
    }

    /// Match `atoms` against the start of `text`.
    fn match_atoms(atoms: &[Atom], text: &str, anchored_end: bool) -> bool {
        match atoms.split_first() {
            None => !anchored_end || text.is_empty(),
            Some((Atom::Lit(c), rest)) => text
                .strip_prefix(*c)
                .is_some_and(|tail| match_atoms(rest, tail, anchored_end)),
            Some((atom, rest)) => {
                let one_part = matches!(atom, Atom::SegmentSeq);
                let mut end = 0;
                loop {
                    let Some(tail) = text.get(end..) else {
                        return false;
                    };
                    if match_atoms(rest, tail, anchored_end) {
                        return true;
                    }
                    let Some(ch) = tail.chars().next() else {
                        return false;
                    };
                    if one_part && ch == '/' {
                        return false;
                    }
                    end = end.saturating_add(ch.len_utf8());
                }
            }
        }
    }

    #[test]
    fn test_profile_reader_reads_the_rule_shapes() {
        let profile = concat!(
            "(version 1)\n",
            "(allow default)\n",
            "(deny file-read-data)\n",
            "(allow file-read-data (literal \"/a/b\"))\n",
            "(allow file-read-data file-write* (subpath \"/c\"))\n",
            "(allow file-read-data (regex \"^/d/[^/]*\\\\.txt$\") (with report))\n",
            "(deny network-outbound)\n",
            "(allow network-outbound (remote ip \"localhost:1\"))\n",
        );
        let read = |path: &str| verdict(profile, "file-read-data", path);
        assert_eq!(read("/a/b"), Verdict::Allowed);
        assert_eq!(read("/a/bb"), Verdict::Denied);
        assert_eq!(read("/c/x/y"), Verdict::Allowed);
        assert_eq!(read("/cx"), Verdict::Denied);
        assert_eq!(read("/d/x.txt"), Verdict::Allowed);
        assert_eq!(read("/d/sub/x.txt"), Verdict::Denied);
        // The network rules do not change a file read.
        assert_eq!(read("/e"), Verdict::Denied);
        assert_eq!(
            verdict(profile, "file-write*", "/c/x"),
            Verdict::Allowed,
            "a rule with two operations covers both"
        );
        // `.*` crosses a path part; a name part does not.
        assert!(regex_matches("^/a/.*/b$", "/a/x/y/b"));
        assert!(!regex_matches("^/a/[^/]*/b$", "/a/x/y/b"));
        assert!(regex_matches("/sudo$", "/usr/bin/sudo"));
        assert!(!regex_matches("/sudo$", "/usr/bin/sudoedit"));
    }

    /// MAC-2 and MAC-3: the generated profile and `pent_profile::classify`
    /// must give the same answer for each SSH key name, at each depth below
    /// `~/.ssh`.
    #[test]
    fn the_watch_profile_and_classify_agree_on_the_key_names() {
        let home = Path::new("/nonexistent/home/u");
        let guard = pent_profile::guard_rules(home);
        let config = SandboxConfig::new("/w".into(), make_test_paths(), "/w".into());
        let profile = generate_watch_profile(&config, &guard).unwrap();
        // The name of the file, and whether the guard must block a read.
        let keys = [
            ("id_ed25519", true),
            ("github_rsa", true),
            ("work.pem", true),
            ("deploy.key", true),
            ("id_ed25519.pub", false),
            ("notes.txt", false),
        ];
        for (name, blocked) in keys {
            for dir in [".ssh", ".ssh/keys", ".ssh/old/2026"] {
                let path = home.join(dir).join(name);
                let text = path.to_string_lossy();
                assert_eq!(
                    verdict(&profile, "file-read-data", &text) == Verdict::Denied,
                    blocked,
                    "the profile does not block {text} as expected"
                );
                assert_eq!(
                    pent_profile::classify(&guard, &path, GuardAccess::Read).is_some(),
                    blocked,
                    "classify does not block {text} as expected"
                );
            }
        }
    }

    /// The same agreement for the Python user site, where the real files
    /// are two or three levels below the guarded directory.
    #[test]
    fn the_watch_profile_and_classify_agree_on_the_python_user_site() {
        let home = Path::new("/nonexistent/home/u");
        let guard = pent_profile::guard_rules(home);
        let config = SandboxConfig::new("/w".into(), make_test_paths(), "/w".into());
        let profile = generate_watch_profile(&config, &guard).unwrap();
        let files = [
            (".local/lib/python3.12/site-packages/evil.pth", true),
            (".local/lib/python3.12/site-packages/usercustomize.py", true),
            ("Library/Python/3.12/lib/python/site-packages/x.pth", true),
            (".local/lib/python3.12/site-packages/notes.txt", false),
        ];
        for (rel, blocked) in files {
            let path = home.join(rel);
            let text = path.to_string_lossy();
            assert_eq!(
                verdict(&profile, "file-write*", &text) == Verdict::Denied,
                blocked,
                "the profile does not block a write to {text} as expected"
            );
            assert_eq!(
                pent_profile::classify(&guard, &path, GuardAccess::Write).is_some(),
                blocked,
                "classify does not block a write to {text} as expected"
            );
        }
    }

    /// A metacharacter in the directory matches only itself, so the rule
    /// does not become wider.
    #[test]
    fn a_metacharacter_in_the_guard_directory_does_not_widen_the_rule() {
        let profile = watch_profile(&[rule(
            GuardAccess::Read,
            GuardTarget::FilesInDir {
                dir: "/nonexistent/a+b[1]/.ssh".into(),
                prefix: "id_".to_string(),
                exclude_suffix: None,
            },
        )]);
        assert!(
            profile.contains(
                r#"(deny file-read-data (regex "^/nonexistent/a\\+b\\[1\\]/\\.ssh/id_[^/]*$"))"#
            ),
            "{profile}"
        );
        assert_eq!(
            verdict(&profile, "file-read-data", "/nonexistent/a+b[1]/.ssh/id_x"),
            Verdict::Denied
        );
        for other in [
            "/nonexistent/ab[1]/.ssh/id_x",
            "/nonexistent/aab[1]/.ssh/id_x",
            "/nonexistent/a+b1/.ssh/id_x",
            "/nonexistent/a+b[1]/Xssh/id_x",
        ] {
            assert_eq!(
                verdict(&profile, "file-read-data", other),
                Verdict::Allowed,
                "the rule became wider: {other}"
            );
        }
    }

    #[test]
    fn test_watch_profile_reports_and_limits_network() {
        let profile = watch_profile(&[]);
        assert!(profile.starts_with("(version 1)\n(allow default)\n"));
        for op in [
            "file-read-data",
            "file-write*",
            "process-exec",
            "network-outbound",
        ] {
            assert!(
                profile.contains(&format!("(allow {op} (with report))\n")),
                "{profile}"
            );
        }
        let report_at = profile
            .find("(allow network-outbound (with report))")
            .unwrap();
        let deny_at = profile.find("(deny network-outbound)\n").unwrap();
        assert!(deny_at > report_at, "the deny must come last: {profile}");
        // The proxy records its own requests, so its port has no report.
        assert!(profile.contains("(allow network-outbound (remote ip \"localhost:4321\"))\n"));
        assert!(profile.contains(r#"(allow network-outbound (subpath "/") (with report))"#));
        assert!(!profile.contains(".pent"), "watch mode has no run policy");
    }

    /// MAC-4. The run profile denies the three ways to run a program that
    /// no profile holds, and each allow of a Mach service comes after the
    /// deny, because the last matching rule wins.
    #[test]
    fn the_run_profile_denies_each_route_out_of_the_sandbox() {
        let config = SandboxConfig::new("/w".into(), make_test_paths(), "/w".into());
        let profile = generate_sbpl_profile(&config).unwrap();
        for deny in [
            "(deny process-exec)\n",
            "(deny job-creation)\n",
            "(deny mach-lookup)\n",
        ] {
            assert!(profile.contains(deny), "the profile has no {deny}{profile}");
        }
        let deny_at = profile.find("(deny mach-lookup)\n").unwrap();
        assert!(!SYSTEM_MACH_SERVICES.is_empty(), "the allowlist is empty");
        for (name, why) in SYSTEM_MACH_SERVICES {
            let rule = format!("(allow mach-lookup (global-name \"{name}\"))\n");
            let allow_at = profile.find(&rule);
            assert!(
                allow_at.is_some_and(|at| at > deny_at),
                "the allow of {name} must come after the deny: {profile}"
            );
            assert!(!why.is_empty(), "the service {name} names no reason");
        }
    }

    /// Watch mode observes; it must not deny a Mach service or a job.
    #[test]
    fn the_watch_profile_denies_no_mach_service() {
        let config = SandboxConfig::new("/w".into(), make_test_paths(), "/w".into());
        let profile = generate_watch_profile(&config, &[]).unwrap();
        assert!(!profile.contains("(deny mach-lookup)"), "{profile}");
        assert!(!profile.contains("(deny job-creation)"), "{profile}");
    }

    #[test]
    fn test_watch_profile_unrestricted_has_no_network_deny() {
        let config = SandboxConfig::new("/w".into(), make_test_paths(), "/w".into())
            .with_network(NetworkMode::Unrestricted);
        let profile = generate_watch_profile(&config, &[]).unwrap();
        assert!(!profile.contains("(deny network"), "{profile}");
    }

    #[test]
    fn test_watch_profile_guard_exact_and_subtree() {
        let profile = watch_profile(&[
            rule(
                GuardAccess::Read,
                GuardTarget::Exact("/nonexistent/u/.netrc".into()),
            ),
            rule(
                GuardAccess::Write,
                GuardTarget::Subtree("/nonexistent/u/Library/LaunchAgents".into()),
            ),
        ]);
        assert!(profile.contains(r#"(deny file-read-data (literal "/nonexistent/u/.netrc"))"#));
        assert!(profile
            .contains(r#"(deny file-write* (subpath "/nonexistent/u/Library/LaunchAgents"))"#));
        // The guard denies come after the reported allows.
        let deny_at = profile.find("(deny file-read-data").unwrap();
        let allow_at = profile
            .find("(allow file-read-data (with report))")
            .unwrap();
        assert!(deny_at > allow_at);
    }

    /// DIFF-5. `~/.ssh/linked` is a symbolic link to `~/keystore`.
    /// Seatbelt matches the path that the kernel resolves, so a rule on
    /// `~/.ssh` alone does not cover `~/keystore/id_rsa`. The profile must
    /// hold the real directory too, for a file name pattern and for a
    /// subtree.
    #[test]
    fn the_watch_profile_covers_a_key_behind_a_symbolic_link() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let ssh = root.join(".ssh");
        let store = root.join("keystore");
        std::fs::create_dir(&ssh).unwrap();
        std::fs::create_dir(&store).unwrap();
        std::fs::write(store.join("id_rsa"), "k").unwrap();
        std::os::unix::fs::symlink(&store, ssh.join("linked")).unwrap();
        let profile = watch_profile(&[
            rule(
                GuardAccess::Read,
                GuardTarget::FilesInDir {
                    dir: ssh.clone(),
                    prefix: "id_".to_string(),
                    exclude_suffix: Some(".pub".to_string()),
                },
            ),
            rule(GuardAccess::Read, GuardTarget::Subtree(ssh.clone())),
        ]);
        // The name `keystore` holds no character that a regular
        // expression gives a meaning to, so the end of the rule is the
        // plain text.
        assert!(
            profile.contains(r#"/keystore/id_[^/]*$"))"#),
            "the pattern rule must cover the real directory of the link: {profile}"
        );
        assert!(
            profile.contains(&format!(
                r#"(deny file-read-data (subpath "{}"))"#,
                store.to_string_lossy()
            )),
            "the subtree rule must cover the real directory of the link: {profile}"
        );
    }

    /// A link that stays inside the guarded directory needs no own rule:
    /// the rule on the directory already covers the target.
    #[test]
    fn a_link_inside_the_guarded_directory_adds_no_rule() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let ssh = root.join(".ssh");
        std::fs::create_dir_all(ssh.join("old")).unwrap();
        std::os::unix::fs::symlink(ssh.join("old"), ssh.join("link")).unwrap();
        assert_eq!(
            guard_dir_variants(&ssh),
            vec![ssh.to_string_lossy().into_owned()]
        );
    }

    #[test]
    fn test_watch_profile_guard_prefix_with_excluded_suffix() {
        let profile = watch_profile(&[rule(
            GuardAccess::Read,
            GuardTarget::FilesInDir {
                dir: "/nonexistent/u/.ssh".into(),
                prefix: "id_".to_string(),
                exclude_suffix: Some(".pub".to_string()),
            },
        )]);
        let deny = r#"(deny file-read-data (regex "^/nonexistent/u/\\.ssh/id_[^/]*$"))"#;
        let deny_deep = r#"(deny file-read-data (regex "^/nonexistent/u/\\.ssh/.*/id_[^/]*$"))"#;
        let allow = r#"(allow file-read-data (regex "^/nonexistent/u/\\.ssh/id_[^/]*\\.pub$") (with report))"#;
        let allow_deep = r#"(allow file-read-data (regex "^/nonexistent/u/\\.ssh/.*/id_[^/]*\\.pub$") (with report))"#;
        let deny_at = profile.find(deny);
        let deny_deep_at = profile.find(deny_deep);
        let allow_at = profile.find(allow);
        let allow_deep_at = profile.find(allow_deep);
        assert!(deny_at.is_some(), "{profile}");
        assert!(deny_deep_at.is_some(), "{profile}");
        assert!(allow_at.is_some(), "{profile}");
        assert!(allow_deep_at.is_some(), "{profile}");
        // The last matching rule wins: the .pub allows follow the denies.
        assert!(allow_at > deny_deep_at);
        assert!(allow_deep_at > deny_deep_at);
    }

    #[test]
    fn test_watch_profile_guard_suffix_pattern() {
        // A pattern with a leading `*` is a file name suffix. A name that
        // ends with `_rsa` never ends with `.pub`, so the rule has no
        // exception.
        let profile = watch_profile(&[rule(
            GuardAccess::Read,
            GuardTarget::FilesInDir {
                dir: "/nonexistent/u/.ssh".into(),
                prefix: "*_rsa".to_string(),
                exclude_suffix: Some(".pub".to_string()),
            },
        )]);
        assert!(
            profile
                .contains(r#"(deny file-read-data (regex "^/nonexistent/u/\\.ssh/[^/]*_rsa$"))"#),
            "{profile}"
        );
        assert!(
            profile.contains(
                r#"(deny file-read-data (regex "^/nonexistent/u/\\.ssh/.*/[^/]*_rsa$"))"#
            ),
            "{profile}"
        );
        assert!(
            !profile.contains(r"\\*_rsa"),
            "the leading star is a suffix mark, not a literal: {profile}"
        );
        assert!(
            !profile.contains(".pub"),
            "the exception matches no name: {profile}"
        );
    }

    #[test]
    fn test_name_pattern_regex_forms() {
        assert_eq!(name_pattern_regex("id_"), "id_[^/]*");
        assert_eq!(name_pattern_regex("*_rsa"), "[^/]*_rsa");
        assert_eq!(name_pattern_regex("*.pem"), r"[^/]*\.pem");
        assert_eq!(name_pattern_regex("a+b"), r"a\+b[^/]*");
        assert_eq!(
            excluded_name_regex("id_", ".pub"),
            Some(r"id_[^/]*\.pub".to_string())
        );
        assert_eq!(excluded_name_regex("*_rsa", ".pub"), None);
        // One suffix ends with the other: every `.tar.gz` ends with `.gz`.
        assert_eq!(
            excluded_name_regex("*.gz", ".tar.gz"),
            Some(r"[^/]*\.tar\.gz".to_string())
        );
        assert_eq!(
            excluded_name_regex("*.tar.gz", ".gz"),
            Some(r"[^/]*\.tar\.gz".to_string())
        );
    }

    #[test]
    fn test_watch_profile_guard_exec_name() {
        let profile = watch_profile(&[rule(
            GuardAccess::ExecName,
            GuardTarget::BinaryName("sudo".to_string()),
        )]);
        assert!(
            profile.contains(r#"(deny process-exec (regex "/sudo$"))"#),
            "{profile}"
        );
    }

    #[test]
    fn test_watch_profile_guard_escapes_paths() {
        let profile = watch_profile(&[
            rule(
                GuardAccess::Read,
                GuardTarget::Exact("/nonexistent/a\"b) (allow default".into()),
            ),
            rule(
                GuardAccess::Read,
                GuardTarget::FilesInDir {
                    dir: "/nonexistent/x (1)".into(),
                    prefix: "k.".to_string(),
                    exclude_suffix: None,
                },
            ),
        ]);
        assert!(
            profile
                .contains(r#"(deny file-read-data (literal "/nonexistent/a\"b) (allow default"))"#),
            "{profile}"
        );
        assert!(
            profile
                .contains(r#"(deny file-read-data (regex "^/nonexistent/x \\(1\\)/k\\.[^/]*$"))"#),
            "{profile}"
        );
        let bad = rule(GuardAccess::Read, GuardTarget::Exact("/a\nb".into()));
        let config = SandboxConfig::new("/w".into(), make_test_paths(), "/w".into());
        assert!(generate_watch_profile(&config, &[bad]).is_err());
    }

    #[test]
    fn test_regex_escape() {
        assert_eq!(regex_escape("a.b*c(d)"), r"a\.b\*c\(d\)");
    }

    #[test]
    fn test_network_rules_blocked() {
        let rules = generate_network_rules(
            &NetworkMode::Blocked,
            &LocalhostPorts::default(),
            Report::No,
        );
        // Blocked = explicit deny
        assert_eq!(rules, "(deny network*)");
    }

    /// A port of the profile opens after the deny, in the blocked mode and
    /// in the proxy mode, and the run profile reports nothing.
    #[test]
    fn the_run_profile_opens_the_listed_ports_after_the_deny() {
        let port = std::num::NonZeroU16::MIN.saturating_add(5431);
        let ports = LocalhostPorts::Listed(vec![port]);
        let blocked = generate_network_rules(&NetworkMode::Blocked, &ports, Report::No);
        assert_eq!(
            blocked,
            "(deny network*)\n(allow network-outbound (remote ip \"localhost:5432\"))"
        );
        let mut config = SandboxConfig::new("/w".into(), make_test_paths(), "/w".into())
            .with_network(proxy_mode());
        config.localhost = ports;
        let profile = generate_sbpl_profile(&config).unwrap();
        let deny_at = profile.find("(deny network-outbound)\n").unwrap();
        let port_at = profile
            .find("(allow network-outbound (remote ip \"localhost:5432\"))\n")
            .unwrap();
        assert!(port_at > deny_at, "{profile}");
        assert!(!profile.contains("localhost:*"), "{profile}");
        assert!(!profile.contains("(with report)"), "{profile}");
    }

    /// Watch mode opens each port on localhost with a report. The proxy
    /// port comes after it with no report, so a request to the proxy makes
    /// no event of the loopback.
    #[test]
    fn the_watch_profile_reports_each_port_but_not_the_proxy() {
        let mut config = SandboxConfig::new("/w".into(), make_test_paths(), "/w".into())
            .with_network(proxy_mode());
        config.localhost = LocalhostPorts::All;
        let profile = generate_watch_profile(&config, &[]).unwrap();
        let deny_at = profile.find("(deny network-outbound)\n").unwrap();
        let all_at = profile
            .find("(allow network-outbound (remote ip \"localhost:*\") (with report))\n")
            .unwrap();
        let proxy_at = profile
            .find("(allow network-outbound (remote ip \"localhost:4321\"))\n")
            .unwrap();
        assert!(deny_at < all_at && all_at < proxy_at, "{profile}");
        // The watch guard closes each control port after the allow.
        for (port, _) in pent_profile::CONTROL_PORTS {
            let guard_at = profile
                .find(&format!(
                    "(deny network-outbound (remote ip \"localhost:{port}\"))\n"
                ))
                .unwrap();
            assert!(guard_at > all_at, "{profile}");
        }
    }

    /// The root process of a run has two names: the front end and the
    /// command. The reader needs both, because `sandbox-exec` runs the
    /// command in the same process (MAC-8).
    #[test]
    fn the_root_process_has_the_name_of_the_front_end_and_of_the_command() {
        assert_eq!(
            root_process_names("/bin/cat"),
            vec!["sandbox-exec".to_string(), "cat".to_string()]
        );
        assert_eq!(
            root_process_names("npm"),
            vec!["sandbox-exec".to_string(), "npm".to_string()]
        );
    }

    /// MAC-4. The run profile denies `process-exec`, and no rule after the
    /// deny gives exec access to a path of the workspace. A program in the
    /// workspace runs only with `--execute`, as on Linux.
    #[test]
    fn the_run_profile_denies_the_execution_of_a_program_in_the_workspace() {
        let ws = std::path::PathBuf::from("/nonexistent/ws");
        let paths = SandboxPaths {
            traversal: vec!["/".to_string()],
            read: vec!["/usr/lib".to_string()],
            execute: vec!["/bin".to_string()],
            read_write: vec!["/tmp".to_string()],
        };
        let config = SandboxConfig::new(ws.clone(), paths, ws.clone());
        let generated = generate_sbpl_profile(&config);
        assert!(generated.is_ok(), "the generator gave no profile");
        let profile = generated.unwrap_or_default();
        assert!(profile.contains("(deny process-exec)\n"), "{profile}");
        let exec_rules: Vec<&str> = profile
            .lines()
            .filter(|l| l.contains("(allow process-exec"))
            .collect();
        assert!(
            !exec_rules.iter().any(|l| l.contains("/nonexistent/ws")),
            "a rule gives exec access to the workspace:\n{exec_rules:#?}"
        );
        // The deny comes before each allow, and the last matching rule
        // wins, so the order is the whole property.
        let deny = profile.find("(deny process-exec)");
        let first_allow = profile.find("(allow process-exec");
        assert!(deny < first_allow, "{profile}");
    }

    // ========================================================================
    // check_available tests
    // ========================================================================

    #[test]
    fn test_check_available_on_macos() {
        // On macOS, sandbox-exec should exist
        let result = check_available();
        #[cfg(target_os = "macos")]
        assert!(result.is_ok());
        #[cfg(not(target_os = "macos"))]
        assert!(result.is_err());
    }

    // ========================================================================
    // generate_sbpl_profile tests
    // ========================================================================

    fn make_test_paths() -> SandboxPaths {
        SandboxPaths {
            traversal: vec!["/".to_string(), "/Users".to_string()],
            read: vec!["/usr/lib".to_string()],
            execute: vec![],
            read_write: vec!["/tmp".to_string()],
        }
    }

    #[test]
    fn test_sbpl_profile_has_version() {
        let config =
            SandboxConfig::new("/workspace".into(), make_test_paths(), "/workspace".into());
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(profile.contains("(version 1)"));
    }

    #[test]
    fn test_sbpl_profile_has_allow_default() {
        let config =
            SandboxConfig::new("/workspace".into(), make_test_paths(), "/workspace".into());
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(profile.contains("(allow default)"));
    }

    #[test]
    fn test_sbpl_profile_allows_workspace() {
        let config = SandboxConfig::new(
            "/my/workspace".into(),
            make_test_paths(),
            "/my/workspace".into(),
        );
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(profile.contains("/my/workspace"));
    }

    #[test]
    fn test_sbpl_profile_includes_traversal() {
        let paths = SandboxPaths {
            traversal: vec!["/".to_string(), "/custom/traversal".to_string()],
            read: vec![],
            execute: vec![],
            read_write: vec![],
        };
        let config = SandboxConfig::new("/workspace".into(), paths, "/workspace".into());
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(profile.contains("(literal \"/custom/traversal\")"));
    }

    #[test]
    fn test_sbpl_profile_includes_network_rules_when_blocked() {
        let config =
            SandboxConfig::new("/workspace".into(), make_test_paths(), "/workspace".into())
                .with_network(NetworkMode::Blocked);
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(profile.contains("(deny network*)"));
    }

    #[test]
    fn test_sbpl_profile_quotes_path_with_parenthesis() {
        // An injection attempt stays inside one quoted string.
        let evil = "/bad\") (allow file-write* (subpath \"/";
        let paths = SandboxPaths {
            traversal: vec![evil.to_string()],
            read: vec![],
            execute: vec![],
            read_write: vec![],
        };
        let config = SandboxConfig::new("/workspace".into(), paths, "/workspace".into());
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(
            profile.contains(
                r#"(allow file-read-data (literal "/bad\") (allow file-write* (subpath \"/"))"#
            ),
            "injected path must stay quoted: {profile}"
        );
        assert!(!profile.contains("(allow file-write* (subpath \"/\"))"));
    }

    #[test]
    fn test_sbpl_profile_accepts_workspace_with_parens() {
        let ws = "/w/proj (copy)";
        let config = SandboxConfig::new(ws.into(), make_test_paths(), ws.into());
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(
            profile.contains(r#"(subpath "/w/proj (copy)")"#),
            "{profile}"
        );
    }

    #[test]
    fn test_sbpl_profile_accepts_workspace_with_semicolon() {
        let config = SandboxConfig::new(
            "/bad;workspace".into(),
            make_test_paths(),
            "/bad;workspace".into(),
        );
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(profile.contains(r#"(subpath "/bad;workspace")"#));
    }

    #[test]
    fn test_sbpl_profile_rejects_newline_in_path() {
        let paths = SandboxPaths {
            traversal: vec![],
            read: vec!["/a\nb".to_string()],
            execute: vec![],
            read_write: vec![],
        };
        let config = SandboxConfig::new("/workspace".into(), paths, "/workspace".into());
        assert!(generate_sbpl_profile(&config).is_err());
    }

    #[test]
    fn test_sbpl_profile_interior_star_is_literal() {
        // Only a trailing '*' makes a glob. An interior '*' is part of the
        // literal path; it does not widen the rule.
        let paths = SandboxPaths {
            traversal: vec![],
            read: vec!["/path/with/*/wildcard".to_string()],
            execute: vec![],
            read_write: vec![],
        };
        let config = SandboxConfig::new("/workspace".into(), paths, "/workspace".into());
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(profile.contains(r#"(subpath "/path/with/*/wildcard")"#));
    }

    #[test]
    fn test_sbpl_profile_glob_is_escaped() {
        let paths = SandboxPaths {
            traversal: vec![],
            read: vec!["/n/a\"b(c).d*".to_string()],
            execute: vec![],
            read_write: vec![],
        };
        let config = SandboxConfig::new("/workspace".into(), paths, "/workspace".into());
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(
            profile.contains(r#"(allow file-read-data (regex "^/n/a\"b\\(c\\)\\.d"))"#),
            "{profile}"
        );
    }

    // ========================================================================
    // The oracle: `sandbox-exec` compiles each profile that pent makes.
    //
    // These tests run only on macOS. They are the fastest way to find an
    // escaping mistake: the Seatbelt reader rejects a profile that is not
    // valid, and the test then prints the profile. A new path shape costs
    // one line in `SHAPES`.
    // ========================================================================
    #[cfg(target_os = "macos")]
    mod oracle {
        use super::*;
        use std::process::{Command, Stdio};

        /// The Seatbelt front end.
        const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

        /// A program that does nothing and that every macOS has.
        const TRUE_BIN: &str = "/usr/bin/true";

        /// The path shapes that a profile must take. Each one is a name and
        /// a path. The name is in the message of a failed assertion.
        const SHAPES: &[(&str, &str)] = &[
            ("plain", "/nonexistent/plain"),
            ("space", "/nonexistent/a b/c d"),
            ("single quote", "/nonexistent/it's"),
            ("double quote", "/nonexistent/a\"b"),
            ("parentheses", "/nonexistent/proj (copy)"),
            ("backslash", "/nonexistent/a\\b"),
            ("hash", "/nonexistent/a#b"),
            ("semicolon", "/nonexistent/a;b"),
            ("tab", "/nonexistent/a\tb"),
            ("non-ASCII", "/nonexistent/ünïcøde/日本語/🙂"),
            (
                "regex metacharacters",
                "/nonexistent/a.b*c?d[e]f{g}h^i$j|k+l",
            ),
            (
                "injection",
                "/nonexistent/x\") (allow file-write* (subpath \"/",
            ),
            ("comment start", "/nonexistent/; (allow default)"),
        ];

        /// Run `/usr/bin/true` under `profile` and return the exit code and
        /// the standard error.
        fn compile(profile: &str) -> (Option<i32>, String) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("profile.sb");
            std::fs::write(&path, profile).unwrap();
            let out = Command::new(SANDBOX_EXEC)
                .arg("-f")
                .arg(&path)
                .arg(TRUE_BIN)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            (
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            )
        }

        /// Fail with the full profile when `sandbox-exec` does not accept
        /// it.
        fn assert_compiles(name: &str, profile: &str) {
            let (code, stderr) = compile(profile);
            assert_eq!(
                code,
                Some(0),
                "sandbox-exec rejected the profile of the shape {name:?} \
                 (exit {code:?})\n--- stderr ---\n{stderr}\n--- profile ---\n{profile}"
            );
        }

        /// A workspace that exists, so that `canonicalize` works.
        fn workspace() -> (tempfile::TempDir, std::path::PathBuf) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().canonicalize().unwrap();
            (dir, path)
        }

        /// The default paths of the platform, plus `path` in each list.
        fn paths_with(path: &str) -> SandboxPaths {
            let mut paths = crate::system_default_paths();
            paths.traversal.push(path.to_string());
            paths.read.push(path.to_string());
            paths.execute.push(path.to_string());
            paths.read_write.push(path.to_string());
            paths
        }

        #[test]
        fn every_path_shape_gives_a_profile_that_compiles() {
            let (_dir, ws) = workspace();
            for (name, path) in SHAPES {
                let config = SandboxConfig::new(ws.clone(), paths_with(path), ws.clone());
                let profile = generate_sbpl_profile(&config).unwrap();
                assert_compiles(name, &profile);
            }
        }

        #[test]
        fn every_glob_shape_gives_a_profile_that_compiles() {
            let (_dir, ws) = workspace();
            for (name, path) in SHAPES {
                let config =
                    SandboxConfig::new(ws.clone(), paths_with(&format!("{path}*")), ws.clone());
                let profile = generate_sbpl_profile(&config).unwrap();
                assert_compiles(&format!("{name} (glob)"), &profile);
            }
        }

        #[test]
        fn a_workspace_with_an_odd_name_gives_a_profile_that_compiles() {
            let (_dir, base) = workspace();
            for (name, part) in [
                ("space", "a b"),
                ("single quote", "it's"),
                ("parentheses", "proj (copy)"),
                ("semicolon", "a;b"),
                ("hash", "a#b"),
                ("non-ASCII", "ünïcøde"),
            ] {
                let ws = base.join(part);
                std::fs::create_dir_all(&ws).unwrap();
                let config =
                    SandboxConfig::new(ws.clone(), crate::system_default_paths(), ws.clone());
                let profile = generate_sbpl_profile(&config).unwrap();
                assert_compiles(&format!("workspace {name}"), &profile);
            }
        }

        #[test]
        fn a_very_long_path_gives_a_profile_that_compiles() {
            let (_dir, ws) = workspace();
            // MAC-9. The reader of `sandbox-exec` has a length limit: the
            // run of 2026-10-25 on a Mac accepted a string of 512 bytes
            // and refused one of 1023 bytes with "Error reading string".
            // `PATH_MAX` is 1024 on macOS, so a path of the system never
            // reaches the limit. The test uses the longest path that the
            // kernel can give.
            let long = format!("/nonexistent/{}", "x".repeat(500));
            let config = SandboxConfig::new(ws.clone(), paths_with(&long), ws);
            let profile = generate_sbpl_profile(&config).unwrap();
            assert_compiles("very long", &profile);
        }

        /// MAC-9. A string over the limit of the reader gives a profile
        /// that `sandbox-exec` refuses. Such a path cannot come from the
        /// kernel, because `PATH_MAX` is 1024 on macOS, but the test holds
        /// the limit, so a later change of it is visible.
        #[test]
        fn a_path_over_the_limit_of_the_reader_gives_a_profile_that_it_refuses() {
            let (_dir, ws) = workspace();
            let long = format!("/nonexistent/{}", "x".repeat(3000));
            let config = SandboxConfig::new(ws.clone(), paths_with(&long), ws);
            let profile = generate_sbpl_profile(&config).unwrap();
            let (code, stderr) = compile(&profile);
            assert_ne!(
                code,
                Some(0),
                "sandbox-exec accepts a string of 3000 bytes now; MAC-9 is \
                 closed and this test must go\n--- stderr ---\n{stderr}"
            );
        }

        #[test]
        fn an_empty_profile_compiles() {
            let (_dir, ws) = workspace();
            let paths = SandboxPaths {
                traversal: vec![],
                read: vec![],
                execute: vec![],
                read_write: vec![],
            };
            let config = SandboxConfig::new(ws.clone(), paths, ws);
            let profile = generate_sbpl_profile(&config).unwrap();
            // The profile denies each file content read, so `/usr/bin/true`
            // cannot start. The check is the reader of the profile, not the
            // run: a parse error has another message.
            let (_code, stderr) = compile(&profile);
            assert!(
                !stderr.contains("sandbox-exec: ") || stderr.contains("Operation not permitted"),
                "sandbox-exec rejected the empty profile\n--- stderr ---\n{stderr}\n\
                 --- profile ---\n{profile}"
            );
        }

        #[test]
        fn every_network_mode_gives_a_profile_that_compiles() {
            let (_dir, ws) = workspace();
            let modes = [
                ("unrestricted", NetworkMode::Unrestricted),
                ("blocked", NetworkMode::Blocked),
                ("localhost", NetworkMode::LocalhostOnly),
                ("proxy", proxy_mode()),
            ];
            for (name, mode) in modes {
                let config =
                    SandboxConfig::new(ws.clone(), crate::system_default_paths(), ws.clone())
                        .with_network(mode);
                let profile = generate_sbpl_profile(&config).unwrap();
                assert_compiles(&format!("network {name}"), &profile);
            }
        }

        #[test]
        fn the_watch_profile_with_the_guard_rules_compiles() {
            let (_dir, ws) = workspace();
            let home = dirs::home_dir().unwrap_or_else(|| ws.clone());
            let guard = pent_profile::guard_rules(&home);
            assert!(!guard.is_empty(), "the guard list must not be empty");
            for mode in [
                NetworkMode::Unrestricted,
                NetworkMode::Blocked,
                proxy_mode(),
            ] {
                let config =
                    SandboxConfig::new(ws.clone(), crate::system_default_paths(), ws.clone())
                        .with_network(mode);
                let profile = generate_watch_profile(&config, &guard).unwrap();
                assert_compiles("watch", &profile);
            }
        }

        #[test]
        fn a_newline_in_a_path_is_rejected_before_generation() {
            let (_dir, ws) = workspace();
            let config = SandboxConfig::new(ws.clone(), paths_with("/nonexistent/a\nb"), ws);
            assert!(
                generate_sbpl_profile(&config).is_err(),
                "a newline in a path must not reach the profile"
            );
        }

        /// Run `/bin/cat path` under `profile` and return true when the
        /// read worked.
        fn can_read(profile: &str, path: &Path) -> (bool, String) {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("profile.sb");
            std::fs::write(&file, profile).unwrap();
            let out = Command::new(SANDBOX_EXEC)
                .arg("-f")
                .arg(&file)
                .arg("/bin/cat")
                .arg(path)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            (
                out.status.success(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            )
        }

        #[test]
        fn the_last_matching_rule_wins() {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().canonicalize().unwrap();
            let open = base.join("open.txt");
            let secret = base.join("secret.txt");
            std::fs::write(&open, "OPEN").unwrap();
            std::fs::write(&secret, "SECRET").unwrap();
            let allow = format!("(allow file-read-data (subpath \"{}\"))\n", base.display());
            let deny = format!("(deny file-read-data (literal \"{}\"))\n", secret.display());

            // The deny comes after the allow, so the deny wins.
            let deny_last = format!("(version 1)\n(allow default)\n{allow}{deny}");
            let (ok, stderr) = can_read(&deny_last, &secret);
            assert!(
                !ok,
                "the deny after the allow must win\n--- stderr ---\n{stderr}\n\
                 --- profile ---\n{deny_last}"
            );
            let (ok, stderr) = can_read(&deny_last, &open);
            assert!(ok, "the other file stays readable: {stderr}");

            // The allow comes after the deny, so the allow wins.
            let allow_last = format!("(version 1)\n(allow default)\n{deny}{allow}");
            let (ok, stderr) = can_read(&allow_last, &secret);
            assert!(
                ok,
                "the allow after the deny must win\n--- stderr ---\n{stderr}\n\
                 --- profile ---\n{allow_last}"
            );
        }
    }

    #[test]
    fn test_sbpl_profile_denies_project_config_writes_last() {
        let config =
            SandboxConfig::new("/workspace".into(), make_test_paths(), "/workspace".into());
        let profile = generate_sbpl_profile(&config).unwrap();
        let deny = r#"(deny file-write* (subpath "/workspace/.pent"))"#;
        let deny_at = profile.find(deny);
        let allow_at = profile.find(r#"(allow file-read-data file-write* (subpath "/workspace"))"#);
        assert!(deny_at.is_some(), "missing .pent deny: {profile}");
        assert!(allow_at.is_some(), "missing workspace allow: {profile}");
        // The last matching rule wins, so the deny must come after every
        // file-write allow.
        let last_allow = profile.rfind("(allow file-read-data file-write*");
        assert!(
            deny_at > last_allow,
            "the .pent deny must come last: {profile}"
        );
    }
}
