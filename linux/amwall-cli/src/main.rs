//! amwall-cli — manage rules.toml directly OR via D-Bus to a running
//! amwall-daemon.
//!
//!   amwall-cli list
//!   amwall-cli allow <comm> <ip>:<port>
//!   amwall-cli deny  <comm> <ip>:<port>
//!   amwall-cli del   <comm> <ip>:<port>
//!   amwall-cli reset [--yes] [--keep-rules] [--keep-config]
//!
//! <ip> is "any", an IPv4 literal, or a bracketed IPv6 literal:
//!   amwall-cli allow curl '[2001:db8::1]:443'
//!
//! Add `--dbus` to route the call through the daemon's
//! org.amwall.Daemon1 interface on the SYSTEM bus instead of editing
//! rules.toml. Requires amwall-daemon running and the policy file at
//! /etc/dbus-1/system.d/org.amwall.Daemon1.conf to be installed.
//!
//! `reset` truncates rules.toml AND clears ~/.config/amwall/ (the
//! GUI's QSettings dir). Equivalent to the Win32 amwall "Network
//! reset" item. Run as sudo for /etc/amwall/rules.toml; the user-
//! config part honors $SUDO_USER so it still targets the invoking
//! user's home directory rather than /root/.config/.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;

use amwall_core::rules::{Action, Rule, RulesFile};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "amwall-cli", version, about = "Manage amwall rules")]
struct Cli {
    /// Path to rules.toml (TOML mode only — ignored with --dbus).
    #[arg(long, env = "AMWALL_RULES_PATH")]
    rules: Option<PathBuf>,

    /// Talk to amwall-daemon via D-Bus instead of editing rules.toml.
    #[arg(long)]
    dbus: bool,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Clone)]
enum Cmd {
    /// Print current rules.
    List,
    /// Add an allow rule.
    Allow { comm: String, dest: String },
    /// Add a deny rule.
    Deny { comm: String, dest: String },
    /// Remove a rule.
    Del { comm: String, dest: String },
    /// Reset to clean state: truncate rules.toml + clear ~/.config/amwall/.
    /// Equivalent to Win32 amwall "Network reset". TOML mode only;
    /// run as sudo so it can write /etc/amwall/rules.toml.
    Reset {
        /// Skip the y/N confirmation prompt.
        #[arg(short = 'y', long)]
        yes: bool,
        /// Don't truncate rules.toml.
        #[arg(long)]
        keep_rules: bool,
        /// Don't clear ~/.config/amwall/.
        #[arg(long)]
        keep_config: bool,
    },
}

#[zbus::proxy(
    interface = "org.amwall.Daemon1",
    default_service = "org.amwall.Daemon1",
    default_path = "/org/amwall/Daemon1",
    gen_blocking = true,
    gen_async = false,
)]
trait AmwallDaemon {
    fn allow(&self, comm: &str, ip: &str, port: u16) -> zbus::Result<()>;
    fn deny(&self, comm: &str, ip: &str, port: u16) -> zbus::Result<()>;
    fn del(&self, comm: &str, ip: &str, port: u16) -> zbus::Result<()>;
    fn list(&self) -> zbus::Result<Vec<(String, String, u16, String)>>;
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.dbus {
        run_dbus(cli.command)
    } else {
        run_toml(cli.rules, cli.command)
    }
}

fn run_dbus(cmd: Cmd) -> Result<()> {
    if matches!(cmd, Cmd::Reset { .. }) {
        // Daemon doesn't expose a Reset method yet — would need to
        // truncate the file + clear the BPF map atomically under
        // the rules mutex. Until that lands, route through TOML
        // mode (which only needs sudo for /etc/amwall/rules.toml).
        anyhow::bail!(
            "--dbus reset is not implemented yet; use:\n  sudo amwall-cli reset");
    }

    let conn = zbus::blocking::Connection::system()
        .context("connecting to D-Bus system bus")?;
    let proxy = AmwallDaemonProxy::new(&conn)
        .context("creating D-Bus proxy (is amwall-daemon running?)")?;

    match cmd {
        Cmd::List => {
            let rules = proxy.list().context("D-Bus List() failed")?;
            if rules.is_empty() {
                println!("(no rules)");
            } else {
                for (c, ip, p, a) in rules {
                    println!("{:5}  comm={:<16} {}:{}", a.to_uppercase(), c, ip, p);
                }
            }
        }
        Cmd::Allow { comm, dest } => {
            let (ip, port) = parse_dest(&dest)?;
            proxy.allow(&comm, &ip, port).context("D-Bus Allow() failed")?;
            eprintln!("[via D-Bus] allowed: {} {}:{}", comm, ip, port);
        }
        Cmd::Deny { comm, dest } => {
            let (ip, port) = parse_dest(&dest)?;
            proxy.deny(&comm, &ip, port).context("D-Bus Deny() failed")?;
            eprintln!("[via D-Bus] denied: {} {}:{}", comm, ip, port);
        }
        Cmd::Del { comm, dest } => {
            let (ip, port) = parse_dest(&dest)?;
            proxy.del(&comm, &ip, port).context("D-Bus Del() failed")?;
            eprintln!("[via D-Bus] removed: {} {}:{}", comm, ip, port);
        }
        Cmd::Reset { .. } => unreachable!("handled by the matches!() guard above"),
    }
    Ok(())
}

fn run_toml(rules_arg: Option<PathBuf>, cmd: Cmd) -> Result<()> {
    if let Cmd::Reset { yes, keep_rules, keep_config } = cmd {
        return do_reset(rules_arg, yes, keep_rules, keep_config);
    }
    let path = rules_arg.unwrap_or_else(default_rules_path);
    let mut file = RulesFile::load(&path)?;

    match cmd {
        Cmd::List => {
            if file.rules.is_empty() {
                println!("(no rules — default-deny applies to all IPv4 connects)");
            } else {
                for r in &file.rules {
                    println!(
                        "{:5}  comm={:<16} {}:{}",
                        action_str(r.action),
                        r.comm,
                        r.ip,
                        r.port
                    );
                }
            }
            return Ok(());
        }
        Cmd::Allow { comm, dest } => upsert(&mut file, comm, dest, Action::Allow)?,
        Cmd::Deny  { comm, dest } => upsert(&mut file, comm, dest, Action::Deny)?,
        Cmd::Del   { comm, dest } => {
            let (ip, port) = parse_dest(&dest)?;
            file.rules.retain(|r| !(r.comm == comm && r.ip == ip && r.port == port));
        }
        Cmd::Reset { .. } => unreachable!("handled by the early-return at top of run_toml"),
    }

    file.save(&path)?;
    eprintln!("wrote {} ({} rules)", path.display(), file.rules.len());
    Ok(())
}

fn do_reset(rules_arg: Option<PathBuf>, yes: bool, keep_rules: bool, keep_config: bool) -> Result<()> {
    // Reset targets the SYSTEM rules.toml by default, not
    // ~/.config/amwall/rules.toml. Under sudo, default_rules_path()
    // would return /root/.config/... because HOME is reset to /root,
    // which is never what reset wants. --rules overrides if needed.
    let rules_path = rules_arg.unwrap_or_else(|| PathBuf::from("/etc/amwall/rules.toml"));
    let user_cfg = user_config_dir();

    eprintln!("amwall-cli reset:");
    if !keep_rules {
        eprintln!("  • truncate {}", rules_path.display());
    }
    if !keep_config {
        match &user_cfg {
            Some(p) => eprintln!("  • remove   {}", p.display()),
            None    => eprintln!("  • (no user-config dir found — SUDO_USER and HOME both unset)"),
        }
    }
    if keep_rules && keep_config {
        eprintln!("  (nothing to do — both --keep-rules and --keep-config set)");
        return Ok(());
    }

    if !yes {
        use std::io::Write;
        eprint!("Proceed? [y/N] ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)
            .context("reading confirmation from stdin")?;
        let line = line.trim();
        if !(line.eq_ignore_ascii_case("y") || line.eq_ignore_ascii_case("yes")) {
            eprintln!("aborted.");
            return Ok(());
        }
    }

    if !keep_rules {
        // Atomic truncate via empty-file write. Daemon mtime poll
        // catches it within ~100 ms and rebuilds its BPF map empty.
        // A missing file (ENOENT) is treated as success — the goal
        // of reset is "no rules", and a non-existent rules.toml
        // already satisfies that. This makes the linux-build.sh
        // pre-install hook safe on a fresh VM where /etc/amwall/
        // doesn't exist yet (it gets created by dpkg). For real
        // permission errors (EACCES on an existing /etc/amwall/),
        // the message is now accurate instead of speculating about
        // sudo.
        match std::fs::write(&rules_path, b"") {
            Ok(()) => {
                eprintln!("  ✓ truncated {}", rules_path.display());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!(
                    "  - {} did not exist (nothing to truncate)",
                    rules_path.display());
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(e).with_context(|| format!(
                    "truncating {} — needs sudo or write access to \
                     /etc/amwall/ (a prior `sudo amwall-gui` run can \
                     leave the dir root-owned with mode 0700)",
                    rules_path.display()));
            }
            Err(e) => {
                return Err(e).with_context(|| format!(
                    "truncating {}", rules_path.display()));
            }
        }
    }
    if !keep_config {
        if let Some(p) = user_cfg {
            if p.exists() {
                std::fs::remove_dir_all(&p)
                    .with_context(|| format!("removing {}", p.display()))?;
                eprintln!("  ✓ removed {}", p.display());
            } else {
                eprintln!("  - {} did not exist", p.display());
            }
        }
    }
    Ok(())
}

fn user_config_dir() -> Option<PathBuf> {
    // Honor SUDO_USER so `sudo amwall-cli reset` clears the invoking
    // user's config dir, not /root/.config/amwall/. Falls back to
    // $HOME for non-sudo invocations.
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() && sudo_user != "root" {
            return Some(PathBuf::from(format!("/home/{}/.config/amwall", sudo_user)));
        }
    }
    if let Ok(h) = std::env::var("HOME") {
        return Some(PathBuf::from(h).join(".config/amwall"));
    }
    None
}

fn upsert(file: &mut RulesFile, comm: String, dest: String, action: Action) -> Result<()> {
    let (ip, port) = parse_dest(&dest)?;
    file.rules.retain(|r| !(r.comm == comm && r.ip == ip && r.port == port));
    file.rules.push(Rule { comm, ip, port, action });
    Ok(())
}

fn parse_dest(s: &str) -> Result<(String, u16)> {
    // IPv6 destinations must be bracketed so the address colons don't
    // collide with the ip:port separator, e.g. "[2001:db8::1]:443".
    // Everything else (an IPv4 literal or "any") splits on the final ':'.
    if let Some(rest) = s.strip_prefix('[') {
        let (addr, port_s) = rest
            .split_once("]:")
            .with_context(|| format!("bracketed IPv6 dest must be '[addr]:port' (got '{}')", s))?;
        let port: u16 = port_s.parse().context("port must be 0-65535")?;
        let ip = Ipv6Addr::from_str(addr)
            .with_context(|| format!("'{}' is not a valid IPv6 address", addr))?;
        return Ok((ip.to_string(), port));
    }
    let (ip_s, port_s) = s
        .rsplit_once(':')
        .with_context(|| format!("dest must be 'ip:port' or '[v6]:port' (got '{}')", s))?;
    let port: u16 = port_s.parse().context("port must be 0-65535")?;
    let ip_norm = if ip_s.eq_ignore_ascii_case("any") || ip_s == "0.0.0.0" || ip_s.is_empty() {
        "any".to_string()
    } else {
        Ipv4Addr::from_str(ip_s)
            .with_context(|| {
                format!("ip '{}' is not 'any' or a v4 address (use [addr]:port for IPv6)", ip_s)
            })?
            .to_string()
    };
    Ok((ip_norm, port))
}

fn default_rules_path() -> PathBuf {
    if let Ok(h) = std::env::var("HOME") {
        PathBuf::from(h).join(".config/amwall/rules.toml")
    } else {
        PathBuf::from("/etc/amwall/rules.toml")
    }
}

fn action_str(a: Action) -> &'static str {
    match a { Action::Allow => "ALLOW", Action::Deny => "DENY" }
}
