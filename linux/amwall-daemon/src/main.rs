//! amwall-daemon — Phase 3 BPF LSM enforcement + D-Bus management.
//!
//! Architecture (Phase 3 / 3.5 / 4):
//!   - Main thread:     BPF setup, ringbuf drain, mtime poll, event print.
//!                      Forwards each ConnectEvent to the D-Bus thread
//!                      via a tokio mpsc unbounded channel.
//!   - D-Bus thread:    own tokio runtime, runs zbus SYSTEM-bus server
//!                      with org.amwall.Daemon1 interface. (System bus,
//!                      not session: the daemon is root, and root can't
//!                      auth onto a per-user session bus.) Emits
//!                      ConnectAttempt signal for each event received.
//!                      D-Bus method calls (Allow/Deny/Del/List) modify
//!                      rules.toml AND the BPF map directly.
//!                      Bus name registration requires the policy file
//!                      /etc/dbus-1/system.d/org.amwall.Daemon1.conf.
//!   - Polkit (Phase 4): Allow/Deny/Del methods call out to
//!                      org.freedesktop.PolicyKit1 to verify the caller
//!                      is authorized for action
//!                      `org.amwall.Daemon1.modify-rules`. Local-active
//!                      sessions pass without prompt (allow_active=yes
//!                      in the policy). List() stays open (read-only).
//!
//! Required env:    AMWALL_EBPF_PATH    path to the BPF ELF
//! Optional env:    AMWALL_RULES_PATH   path to rules.toml
//!                                       (default: ~/.config/amwall/rules.toml)

use std::collections::{HashMap as StdHashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use aya::maps::{HashMap as AyaHashMap, MapData, RingBuf};
use aya::programs::Lsm;
use aya::{Btf, Ebpf, Pod};
use tokio::sync::mpsc;

use amwall_core::rules::{Action, Rule, RulesFile};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const ACT_ALLOW: u8 = 1;

const POLKIT_ACTION_MODIFY: &str = "org.amwall.Daemon1.modify-rules";

#[repr(C)]
#[derive(Clone, Copy)]
struct ConnectEvent {
    pid: u32,
    comm: [u8; 16],
    family: u16,
    dest_port: u16,
    dest_ip4: u32,
    dest_ip6: [u8; 16],
    action: u8,
    _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct RuleKey {
    comm: [u8; 16],
    dest_ip4: u32,
    dest_port: u16,
    _pad: u16,
}

// Phase 6.4.1: parallel IPv6 BPF map. Mirror layout of amwall-ebpf's
// RuleKeyV6. The daemon installs a v6 wildcard entry for every "any"
// rule so a single user click covers v4 + v6 destinations.
#[repr(C)]
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct RuleKeyV6 {
    comm: [u8; 16],
    dest_ip6: [u8; 16],
    dest_port: u16,
    _pad: [u8; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RuleValue {
    action: u8,
    _pad: [u8; 7],
}

unsafe impl Pod for RuleKey {}
unsafe impl Pod for RuleKeyV6 {}
unsafe impl Pod for RuleValue {}

type RulesMap   = AyaHashMap<MapData, RuleKey,   RuleValue>;
type RulesV6Map = AyaHashMap<MapData, RuleKeyV6, RuleValue>;
type RulesShared   = Arc<Mutex<RulesMap>>;
type RulesV6Shared = Arc<Mutex<RulesV6Map>>;

// Phase 6.9 blocklist BPF maps. Key = u32 (v4) or [u8; 16] (v6)
// destination address in NETWORK byte order — matches the addr
// field of sockaddr_in/sockaddr_in6 the BPF program sees.
type BlocklistV4Map = AyaHashMap<MapData, u32, u8>;
type BlocklistV6Map = AyaHashMap<MapData, [u8; 16], u8>;
type BlocklistV4Shared = Arc<Mutex<BlocklistV4Map>>;
type BlocklistV6Shared = Arc<Mutex<BlocklistV6Map>>;

// ─── Blocklist module (Phase 6.9) ───────────────────────────────────

mod blocklist {
    use super::*;
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, Ipv6Addr};

    pub const LISTS_DIR: &str = "/usr/share/amwall/blocklists";
    pub const STATE_PATH: &str = "/etc/amwall/blocklists.toml";

    #[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
    pub struct State {
        #[serde(default)]
        pub enabled: Vec<String>,
    }

    impl State {
        pub fn load() -> Self {
            std::fs::read_to_string(STATE_PATH)
                .ok()
                .and_then(|s| toml::from_str(&s).ok())
                .unwrap_or_default()
        }

        pub fn save(&self) -> Result<()> {
            if let Some(parent) = Path::new(STATE_PATH).parent() {
                std::fs::create_dir_all(parent).ok();
            }
            let s = toml::to_string_pretty(self)
                .context("serializing blocklists state")?;
            std::fs::write(STATE_PATH, s)
                .with_context(|| format!("writing {}", STATE_PATH))?;
            Ok(())
        }
    }

    /// Metadata about one .txt file under LISTS_DIR — name (filename
    /// stem), short human description (first comment block of the
    /// file), and counts of v4 / v6 entries.
    pub struct ListMeta {
        pub name: String,
        pub description: String,
        pub v4_count: u32,
        pub v6_count: u32,
    }

    /// Scan LISTS_DIR for *.txt files. Returns name + counts.
    pub fn scan() -> Vec<ListMeta> {
        let mut out = Vec::new();
        let dir = match std::fs::read_dir(LISTS_DIR) {
            Ok(d) => d,
            Err(_) => return out,
        };
        for entry in dir.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("txt") {
                continue;
            }
            let name = match p.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let (description, v4, v6) = parse_list(&p);
            out.push(ListMeta {
                name,
                description,
                v4_count: v4.len() as u32,
                v6_count: v6.len() as u32,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Parse a list file: returns (one-line description, v4 set, v6 set).
    /// Description = first non-empty comment line stripped of the
    /// leading "# " — gives the user something better than the bare
    /// filename in the GUI.
    pub fn parse_list(path: &Path) -> (String, HashSet<u32>, HashSet<[u8; 16]>) {
        let mut desc = String::new();
        let mut v4 = HashSet::new();
        let mut v6 = HashSet::new();
        let contents = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return (desc, v4, v6),
        };
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() { continue; }
            if let Some(rest) = line.strip_prefix('#') {
                if desc.is_empty() {
                    desc = rest.trim().to_string();
                }
                continue;
            }
            if let Ok(a) = line.parse::<Ipv4Addr>() {
                // Store in network byte order — matches the addr
                // field in sockaddr_in the BPF program reads.
                v4.insert(u32::from(a).to_be());
            } else if let Ok(a) = line.parse::<Ipv6Addr>() {
                v6.insert(a.octets());
            }
            // Silently skip malformed lines — daemon stays robust
            // against typos in user-edited lists.
        }
        (desc, v4, v6)
    }

    /// Compute the desired union of v4 + v6 addresses across all
    /// enabled lists, then diff against current BPF map state and
    /// add/remove entries to converge. No reload "off" window —
    /// matches the rules.toml sync pattern.
    pub fn sync(
        map_v4: &mut BlocklistV4Map,
        map_v6: &mut BlocklistV6Map,
        state:  &State,
    ) -> Result<(usize, usize)> {
        let mut want_v4: HashSet<u32> = HashSet::new();
        let mut want_v6: HashSet<[u8; 16]> = HashSet::new();
        for name in &state.enabled {
            let path = PathBuf::from(LISTS_DIR).join(format!("{}.txt", name));
            let (_d, v4, v6) = parse_list(&path);
            want_v4.extend(v4);
            want_v6.extend(v6);
        }

        let current_v4: HashSet<u32> =
            map_v4.keys().filter_map(Result::ok).collect();
        let current_v6: HashSet<[u8; 16]> =
            map_v6.keys().filter_map(Result::ok).collect();

        // Remove dropped entries
        for k in current_v4.difference(&want_v4) {
            map_v4.remove(k).ok();
        }
        for k in current_v6.difference(&want_v6) {
            map_v6.remove(k).ok();
        }
        // Add new entries
        for k in want_v4.difference(&current_v4) {
            map_v4.insert(k, 1u8, 0).with_context(
                || format!("BLOCKLIST_V4 insert {:08x}", k))?;
        }
        for k in want_v6.difference(&current_v6) {
            map_v6.insert(k, 1u8, 0).with_context(
                || format!("BLOCKLIST_V6 insert"))?;
        }
        Ok((want_v4.len(), want_v6.len()))
    }
}

// ─── D-Bus interface ────────────────────────────────────────────────

struct AmwallDaemon {
    rules:        RulesShared,
    rules_v6:     RulesV6Shared,
    rules_path:   PathBuf,
    blocklist_v4: BlocklistV4Shared,
    blocklist_v6: BlocklistV6Shared,
}

#[zbus::interface(name = "org.amwall.Daemon1")]
impl AmwallDaemon {
    async fn allow(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        comm: String,
        ip: String,
        port: u16,
    ) -> zbus::fdo::Result<()> {
        check_polkit(conn, &header, POLKIT_ACTION_MODIFY).await?;
        self.modify(comm, ip, port, Action::Allow)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    async fn deny(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        comm: String,
        ip: String,
        port: u16,
    ) -> zbus::fdo::Result<()> {
        check_polkit(conn, &header, POLKIT_ACTION_MODIFY).await?;
        self.modify(comm, ip, port, Action::Deny)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    async fn del(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        comm: String,
        ip: String,
        port: u16,
    ) -> zbus::fdo::Result<()> {
        check_polkit(conn, &header, POLKIT_ACTION_MODIFY).await?;
        self.delete(comm, ip, port)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    async fn list(&self) -> zbus::fdo::Result<Vec<(String, String, u16, String)>> {
        let cfg = RulesFile::load(&self.rules_path)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(cfg.rules.iter()
            .map(|r| (
                r.comm.clone(),
                r.ip.clone(),
                r.port,
                action_to_str(r.action).to_string(),
            ))
            .collect())
    }

    // ResolveSockets: take a list of socket inodes (column [9] of
    // /proc/net/tcp{,6}) and return (inode, pid, comm, exe) tuples
    // for every PID that owns one of them. The daemon runs as root
    // so it can read /proc/<pid>/fd for every process — the GUI
    // (running as the desktop user) can't, which is why this lives
    // here. Inodes the daemon couldn't match (kernel-only sockets,
    // closed-by-the-time-we-walked race) are simply omitted from
    // the result rather than returning sentinel rows.
    //
    // ─── Phase 6.9 blocklist API ────────────────────────────────────

    // BlocklistList: returns (name, description, v4_count, v6_count,
    // enabled) for every .txt file under /usr/share/amwall/blocklists.
    // Read-only, no polkit gate.
    async fn blocklist_list(
        &self,
    ) -> zbus::fdo::Result<Vec<(String, String, u32, u32, bool)>> {
        let state = blocklist::State::load();
        let enabled: std::collections::HashSet<&String> =
            state.enabled.iter().collect();
        let mut out = Vec::new();
        for m in blocklist::scan() {
            let is_on = enabled.contains(&m.name);
            out.push((m.name, m.description, m.v4_count, m.v6_count, is_on));
        }
        Ok(out)
    }

    // BlocklistSetEnabled: flip the enabled bit for one list and
    // re-sync the BPF maps. polkit-gated under the same action as
    // rule modification — toggling a blocklist is policy-equivalent
    // to writing a deny rule.
    async fn blocklist_set_enabled(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        name: String,
        enabled: bool,
    ) -> zbus::fdo::Result<()> {
        check_polkit(conn, &header, POLKIT_ACTION_MODIFY).await?;

        let mut state = blocklist::State::load();
        let already = state.enabled.iter().any(|n| n == &name);
        if enabled && !already {
            state.enabled.push(name.clone());
        } else if !enabled && already {
            state.enabled.retain(|n| n != &name);
        } else {
            return Ok(());  // no-op, already in desired state
        }
        state.save().map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let mut map_v4 = self.blocklist_v4.lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("v4 lock: {}", e)))?;
        let mut map_v6 = self.blocklist_v6.lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("v6 lock: {}", e)))?;
        let (n4, n6) = blocklist::sync(&mut map_v4, &mut map_v6, &state)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        eprintln!("[USER ] blocklist {} {} (now {} v4 + {} v6 entries)",
            if enabled { "ENABLE" } else { "DISABLE" },
            name, n4, n6);
        Ok(())
    }

    // Reset: clear everything the daemon owns — rules.toml truncated,
    // blocklists.toml deleted, BPF maps emptied. Polkit-gated under
    // modify-rules since it's the heaviest possible modify. The GUI's
    // own QSettings (window geometry, prompt timeout, etc.) lives in
    // the user's home and is cleared GUI-side, not here — keeps the
    // privilege boundary clean.
    async fn reset(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        check_polkit(conn, &header, POLKIT_ACTION_MODIFY).await?;

        // 1. Truncate rules.toml. The daemon's own mtime poll will
        //    rebuild the BPF maps empty within ~100 ms — we don't
        //    need to clear them ourselves and risk a race against
        //    that loop.
        std::fs::write(&self.rules_path, b"")
            .map_err(|e| zbus::fdo::Error::Failed(
                format!("truncating {}: {}", self.rules_path.display(), e)))?;
        eprintln!("[USER ] RESET truncated {}", self.rules_path.display());

        // 2. Remove blocklists state file. Then sync BPF blocklist
        //    maps with empty state — same diff path the
        //    BlocklistSetEnabled D-Bus method uses, just with a
        //    State that has no enabled lists.
        let bl_state_path = std::path::Path::new(blocklist::STATE_PATH);
        if bl_state_path.exists() {
            std::fs::remove_file(bl_state_path)
                .map_err(|e| zbus::fdo::Error::Failed(
                    format!("removing {}: {}", bl_state_path.display(), e)))?;
            eprintln!("[USER ] RESET removed {}", bl_state_path.display());
        }
        let empty_state = blocklist::State::default();
        {
            let mut map_v4 = self.blocklist_v4.lock()
                .map_err(|e| zbus::fdo::Error::Failed(format!("v4 lock: {}", e)))?;
            let mut map_v6 = self.blocklist_v6.lock()
                .map_err(|e| zbus::fdo::Error::Failed(format!("v6 lock: {}", e)))?;
            blocklist::sync(&mut map_v4, &mut map_v6, &empty_state)
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        }
        eprintln!("[USER ] RESET complete (rules + blocklists cleared)");
        Ok(())
    }

    async fn resolve_sockets(
        &self,
        inodes: Vec<u64>,
    ) -> zbus::fdo::Result<Vec<(u64, u32, String, String)>> {
        if inodes.is_empty() {
            return Ok(Vec::new());
        }
        let wanted: std::collections::HashSet<u64> = inodes.into_iter().collect();
        let mut out = Vec::new();

        let proc_dir = match std::fs::read_dir("/proc") {
            Ok(d) => d,
            Err(e) => return Err(zbus::fdo::Error::Failed(
                format!("read_dir /proc: {}", e))),
        };
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_s = name.to_string_lossy();
            let pid: u32 = match name_s.parse() {
                Ok(p) => p,
                Err(_) => continue,  // non-numeric (cmdline, sys, etc.)
            };

            let fd_path = format!("/proc/{}/fd", pid);
            let fd_dir = match std::fs::read_dir(&fd_path) {
                Ok(d) => d,
                Err(_) => continue,  // proc died / EACCES
            };

            let mut resolved_meta = false;
            let mut comm = String::new();
            let mut exe  = String::new();

            for fd_entry in fd_dir.flatten() {
                let target = match std::fs::read_link(fd_entry.path()) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let target_s = target.to_string_lossy();
                if !target_s.starts_with("socket:[") {
                    continue;
                }
                let inner = &target_s[8..];
                let close = match inner.find(']') {
                    Some(c) => c,
                    None => continue,
                };
                let inode: u64 = match inner[..close].parse() {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                if !wanted.contains(&inode) {
                    continue;
                }
                if !resolved_meta {
                    comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    exe = std::fs::read_link(format!("/proc/{}/exe", pid))
                        .ok()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    resolved_meta = true;
                }
                out.push((inode, pid, comm.clone(), exe.clone()));
            }
        }
        Ok(out)
    }

    #[zbus(signal)]
    async fn connect_attempt(
        ctx: &zbus::SignalContext<'_>,
        pid: u32,
        comm: String,
        ip: String,
        port: u16,
        action: String,
    ) -> zbus::Result<()>;
}

impl AmwallDaemon {
    fn modify(&self, comm: String, ip: String, port: u16, action: Action) -> Result<()> {
        // Surface user/CLI rule changes in the daemon log so triage
        // can correlate "user clicked Allow" → subsequent connection
        // events. Polkit gating already happened in the D-Bus method
        // handler; if we're here the change is authorised.
        eprintln!(
            "[USER ] {} comm={} {}:{} (D-Bus rule change)",
            if matches!(action, Action::Allow) { "ALLOW" } else { "DENY " },
            comm, ip,
            if port == 0 { "any".to_string() } else { port.to_string() },
        );

        // Persist to TOML.
        let mut cfg = RulesFile::load(&self.rules_path).unwrap_or_default();
        cfg.rules.retain(|r| !(r.comm == comm && r.ip == ip && r.port == port));
        cfg.rules.push(Rule { comm: comm.clone(), ip: ip.clone(), port, action });
        cfg.save(&self.rules_path)?;

        // Apply to BPF map immediately. (mtime poll will also trigger
        // a reload moments later — harmless thanks to the diff-style
        // reload that doesn't transiently empty the map.)
        let rule = Rule { comm, ip, port, action };
        let val = RuleValue { action: rule.action_byte(), _pad: [0; 7] };

        // IPv4 map (always — "any" is dest_ip4=0 which is the v4 wildcard).
        let key = RuleKey {
            comm: rule.comm_bytes(),
            dest_ip4: rule.ip4()?,
            dest_port: rule.port,
            _pad: 0,
        };
        {
            let mut map = self.rules.lock().map_err(|_| anyhow::anyhow!("rules mutex poisoned"))?;
            map.insert(key, val, 0)
                .with_context(|| format!("inserting v4 via D-Bus: {:?}", rule))?;
        }

        // Phase 6.4.1: also mirror "any" rules into the v6 wildcard
        // slot. Specific IPv6 addresses aren't supported via the
        // current rules.toml schema (no v6 parsing path) — only "any"
        // touches the v6 map for now. Future: add a v6 ip parsing
        // branch alongside ip4().
        if rule.ip == "any" {
            let key6 = RuleKeyV6 {
                comm: rule.comm_bytes(),
                dest_ip6: [0; 16],
                dest_port: rule.port,
                _pad: [0; 6],
            };
            let mut map6 = self.rules_v6.lock().map_err(|_| anyhow::anyhow!("rules_v6 mutex poisoned"))?;
            map6.insert(key6, val, 0)
                .with_context(|| format!("inserting v6 wildcard via D-Bus: {:?}", rule))?;
        }
        Ok(())
    }

    fn delete(&self, comm: String, ip: String, port: u16) -> Result<()> {
        eprintln!(
            "[USER ] DEL   comm={} {}:{} (D-Bus rule change)",
            comm, ip,
            if port == 0 { "any".to_string() } else { port.to_string() },
        );

        let mut cfg = RulesFile::load(&self.rules_path).unwrap_or_default();
        cfg.rules.retain(|r| !(r.comm == comm && r.ip == ip && r.port == port));
        cfg.save(&self.rules_path)?;

        // Best-effort BPF map removal. Need a Rule to compute the key
        // — action doesn't matter for keying.
        let was_any = ip == "any";
        let dummy = Rule { comm, ip, port, action: Action::Allow };
        let key = RuleKey {
            comm: dummy.comm_bytes(),
            dest_ip4: dummy.ip4()?,
            dest_port: dummy.port,
            _pad: 0,
        };
        {
            let mut map = self.rules.lock().map_err(|_| anyhow::anyhow!("rules mutex poisoned"))?;
            let _ = map.remove(&key);
        }
        // Mirror the "any" → v6-wildcard pairing on delete.
        if was_any {
            let key6 = RuleKeyV6 {
                comm: dummy.comm_bytes(),
                dest_ip6: [0; 16],
                dest_port: dummy.port,
                _pad: [0; 6],
            };
            let mut map6 = self.rules_v6.lock().map_err(|_| anyhow::anyhow!("rules_v6 mutex poisoned"))?;
            let _ = map6.remove(&key6);
        }
        Ok(())
    }
}

fn action_to_str(a: Action) -> &'static str {
    match a { Action::Allow => "allow", Action::Deny => "deny" }
}

// ─── Polkit (Phase 4) ───────────────────────────────────────────────
//
// CheckAuthorization on org.freedesktop.PolicyKit1.Authority.
//   subject       (sa{sv})  = ("system-bus-name", { "name": <caller> })
//   action_id     s         = "org.amwall.Daemon1.modify-rules"
//   details       a{ss}     = empty
//   flags         u         = 1 (AllowUserInteraction)
//   cancellation  s         = ""
//   → result      (bba{ss}) = (is_authorized, is_challenge, details)
async fn check_polkit(
    conn: &zbus::Connection,
    header: &zbus::message::Header<'_>,
    action_id: &str,
) -> zbus::fdo::Result<()> {
    use std::collections::HashMap;
    use zbus::zvariant::Value;

    let sender = header
        .sender()
        .ok_or_else(|| zbus::fdo::Error::Failed("D-Bus message has no sender".into()))?;

    let mut subject_details: HashMap<&str, Value<'_>> = HashMap::new();
    subject_details.insert("name", Value::from(sender.as_str()));
    let subject: (&str, HashMap<&str, Value<'_>>) = ("system-bus-name", subject_details);

    let details: HashMap<&str, &str> = HashMap::new();
    let flags: u32 = 1; // AllowUserInteraction

    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
    )
    .await
    .map_err(|e| zbus::fdo::Error::Failed(format!("polkit proxy: {e}")))?;

    let (is_authorized, _is_challenge, _out_details): (bool, bool, HashMap<String, String>) =
        proxy
            .call(
                "CheckAuthorization",
                &(subject, action_id, details, flags, ""),
            )
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("polkit CheckAuthorization: {e}")))?;

    if is_authorized {
        Ok(())
    } else {
        Err(zbus::fdo::Error::AuthFailed(format!(
            "polkit denied '{action_id}' for caller {sender}"
        )))
    }
}

// ─── D-Bus thread (own tokio runtime) ───────────────────────────────

async fn run_dbus_server(
    rules: RulesShared,
    rules_v6: RulesV6Shared,
    blocklist_v4: BlocklistV4Shared,
    blocklist_v6: BlocklistV6Shared,
    rules_path: PathBuf,
    mut event_rx: mpsc::UnboundedReceiver<ConnectEvent>,
) -> Result<()> {
    eprintln!("amwall-daemon: D-Bus thread starting (system bus)");

    let iface = AmwallDaemon {
        rules, rules_v6, rules_path,
        blocklist_v4, blocklist_v6,
    };
    let conn = zbus::connection::Builder::system()
        .context("system bus connection (is dbus running?)")?
        .name("org.amwall.Daemon1")
        .context("requesting bus name (policy file installed?)")?
        .serve_at("/org/amwall/Daemon1", iface)
        .context("registering interface")?
        .build()
        .await
        .context("building zbus connection")?;

    let object_server = conn.object_server();
    let iface_ref: zbus::InterfaceRef<AmwallDaemon> = object_server
        .interface("/org/amwall/Daemon1")
        .await
        .context("getting interface ref")?;

    eprintln!("amwall-daemon: D-Bus interface registered at org.amwall.Daemon1 (system bus)");

    while let Some(ev) = event_rx.recv().await {
        let comm = comm_str_owned(&ev.comm);
        let ip = match ev.family {
            AF_INET => Ipv4Addr::from(u32::from_be(ev.dest_ip4)).to_string(),
            AF_INET6 => Ipv6Addr::from(ev.dest_ip6).to_string(),
            other => format!("(family={})", other),
        };
        let action = if ev.action == ACT_ALLOW { "allow" } else { "deny" }.to_string();

        // Best-effort emit; signals to no-listener buses are normal.
        let _ = AmwallDaemon::connect_attempt(
            iface_ref.signal_context(),
            ev.pid,
            comm,
            ip,
            ev.dest_port,
            action,
        ).await;
    }

    Ok(())
}

// ─── Main thread (sync BPF + ringbuf + mtime poll) ──────────────────

fn main() -> Result<()> {
    let ebpf_path: PathBuf = std::env::var("AMWALL_EBPF_PATH")
        .context("AMWALL_EBPF_PATH env var not set")?
        .into();
    let rules_path = rules_path_from_env();

    eprintln!("amwall-daemon: BPF ELF = {}", ebpf_path.display());
    eprintln!("amwall-daemon: rules   = {}", rules_path.display());

    let mut ebpf = Ebpf::load_file(&ebpf_path)
        .with_context(|| format!("loading BPF ELF from {}", ebpf_path.display()))?;
    let btf = Btf::from_sys_fs()
        .context("loading vmlinux BTF (CONFIG_DEBUG_INFO_BTF must be enabled)")?;

    let program: &mut Lsm = ebpf
        .program_mut("amwall_socket_connect")
        .context("amwall_socket_connect program not found in BPF ELF")?
        .try_into()
        .context("amwall_socket_connect is not an Lsm program")?;
    program.load("socket_connect", &btf).context("loading LSM program")?;
    program.attach().context("attaching LSM program")?;

    let rules_raw_map = ebpf.take_map("RULES").context("RULES map missing")?;
    let rules_raw: RulesMap = AyaHashMap::try_from(rules_raw_map)
        .context("RULES map is not a HashMap")?;
    let rules: RulesShared = Arc::new(Mutex::new(rules_raw));

    // Phase 6.4.1: parallel IPv6 rule map.
    let rules_v6_raw_map = ebpf.take_map("RULES_V6").context("RULES_V6 map missing")?;
    let rules_v6_raw: RulesV6Map = AyaHashMap::try_from(rules_v6_raw_map)
        .context("RULES_V6 map is not a HashMap")?;
    let rules_v6: RulesV6Shared = Arc::new(Mutex::new(rules_v6_raw));

    // Phase 6.9: blocklist maps. Checked BEFORE per-comm rules in
    // amwall-ebpf::decide, so a hit overrides any user-set allow.
    let bl4_raw_map = ebpf.take_map("BLOCKLIST_V4").context("BLOCKLIST_V4 map missing")?;
    let bl4_raw: BlocklistV4Map = AyaHashMap::try_from(bl4_raw_map)
        .context("BLOCKLIST_V4 is not a HashMap")?;
    let blocklist_v4: BlocklistV4Shared = Arc::new(Mutex::new(bl4_raw));

    let bl6_raw_map = ebpf.take_map("BLOCKLIST_V6").context("BLOCKLIST_V6 map missing")?;
    let bl6_raw: BlocklistV6Map = AyaHashMap::try_from(bl6_raw_map)
        .context("BLOCKLIST_V6 is not a HashMap")?;
    let blocklist_v6: BlocklistV6Shared = Arc::new(Mutex::new(bl6_raw));

    let events_map = ebpf.take_map("EVENTS").context("EVENTS map missing")?;
    let mut events = RingBuf::try_from(events_map).context("EVENTS map is not a ring buffer")?;

    // Initial rule load — populates both v4 and v6 maps from rules.toml.
    {
        let mut map = rules.lock().unwrap();
        let mut map_v6 = rules_v6.lock().unwrap();
        match reload_rules(&mut map, &mut map_v6, &rules_path) {
            Ok(n) => eprintln!("amwall-daemon: loaded {} rules from {}", n, rules_path.display()),
            Err(e) => eprintln!("amwall-daemon: rules load failed: {}", e),
        }
    }
    // Initial blocklist sync (Phase 6.9). No-op when no lists are
    // enabled — /etc/amwall/blocklists.toml only gets written on the
    // first BlocklistSetEnabled D-Bus call.
    {
        let state = blocklist::State::load();
        let mut map_v4 = blocklist_v4.lock().unwrap();
        let mut map_v6 = blocklist_v6.lock().unwrap();
        match blocklist::sync(&mut map_v4, &mut map_v6, &state) {
            Ok((n4, n6)) => eprintln!(
                "amwall-daemon: blocklist active — {} v4 + {} v6 entries from {} list(s)",
                n4, n6, state.enabled.len()),
            Err(e) => eprintln!("amwall-daemon: blocklist sync failed: {}", e),
        }
    }
    eprintln!("amwall-daemon: enforcement ON. Default-deny on IPv4 + IPv6. Ctrl-C to exit.");

    // Channel from BPF drain → D-Bus signal emit.
    let (event_tx, event_rx) = mpsc::unbounded_channel::<ConnectEvent>();

    let dbus_rules    = rules.clone();
    let dbus_rules_v6 = rules_v6.clone();
    let dbus_bl4      = blocklist_v4.clone();
    let dbus_bl6      = blocklist_v6.clone();
    let dbus_path     = rules_path.clone();
    let dbus_thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime build");
        if let Err(e) = rt.block_on(run_dbus_server(
            dbus_rules, dbus_rules_v6, dbus_bl4, dbus_bl6, dbus_path, event_rx))
        {
            eprintln!("amwall-daemon: D-Bus server stopped:");
            for cause in e.chain() {
                eprintln!("  caused by: {}", cause);
            }
        }
    });

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || r.store(false, Ordering::SeqCst))
        .context("installing Ctrl-C handler")?;

    let mut last_mtime = mtime_of(&rules_path);

    while running.load(Ordering::SeqCst) {
        while let Some(item) = events.next() {
            let bytes: &[u8] = &item;
            if bytes.len() < std::mem::size_of::<ConnectEvent>() { continue; }
            let ev: ConnectEvent = unsafe {
                std::ptr::read_unaligned(bytes.as_ptr() as *const ConnectEvent)
            };
            print_event(&ev);
            // Best-effort signal forwarding.
            let _ = event_tx.send(ev);
        }

        let now = mtime_of(&rules_path);
        if now != last_mtime {
            let mut map = rules.lock().unwrap();
            let mut map_v6 = rules_v6.lock().unwrap();
            match reload_rules(&mut map, &mut map_v6, &rules_path) {
                Ok(n) => eprintln!("amwall-daemon: rules reloaded ({} entries)", n),
                Err(e) => eprintln!("amwall-daemon: rules reload FAILED: {}", e),
            }
            drop(map);
            drop(map_v6);
            last_mtime = now;
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    eprintln!("amwall-daemon: shutting down (BPF auto-unloads).");
    drop(event_tx); // closes channel → D-Bus thread exits its recv loop
    let _ = dbus_thread.join();
    Ok(())
}

fn rules_path_from_env() -> PathBuf {
    if let Ok(p) = std::env::var("AMWALL_RULES_PATH") { return p.into(); }
    if let Ok(h) = std::env::var("HOME") {
        return PathBuf::from(h).join(".config/amwall/rules.toml");
    }
    PathBuf::from("/etc/amwall/rules.toml")
}

fn mtime_of(path: &Path) -> SystemTime {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

// Diff-style reload: compute desired state, then add/remove rather
// than clear-then-insert. Avoids the brief "default-deny everything"
// window during reload (kernel could see an empty RULES map otherwise).
//
// Phase 6.4.1: also maintains RULES_V6. For each rule with ip="any"
// we install a v6 wildcard slot too, so a single user rule covers
// both address families. Specific IPv6 addresses aren't yet
// representable in rules.toml — only the "any" wildcard reaches v6.
fn reload_rules(map: &mut RulesMap, map_v6: &mut RulesV6Map, path: &Path) -> Result<usize> {
    let cfg = RulesFile::load(path)?;

    let mut desired_v4: StdHashMap<RuleKey, RuleValue> = StdHashMap::new();
    let mut desired_v6: StdHashMap<RuleKeyV6, RuleValue> = StdHashMap::new();
    for r in &cfg.rules {
        let val = RuleValue { action: r.action_byte(), _pad: [0; 7] };
        let key = RuleKey {
            comm: r.comm_bytes(),
            dest_ip4: r.ip4()?,
            dest_port: r.port,
            _pad: 0,
        };
        desired_v4.insert(key, val);
        if r.ip == "any" {
            let key6 = RuleKeyV6 {
                comm: r.comm_bytes(),
                dest_ip6: [0; 16],
                dest_port: r.port,
                _pad: [0; 6],
            };
            desired_v6.insert(key6, val);
        }
    }

    let current_v4: HashSet<RuleKey> = map.keys().filter_map(Result::ok).collect();
    for k in &current_v4 {
        if !desired_v4.contains_key(k) {
            let _ = map.remove(k);
        }
    }
    for (k, v) in &desired_v4 {
        map.insert(*k, *v, 0)?;
    }

    let current_v6: HashSet<RuleKeyV6> = map_v6.keys().filter_map(Result::ok).collect();
    for k in &current_v6 {
        if !desired_v6.contains_key(k) {
            let _ = map_v6.remove(k);
        }
    }
    for (k, v) in &desired_v6 {
        map_v6.insert(*k, *v, 0)?;
    }

    Ok(cfg.rules.len())
}

fn print_event(e: &ConnectEvent) {
    // Per-family tag so log readers can distinguish rule-driven
    // decisions from default-allow paths:
    //   [ALLOW] / [DENY ]  — IPv4 OR IPv6, evaluated against rules.
    //                        v6 has its own family-prefixed variant
    //                        below so reads scan as "v4 vs v6 deny".
    //   [LOCAL]            — AF_UNIX / AF_NETLINK / etc. — local IPC,
    //                        not a network policy concern (matches
    //                        simplewall behavior on Windows).
    //   [USER ]            — appears separately from modify()/delete()
    //                        when a user/CLI action persists a rule.
    let comm = comm_str(&e.comm);
    let (tag, dest) = match e.family {
        AF_INET => {
            let host = u32::from_be(e.dest_ip4);
            let t = if e.action == ACT_ALLOW { "ALLOW" } else { "DENY " };
            (t, format!("{}:{}", Ipv4Addr::from(host), e.dest_port))
        }
        AF_INET6 => {
            let t = if e.action == ACT_ALLOW { "V6 OK" } else { "V6 NO" };
            (t, format!("[{}]:{}", Ipv6Addr::from(e.dest_ip6), e.dest_port))
        }
        _ => (
            "LOCAL",
            format!("(family={})", e.family),
        ),
    };
    eprintln!("[{}] pid={} comm={} dest={}", tag, e.pid, comm, dest);
}

fn comm_str(bytes: &[u8; 16]) -> &str {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).unwrap_or("?")
}

fn comm_str_owned(bytes: &[u8; 16]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
