//! Elevated live probe for the Connections-tab traffic columns (upstream
//! PR #2100 port). Repeatedly samples per-connection TCP ESTATS and prints
//! any connection that became stats-enabled and any that moved bytes.
//!
//! This is the "instrument the success" check for the ESTATS FFI: a wrong
//! version/size constant would compile and silently return zeros, and the
//! gate triad can't see that. Run it from an ELEVATED shell — enabling
//! collection needs admin, so without it every row stays blank (which is
//! itself the correct graceful-degradation behavior).
//!
//!   cargo run --release --example traffic_probe   (elevated)

#[cfg(windows)]
fn main() {
    use amwall::gui::connections::{enumerate_with_traffic, format_bytesize, format_speed, TrafficMonitor};
    use std::time::Duration;

    // Elevated children get a fresh console whose stdout is discarded, so
    // an optional argv[1] names a file to also write the report to.
    let out_path = std::env::args().nth(1);
    let mut report = String::new();
    macro_rules! line { ($($a:tt)*) => {{ let s = format!($($a)*); println!("{s}"); report.push_str(&s); report.push('\n'); }}; }

    let mut monitor = TrafficMonitor::new();
    let rounds = 8;
    let mut max_enabled = 0usize;
    let mut ever_moved = 0usize;

    for round in 0..rounds {
        let conns = enumerate_with_traffic(&mut monitor);
        let enabled = conns.iter().filter(|c| c.has_stats).count();
        max_enabled = max_enabled.max(enabled);

        if round == rounds - 1 {
            line!("--- final sample: {} connections, {enabled} stats-enabled ---", conns.len());
            for c in &conns {
                if c.has_stats && (c.total_bytes > 0 || c.download_speed > 0 || c.upload_speed > 0) {
                    line!(
                        "{:<22} {}:{} -> {}:{}  down {:>10}  up {:>10}  total {:>10}",
                        c.process,
                        c.local.ip,
                        c.local.port,
                        c.remote.ip,
                        c.remote.port,
                        format_speed(c.download_speed),
                        format_speed(c.upload_speed),
                        format_bytesize(c.total_bytes),
                    );
                    ever_moved += 1;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(900));
    }

    // --- features 2 & 3: interface map + per-app rollup ---
    use amwall::gui::connections::{interface_names_by_ip, process_full_path};
    use std::collections::HashMap;
    use std::path::PathBuf;
    let ifaces = interface_names_by_ip();
    line!("");
    line!("--- {} interface IP(s) mapped ---", ifaces.len());
    {
        // Print each distinct interface name once.
        let mut names: Vec<&String> = ifaces.values().collect();
        names.sort();
        names.dedup();
        for n in names {
            line!("  interface: {n}");
        }
    }
    let conns = enumerate_with_traffic(&mut monitor);
    let mut pid_path: HashMap<u32, Option<PathBuf>> = HashMap::new();
    let mut rollup: HashMap<PathBuf, (u64, u64, Vec<String>)> = HashMap::new();
    for c in &conns {
        let path = pid_path.entry(c.pid).or_insert_with(|| process_full_path(c.pid)).clone();
        let Some(path) = path else { continue };
        let e = rollup.entry(path).or_insert((0, 0, Vec::new()));
        e.0 += c.download_speed;
        e.1 += c.upload_speed;
        if let Some(n) = ifaces.get(&c.local.ip) {
            if !e.2.iter().any(|x| x == n) {
                e.2.push(n.clone());
            }
        }
    }
    line!("--- per-app rollup ({} apps with connections) ---", rollup.len());
    for (path, (down, up, ifs)) in &rollup {
        let name = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        line!(
            "  {:<24} down {:>10}  up {:>10}  iface [{}]",
            name,
            format_speed(*down),
            format_speed(*up),
            ifs.join(", ")
        );
    }

    line!("");
    line!("ESTATS enabled on at least {max_enabled} connection(s) at peak.");
    line!("Connections with observed traffic in the final pass: {ever_moved}.");
    if max_enabled == 0 {
        line!("RESULT: no rows became stats-enabled — either not elevated, or the FFI is wrong.");
    } else if ever_moved == 0 {
        line!("RESULT: FFI works (rows enabled) but the machine was idle — no bytes moved to confirm counts.");
    } else {
        line!("RESULT: OK — ESTATS FFI returns real per-connection byte counts.");
    }

    if let Some(p) = out_path {
        let _ = std::fs::write(p, report);
    }
}

#[cfg(not(windows))]
fn main() {}
