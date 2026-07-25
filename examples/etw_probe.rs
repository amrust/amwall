//! Elevated live check for the ETW per-process network meter. Starts the
//! real Kernel-Network trace, samples per-PID throughput once a second,
//! and prints the top talkers resolved to process names. Compare a
//! torrent client's row here against the client's own speed readout: if
//! the ETW meter is wired correctly it should MATCH (TCP+UDP), whereas
//! the TCP-only ESTATS path under-reads a µTP torrent badly.
//!
//!   cargo run --release --example etw_probe   (elevated)

#[cfg(windows)]
fn main() {
    use amwall::gui::connections::{format_speed, process_full_path};
    use amwall::gui::net_meter::NetMeter;
    use std::collections::HashMap;
    use std::time::Duration;

    let out_path = std::env::args().nth(1);
    let mut report = String::new();
    macro_rules! line { ($($a:tt)*) => {{ let s = format!($($a)*); println!("{s}"); report.push_str(&s); report.push('\n'); }}; }

    let Some(mut meter) = NetMeter::start() else {
        line!("RESULT: meter failed to start — run elevated (a real-time ETW session needs admin).");
        if let Some(p) = out_path { let _ = std::fs::write(p, report); }
        return;
    };
    line!("meter started; sampling per-process TCP+UDP throughput...");

    let mut name_cache: HashMap<u32, String> = HashMap::new();
    let mut peak_total_down = 0u64;

    for round in 0..10 {
        std::thread::sleep(Duration::from_millis(1000));
        let rates = meter.rates();
        if round == 0 {
            continue; // first sample only primes the baseline
        }
        let mut rows: Vec<(u32, u64, u64)> =
            rates.iter().map(|(&pid, &(d, u))| (pid, d, u)).collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.1 + r.2));
        let total_down: u64 = rows.iter().map(|r| r.1).sum();
        let total_up: u64 = rows.iter().map(|r| r.2).sum();
        peak_total_down = peak_total_down.max(total_down);

        line!("");
        line!(
            "round {round}: {} process(es) moving traffic  |  total ↓ {}  ↑ {}",
            rows.len(),
            format_speed(total_down),
            format_speed(total_up)
        );
        for (pid, down, up) in rows.iter().take(6) {
            let name = name_cache.entry(*pid).or_insert_with(|| {
                process_full_path(*pid)
                    .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
                    .unwrap_or_else(|| format!("pid {pid}"))
            });
            line!("    {:<24} ↓ {:>12}  ↑ {:>12}", name, format_speed(*down), format_speed(*up));
        }

        // Per-endpoint (Connections tab). Spotlight UDP — the new capability.
        let conns = meter.conn_rates();
        let mut udp: Vec<_> = conns
            .iter()
            .filter(|((is_udp, _), t)| *is_udp && (t.download > 0 || t.upload > 0))
            .map(|((_, port), t)| (*port, t.download, t.upload))
            .collect();
        udp.sort_by_key(|e| std::cmp::Reverse(e.1 + e.2));
        for (port, down, up) in udp.iter().take(4) {
            line!(
                "    UDP local:{:<5}          ↓ {:>12}  ↑ {:>12}",
                port,
                format_speed(*down),
                format_speed(*up)
            );
        }
    }

    line!("");
    if peak_total_down > 0 {
        line!("RESULT: OK — ETW meter reports live per-process TCP+UDP throughput (peak ↓ {}).", format_speed(peak_total_down));
    } else {
        line!("RESULT: meter ran but saw no traffic — was the machine idle?");
    }

    if let Some(p) = out_path { let _ = std::fs::write(p, report); }
}

#[cfg(not(windows))]
fn main() {}
