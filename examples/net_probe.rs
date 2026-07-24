// amwall — outbound network probe for the release-gate smoke test.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// A deliberately tiny, UNPRIVILEGED program whose only job is to try
// one outbound TCP connection and report the result via its exit
// code, so an elevated harness can install default-deny and prove an
// ordinary app can no longer reach the network:
//
//   exit 0  -> CONNECTED    (traffic was allowed)
//   exit 1  -> BLOCKED      (connect failed: firewall drop / no route)
//   exit 2  -> usage error  (bad target argument)
//
// Usage (from an elevated shell, with amwall filters ON, to see a
// real block in amwall's own log + `netsh wfp show filters`):
//
//   cargo run --example net_probe --release \
//       --target x86_64-pc-windows-msvc -- 1.1.1.1:443 3000
//
// The default target is a LITERAL IP:port (1.1.1.1:443) so the probe
// exercises the CONNECT path only — no DNS lookup that a separate DNS
// filter could confound. Substitute any always-up TCP endpoint you
// trust. The second argument is the connect timeout in milliseconds.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

fn main() {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| "1.1.1.1:443".to_string());
    let timeout_ms: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(3000);

    let addr = match target.to_socket_addrs().ok().and_then(|mut it| it.next()) {
        Some(a) => a,
        None => {
            eprintln!("net_probe: could not resolve target '{target}'");
            std::process::exit(2);
        }
    };

    match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)) {
        Ok(_stream) => {
            println!("net_probe: CONNECTED to {addr}");
            std::process::exit(0);
        }
        Err(e) => {
            println!("net_probe: BLOCKED reaching {addr} ({e})");
            std::process::exit(1);
        }
    }
}
