//! Live enforcement smoke test — the release gate the pure-logic
//! suite structurally cannot provide.
//!
//! It installs amwall's REAL default-deny set on a live Base Filtering
//! Engine, then proves an ordinary outbound TCP connection that worked
//! a moment ago is now BLOCKED, and that the drop surfaces through the
//! same net-event subscription that feeds the Apps list and the
//! connect prompt.
//!
//! This is the guard that would have caught the v1.1.17 / v1.1.18
//! "firewall permits everything" regression: `cargo test` alone never
//! opens the BFE, so a green gate triad shipped a firewall that did
//! not enforce. Run it deliberately, from an ELEVATED shell:
//!
//! ```text
//! cargo test --target x86_64-pc-windows-msvc \
//!     --test live_enforcement -- --ignored --nocapture
//! ```
//!
//! Safety: default-deny is installed SESSION-SCOPED (non-persistent)
//! and behind a Drop guard that always runs `cleanup_provider`, so
//! even a panicking assertion restores the network on unwind. If the
//! process is hard-killed mid-run, the session filters die with the
//! engine handle; `amwall.exe -uninstall` or a reboot is the backstop.

#![cfg(windows)]

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use amwall::install::{self, PROVIDER_KEY};
use amwall::wfp::events::{self, NetEvent};
use amwall::wfp::WfpEngine;

/// Literal IP:port so the probe exercises the CONNECT path only — no
/// DNS lookup a separate DNS filter could confound.
const TARGET: &str = "1.1.1.1:443";
const CONNECT_TIMEOUT: Duration = Duration::from_millis(3000);

/// Tears down the amwall provider when dropped — including on a panic
/// during an assertion, which is what keeps a failed test from leaving
/// the machine in default-deny (no network).
struct ProviderGuard<'e> {
    engine: &'e WfpEngine,
}
impl Drop for ProviderGuard<'_> {
    fn drop(&mut self) {
        let _ = self.engine.cleanup_provider(&PROVIDER_KEY);
    }
}

fn resolve() -> SocketAddr {
    TARGET
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .expect("literal target must resolve")
}

fn can_connect(addr: &SocketAddr) -> bool {
    TcpStream::connect_timeout(addr, CONNECT_TIMEOUT).is_ok()
}

#[test]
#[ignore = "requires elevated shell + live BFE — installs real default-deny"]
fn default_deny_actually_blocks_outbound() {
    let addr = resolve();

    // (A) Baseline. The endpoint must be reachable BEFORE amwall
    // installs, or a later block can't be attributed to amwall (the
    // machine may be offline, or another firewall may already be
    // blocking). Guardrail #1: assert the DELTA, not an absolute.
    if !can_connect(&addr) {
        eprintln!(
            "SKIP: no baseline connectivity to {addr} (offline, or another \
             firewall / VPN killswitch is already blocking). Cannot \
             attribute a block to amwall; skipping."
        );
        return;
    }

    let engine = WfpEngine::open().expect("open engine (are you elevated?)");
    // Own the provider cleanly: remove any amwall filters left by the
    // app or a prior run before this test installs its own.
    let _ = engine.cleanup_provider(&PROVIDER_KEY);

    // Empty user profile -> install_profile installs only the
    // provider / sublayer + the default-deny set (GlobalRulesConfig
    // defaults block both directions). persistent = false so the
    // filters never outlive this process.
    let profile = amwall::profile::parse_str(
        r#"<?xml version="1.0" ?><root timestamp="0" type="4" version="5"><rules_custom/></root>"#,
    )
    .expect("empty profile parse");

    // Subscribe BEFORE installing / probing so the drop is delivered
    // to us (events generated before subscription are not replayed).
    let (_subscription, rx) = events::subscribe(&engine).expect("subscribe to net events");

    let guard = ProviderGuard { engine: &engine };
    install::install_profile(&engine, &profile, false).expect("install default-deny");

    // (B) THE enforcement assertion. The same connect that succeeded
    // in the baseline must now fail. If it still succeeds, default-deny
    // is not enforcing — the exact v1.1.17 / v1.1.18 bug.
    assert!(
        !can_connect(&addr),
        "default-deny is installed but the outbound connection to {addr} \
         still SUCCEEDED — the firewall is not enforcing (v1.1.17/1.1.18 \
         class regression)"
    );

    // (C) The drop must surface through the event subscription that
    // feeds the Apps list + connect prompt. Look for a Drop to our
    // target port within a short window. Its absence would mean the
    // kernel blocked traffic but nothing is delivered to the UI
    // pipeline — the class of bug that hides blocked apps from the
    // list and suppresses the allow/block prompt.
    let mut saw_drop = false;
    let deadline = Instant::now() + Duration::from_millis(2500);
    while Instant::now() < deadline {
        if let Ok(NetEvent::Drop(d)) = rx.recv_timeout(Duration::from_millis(250)) {
            if d.remote_port == Some(addr.port()) {
                saw_drop = true;
                break;
            }
        }
    }
    assert!(
        saw_drop,
        "connection was blocked but no Drop net-event for port {} was \
         observed within the window — the event pipeline that feeds the \
         Apps list / connect prompt is not delivering drops",
        addr.port()
    );

    // Explicit teardown + count assertion (don't rely on Drop alone —
    // engine-drop auto-cleanup was observed unreliable).
    drop(guard);
    let leftover = engine
        .cleanup_provider(&PROVIDER_KEY)
        .expect("final cleanup_provider");
    assert!(
        !leftover.provider_deleted,
        "provider should already be gone after the guard cleaned up"
    );

    // Sanity: the network recovers once amwall is uninstalled.
    assert!(
        can_connect(&addr),
        "network did not recover after uninstall — cleanup may be incomplete"
    );
}
