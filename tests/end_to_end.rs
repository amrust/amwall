//! End-to-end integration test: hand-crafted user-profile XML →
//! parsed `Profile` → per-rule `rules::parse_str` →
//! `rules::compile` → `wfp::filter::add` → `cleanup_provider`.
//!
//! Validates that the M1 (WFP) and M2 (profile I/O) and M3 (rules
//! engine) halves of the project actually compose, not just that
//! each works in isolation. If any cross-module contract drifts —
//! attribute name change in serialize, action default flip in
//! parse, condition-storage lifetime bug in compile — this test
//! catches it before the regression hits the install_demo example
//! or the eventual M4 CLI.
//!
//! Admin-only (filter::add requires elevation). Run via
//! `cargo test -- --ignored` from an elevated shell.

#![cfg(windows)]

use amwall::profile::{self, Action};
use amwall::rules;
use amwall::wfp::condition::{FilterCondition, IpProto};
use amwall::wfp::filter::{self as wfp_filter, FilterAction};
use amwall::wfp::{provider, sublayer, WfpEngine};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V4;

/// Hand-crafted user profile that exercises:
///   - a multi-clause rule (`"65530;65531"`) → 2 filters
///   - a CIDR-form blocklist rule → 1 filter
///   - both Permit and Block actions
///   - `protocol` attribute resolution
///
/// This test predates the `install::install_profile` module from
/// M4.2 and instead manually loops `wfp::filter::add` with a
/// hardcoded layer. It deliberately doesn't go through
/// `install_profile` so the M4.4 layer-selection fan-out doesn't
/// apply here — that's tested separately in
/// `install::tests::install_profile_then_uninstall_admin_smoke`.
///
/// Uses TEST-NET-2 (`198.51.100.0/24`, RFC 5737) and reserved-high
/// ports so the installed filters can't fire on real traffic.
const PROFILE_XML: &str = r#"<?xml version="1.0" ?>
<root timestamp="0" type="4" version="5">
  <rules_custom>
    <item name="e2e-tcp" rule="65530;65531" protocol="6" is_enabled="true" />
    <item name="e2e-block" rule="198.51.100.0/24" is_block="true" is_enabled="true" />
  </rules_custom>
</root>"#;

#[test]
#[ignore = "requires elevated shell — exercises real BFE end-to-end"]
fn full_pipeline_profile_to_kernel_to_cleanup() {
    // 1. Parse the XML (M2.1).
    let profile = profile::parse_str(PROFILE_XML).expect("profile parse failed");
    assert_eq!(
        profile.custom_rules.len(),
        2,
        "expected 2 rules in custom_rules"
    );

    // 2. Open engine, register provider + sublayer (M1.1–M1.4).
    let engine = WfpEngine::open().expect("engine open failed");
    let prov = provider::add(&engine, "amwall e2e", "end-to-end test", false)
        .expect("provider add failed");
    let sub = sublayer::add(
        &engine,
        "amwall e2e sublayer",
        "",
        0x4000,
        Some(&prov.key()),
        false,
    )
    .expect("sublayer add failed");

    // 3. For each rule, parse rule strings (M3.1), compile to
    //    FilterConditions (M3.2/M3.3), install one filter per
    //    semicolon-separated clause (M1.5).
    //
    //    Upstream's per-clause-becomes-its-own-filter semantic
    //    means a `rule="65530;65531"` produces two filters, not one
    //    AND-of-both — see the M3.2 doc comment on `compile`.
    let mut installed = 0u32;
    for rule in &profile.custom_rules {
        let action = match rule.action {
            Action::Permit => FilterAction::Permit,
            Action::Block => FilterAction::Block,
        };
        let remote_str = rule.remote.as_deref().unwrap_or("");
        let clauses = rules::parse_str(remote_str).expect("rule string parse failed");

        for clause in &clauses {
            let mut conds: Vec<FilterCondition> = Vec::new();

            // Protocol lifts to a Protocol condition. Using
            // IpProto::Other(n) preserves the raw byte from the
            // profile — for known protocol numbers (6 = Tcp) the
            // compiled condition is identical to IpProto::Tcp.
            if let Some(proto) = rule.protocol {
                conds.push(FilterCondition::Protocol(IpProto::Other(proto)));
            }
            conds.extend(rules::compile(rules::Side::Remote, std::slice::from_ref(clause)));

            wfp_filter::add(
                &engine,
                &rule.name,
                "",
                &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                &sub.key(),
                Some(&prov.key()),
                &conds,
                action,
                false,
                None,
            )
            .expect("filter add failed");
            installed += 1;
        }
    }
    assert_eq!(installed, 3, "expected 3 filters installed");

    // 4. Tear down via cleanup_provider (M1.7) and assert exact
    //    counts — proves every filter we added is reachable from
    //    the provider key, with no extras and no leftovers.
    let report = engine
        .cleanup_provider(&prov.key())
        .expect("cleanup_provider failed");
    assert_eq!(report.filters_deleted, 3);
    assert_eq!(report.sublayers_deleted, 1);
    assert!(report.provider_deleted);
}
