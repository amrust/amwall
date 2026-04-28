// Integration test: parse the real upstream profile_internal.xml
// fixture (extracted from simplewall-master/bin/) and assert the
// shape we get back. This is the end-to-end "does it actually parse
// production-shaped data" check on top of profile::parse's unit
// tests.
//
// Also covers the parse → serialize → parse semantic round-trip
// against the same fixture. We don't claim BYTE-equivalent
// round-trip on profile_internal.xml because that file is hand-
// edited upstream and contains attributes (`is_services`,
// `os_version`) plus pre-root `<!-- ... -->` comments that
// upstream's writer doesn't emit. Byte-equivalence is asserted on
// USER-shape profiles (see profile::serialize::tests).

use simplewall_rs::profile::{self, Action, Direction, ProfileKind};

const PROFILE_INTERNAL: &str =
    include_str!("fixtures/profile_internal.xml");

#[test]
fn parses_upstream_profile_internal_xml() {
    let p = profile::parse_str(PROFILE_INTERNAL).expect("parse failed");

    // Header — values come from the literal `<root>` element in
    // simplewall v3.8.7's bundled profile_internal.xml.
    assert_eq!(p.kind, ProfileKind::User); // type=4 in the file
    assert_eq!(p.version, 5);
    assert_eq!(p.timestamp, 1717635779);

    // Section population. profile_internal.xml has system rules,
    // custom rules, and blocklist rules — but no <apps> or
    // <rules_config> (those live in user profile.xml).
    assert!(p.apps.is_empty());
    assert!(p.rule_configs.is_empty());

    assert!(
        !p.system_rules.is_empty(),
        "<rules_system> should not be empty"
    );
    assert!(
        !p.custom_rules.is_empty(),
        "<rules_custom> should not be empty"
    );
    assert!(
        !p.blocklist_rules.is_empty(),
        "<rules_blocklist> should not be empty"
    );

    // Spot-check a known system rule (DNS, line 8 of upstream file).
    let dns = p
        .system_rules
        .iter()
        .find(|r| r.name == "DNS")
        .expect("DNS rule missing");
    assert_eq!(dns.remote.as_deref(), Some("53"));
    assert_eq!(dns.protocol, Some(17)); // UDP
    assert_eq!(dns.apps.as_deref(), Some("Dnscache"));
    assert!(dns.is_enabled);

    // Spot-check a known custom rule (HTTP, line ~36).
    let http = p
        .custom_rules
        .iter()
        .find(|r| r.name == "HTTP")
        .expect("HTTP rule missing");
    assert_eq!(http.remote.as_deref(), Some("80;443;8000;8008;8080;8443-8444"));
    assert_eq!(http.protocol, Some(6)); // TCP

    // Spot-check direction and action defaults: most upstream rules
    // omit `dir` and `is_block`, so we expect Outbound + Permit.
    assert_eq!(http.direction, Direction::Outbound);
    assert_eq!(http.action, Action::Permit);

    // Sanity: at least a few hundred blocklist rules — the bundled
    // file has ~1000+ extra_*.* IP entries.
    assert!(
        p.blocklist_rules.len() > 100,
        "expected >100 blocklist rules, got {}",
        p.blocklist_rules.len()
    );
}

/// parse → serialize → parse: every collection's contents survive a
/// full round-trip through the writer + reader. Asserts structural
/// equality on every Vec, not byte equality on the XML output (the
/// internal-profile fixture has hand-authored attributes and
/// comments upstream's writer doesn't emit).
#[test]
fn upstream_profile_internal_xml_semantic_round_trip() {
    let original = profile::parse_str(PROFILE_INTERNAL).expect("first parse failed");
    let written = profile::to_string(&original);
    let reparsed = profile::parse_str(&written).expect("second parse failed");

    assert_eq!(original.timestamp, reparsed.timestamp);
    assert_eq!(original.kind, reparsed.kind);
    assert_eq!(original.version, reparsed.version);
    assert_eq!(original.apps, reparsed.apps);
    assert_eq!(original.rule_configs, reparsed.rule_configs);
    assert_eq!(original.system_rules, reparsed.system_rules);
    assert_eq!(original.custom_rules, reparsed.custom_rules);
    assert_eq!(original.blocklist_rules, reparsed.blocklist_rules);
}
