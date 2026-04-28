// simplewall-rs — profile.xml serialization.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// Inverse of `parse::parse_str`. Emits XML matching upstream
// simplewall's writer output (see `simplewall-master/src/db.c`
// `_app_db_save_app` / `_app_db_save_rule` / `_app_db_save_ruleconfig`).
//
// Attribute order, default-skipping rules, indentation, and line
// endings are chosen to byte-equivalently round-trip a USER-shaped
// profile.xml. The internal profile (`profile_internal.xml`) is
// hand-authored upstream and includes attributes upstream's writer
// doesn't emit (`is_services`, `os_version`); for that flavor we
// only guarantee semantic round-trip (parse → serialize → parse →
// equal) rather than byte equality.
//
// Format (matches `tests/fixtures/profile_internal.xml`):
//
//     <?xml version="1.0" ?>\n
//     <root timestamp="..." type="..." version="...">\n
//     \t<section>\n
//     \t\t<item attr="..." ... />\n
//     \t</section>\n
//     </root>\n
//
// Empty sections are elided entirely (matches upstream behavior;
// upstream skips `_app_db_writeelementstart` for sections with no
// items in practice).

use super::{Action, AddressFamily, App, Direction, Profile, ProfileKind, Rule, RuleConfig};

/// Serialize a `Profile` into a `String` containing the XML form.
pub fn to_string(profile: &Profile) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" ?>\n");
    write_root(&mut out, profile);
    out
}

fn write_root(out: &mut String, p: &Profile) {
    out.push_str("<root");
    write_attr_i64(out, "timestamp", p.timestamp);
    write_attr_u32(out, "type", profile_kind_raw(p.kind));
    write_attr_u32(out, "version", p.version);
    out.push_str(">\n");

    if !p.apps.is_empty() {
        write_apps(out, &p.apps);
    }
    if !p.rule_configs.is_empty() {
        write_rule_configs(out, &p.rule_configs);
    }
    if !p.system_rules.is_empty() {
        write_rules(out, "rules_system", &p.system_rules);
    }
    if !p.custom_rules.is_empty() {
        write_rules(out, "rules_custom", &p.custom_rules);
    }
    if !p.blocklist_rules.is_empty() {
        write_rules(out, "rules_blocklist", &p.blocklist_rules);
    }

    out.push_str("</root>\n");
}

fn profile_kind_raw(k: ProfileKind) -> u32 {
    match k {
        ProfileKind::User | ProfileKind::Internal => 4,
        ProfileKind::Other(n) => n,
    }
}

fn write_apps(out: &mut String, apps: &[App]) {
    out.push_str("\t<apps>\n");
    for app in apps {
        out.push_str("\t\t<item");
        // Upstream order (db.c::_app_db_save_app):
        //   path, hash, comment, timestamp, timer, profile (FFU,
        //   skipped), is_undeletable, is_silent, is_enabled.
        write_attr_str(out, "path", &app.path.to_string_lossy());
        if let Some(hash) = &app.hash {
            write_attr_str(out, "hash", hash);
        }
        if let Some(comment) = &app.comment {
            write_attr_str(out, "comment", comment);
        }
        if app.timestamp != 0 {
            write_attr_i64(out, "timestamp", app.timestamp);
        }
        if app.timer != 0 {
            write_attr_i64(out, "timer", app.timer);
        }
        if app.is_undeletable {
            write_attr_bool(out, "is_undeletable", true);
        }
        if app.is_silent {
            write_attr_bool(out, "is_silent", true);
        }
        if app.is_enabled {
            write_attr_bool(out, "is_enabled", true);
        }
        out.push_str(" />\n");
    }
    out.push_str("\t</apps>\n");
}

fn write_rule_configs(out: &mut String, configs: &[RuleConfig]) {
    out.push_str("\t<rules_config>\n");
    for cfg in configs {
        out.push_str("\t\t<item");
        // Upstream order (db.c::_app_db_save_ruleconfig):
        //   name, apps (if present), is_enabled (always written).
        write_attr_str(out, "name", &cfg.name);
        if let Some(apps) = &cfg.apps {
            write_attr_str(out, "apps", apps);
        }
        write_attr_bool(out, "is_enabled", cfg.is_enabled);
        out.push_str(" />\n");
    }
    out.push_str("\t</rules_config>\n");
}

fn write_rules(out: &mut String, section: &str, rules: &[Rule]) {
    out.push_str(&format!("\t<{section}>\n"));
    for rule in rules {
        out.push_str("\t\t<item");
        // Upstream order (db.c::_app_db_save_rule):
        //   name, rule (=rule_remote), rule_local, comment, profile
        //   (FFU, skipped), dir (skip if Outbound), protocol (skip if
        //   0), version (skip if AF_UNSPEC), apps, is_block (skip if
        //   Permit), is_enabled (skip if false).
        //
        // After upstream's set, we append `is_services` and
        // `os_version` if present. Upstream's writer doesn't emit
        // those — they only appear in the hand-authored
        // profile_internal.xml — but preserving them on round-trip
        // matters for the parse → serialize → parse semantic check.
        write_attr_str(out, "name", &rule.name);
        if let Some(remote) = &rule.remote {
            write_attr_str(out, "rule", remote);
        }
        if let Some(local) = &rule.local {
            write_attr_str(out, "rule_local", local);
        }
        if let Some(comment) = &rule.comment {
            write_attr_str(out, "comment", comment);
        }
        if rule.direction != Direction::Outbound {
            write_attr_i32(out, "dir", direction_raw(rule.direction));
        }
        if let Some(proto) = rule.protocol {
            if proto != 0 {
                write_attr_u8(out, "protocol", proto);
            }
        }
        if let Some(af) = rule.address_family {
            let raw = address_family_raw(af);
            if raw != 0 {
                write_attr_u32(out, "version", raw);
            }
        }
        if let Some(apps) = &rule.apps {
            write_attr_str(out, "apps", apps);
        }
        if rule.action == Action::Block {
            write_attr_bool(out, "is_block", true);
        }
        if rule.is_enabled {
            write_attr_bool(out, "is_enabled", true);
        }
        // Round-trip-fidelity tail (not in upstream's writer):
        if rule.is_services {
            write_attr_bool(out, "is_services", true);
        }
        if let Some(os) = &rule.os_version {
            write_attr_str(out, "os_version", os);
        }
        out.push_str(" />\n");
    }
    out.push_str(&format!("\t</{section}>\n"));
}

fn direction_raw(d: Direction) -> i32 {
    match d {
        Direction::Outbound => 0,
        Direction::Inbound => 1,
        Direction::Any => 2,
        Direction::Other(n) => n,
    }
}

fn address_family_raw(af: AddressFamily) -> u32 {
    match af {
        AddressFamily::Ipv4 => 2,
        AddressFamily::Ipv6 => 23,
        AddressFamily::Other(n) => n,
    }
}

// ---- attribute writers ----

fn write_attr_str(out: &mut String, name: &str, value: &str) {
    out.push(' ');
    out.push_str(name);
    out.push_str("=\"");
    escape_attr_into(out, value);
    out.push('"');
}

fn write_attr_bool(out: &mut String, name: &str, value: bool) {
    write_attr_str(out, name, if value { "true" } else { "false" });
}

fn write_attr_i64(out: &mut String, name: &str, value: i64) {
    out.push(' ');
    out.push_str(name);
    out.push_str("=\"");
    out.push_str(&value.to_string());
    out.push('"');
}

fn write_attr_i32(out: &mut String, name: &str, value: i32) {
    out.push(' ');
    out.push_str(name);
    out.push_str("=\"");
    out.push_str(&value.to_string());
    out.push('"');
}

fn write_attr_u32(out: &mut String, name: &str, value: u32) {
    out.push(' ');
    out.push_str(name);
    out.push_str("=\"");
    out.push_str(&value.to_string());
    out.push('"');
}

fn write_attr_u8(out: &mut String, name: &str, value: u8) {
    out.push(' ');
    out.push_str(name);
    out.push_str("=\"");
    out.push_str(&value.to_string());
    out.push('"');
}

/// Escape an attribute value into `out`. Handles the five XML
/// reserved characters; matches the standard double-quote attribute
/// form.
fn escape_attr_into(out: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::parse_str;

    /// Hand-crafted user profile that exercises every attribute path
    /// upstream's writer takes. Round-trip target: `to_string` of the
    /// `parse_str` result is byte-equivalent to this literal.
    const USER_FIXTURE: &str = "\
<?xml version=\"1.0\" ?>
<root timestamp=\"1700000000\" type=\"4\" version=\"5\">
\t<apps>
\t\t<item path=\"C:\\Windows\\System32\\cmd.exe\" is_enabled=\"true\" />
\t\t<item path=\"C:\\Program Files\\Test\\app.exe\" comment=\"user note\" timestamp=\"1699000000\" is_silent=\"true\" is_enabled=\"true\" />
\t</apps>
\t<rules_config>
\t\t<item name=\"DNS\" is_enabled=\"true\" />
\t</rules_config>
\t<rules_custom>
\t\t<item name=\"HTTP\" rule=\"80;443\" protocol=\"6\" is_enabled=\"true\" />
\t\t<item name=\"Block-test\" rule=\"1.2.3.4\" dir=\"2\" is_block=\"true\" />
\t</rules_custom>
</root>
";

    #[test]
    fn user_fixture_round_trips_byte_equivalent() {
        let parsed = parse_str(USER_FIXTURE).expect("parse failed");
        let written = to_string(&parsed);
        assert_eq!(
            written, USER_FIXTURE,
            "round-trip differed:\n--- parsed → written ---\n{written}\n--- expected ---\n{USER_FIXTURE}"
        );
    }

    /// Empty sections elide entirely. Profile with only timestamp /
    /// type / version → `<root .../>`-style minimal output.
    #[test]
    fn empty_profile_elides_all_sections() {
        let p = Profile {
            timestamp: 0,
            kind: ProfileKind::User,
            version: 5,
            apps: vec![],
            rule_configs: vec![],
            system_rules: vec![],
            custom_rules: vec![],
            blocklist_rules: vec![],
        };
        let out = to_string(&p);
        assert_eq!(
            out,
            "<?xml version=\"1.0\" ?>\n<root timestamp=\"0\" type=\"4\" version=\"5\">\n</root>\n",
        );
    }

    /// XML reserved characters in attribute values are escaped to the
    /// standard named entities.
    #[test]
    fn special_chars_in_attributes_are_escaped() {
        let p = Profile {
            timestamp: 0,
            kind: ProfileKind::User,
            version: 5,
            apps: vec![],
            rule_configs: vec![],
            system_rules: vec![],
            custom_rules: vec![Rule {
                name: r#"a&b<c>d"e'f"#.into(),
                remote: None,
                local: None,
                direction: Direction::Outbound,
                action: Action::Permit,
                protocol: None,
                address_family: None,
                apps: None,
                is_services: false,
                is_enabled: false,
                os_version: None,
                comment: None,
            }],
            blocklist_rules: vec![],
        };
        let out = to_string(&p);
        assert!(
            out.contains("name=\"a&amp;b&lt;c&gt;d&quot;e&apos;f\""),
            "attribute escape mismatch: {out}"
        );
        // Re-parse to confirm round-trip survives the escape pass.
        let reparsed = parse_str(&out).expect("re-parse failed");
        assert_eq!(reparsed.custom_rules[0].name, r#"a&b<c>d"e'f"#);
    }

    /// `is_block` is omitted when the rule's action is Permit
    /// (default), and present (`true`) when Block.
    #[test]
    fn is_block_omitted_for_permit_emitted_for_block() {
        let mut p = Profile {
            timestamp: 0,
            kind: ProfileKind::User,
            version: 5,
            apps: vec![],
            rule_configs: vec![],
            system_rules: vec![],
            custom_rules: vec![Rule {
                name: "permit".into(),
                remote: None,
                local: None,
                direction: Direction::Outbound,
                action: Action::Permit,
                protocol: None,
                address_family: None,
                apps: None,
                is_services: false,
                is_enabled: false,
                os_version: None,
                comment: None,
            }],
            blocklist_rules: vec![],
        };
        let out = to_string(&p);
        assert!(!out.contains("is_block"));
        p.custom_rules[0].action = Action::Block;
        p.custom_rules[0].name = "block".into();
        let out = to_string(&p);
        assert!(out.contains("is_block=\"true\""));
    }
}
