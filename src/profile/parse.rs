// simplewall-rs — profile.xml deserialization.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// Event-based parser using `quick_xml::Reader`. Tracks the section
// nesting (`<root>` → `<apps>` / `<rules_*>` / etc.) and dispatches
// each `<item>` to the right collector based on the parent.
//
// Designed for round-trip fidelity:
//   - Unknown attributes on known elements are silently dropped (we
//     don't preserve them; documented limit). Future M2.x can add a
//     pass-through map if needed.
//   - Unknown sections are ignored (forward-compatible with future
//     upstream profile-format additions).
//   - Numeric attribute encoding (Direction / AddressFamily / type)
//     uses `Other(raw)` variants so unfamiliar values round-trip.

use std::path::PathBuf;
use std::str::FromStr;

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use super::{
    Action, AddressFamily, App, Direction, Profile, ProfileKind, Rule, RuleConfig,
};

/// Errors surfaced by `parse_str`.
#[derive(Debug)]
pub enum ParseError {
    /// Underlying `quick_xml::Reader` error (malformed XML, EOF in the
    /// middle of an element, etc.).
    Xml(quick_xml::Error),
    /// `<root>` element was not found at the top level. Either the
    /// document is truncated or it's something other than a simplewall
    /// profile.
    MissingRoot,
    /// A required attribute was missing on an element.
    MissingAttribute {
        element: &'static str,
        attribute: &'static str,
    },
    /// An attribute value couldn't be parsed as the expected type
    /// (e.g. `protocol="abc"` instead of an integer).
    BadAttribute {
        element: &'static str,
        attribute: &'static str,
        value: String,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Xml(e) => write!(f, "xml read error: {e}"),
            Self::MissingRoot => write!(f, "no <root> element found"),
            Self::MissingAttribute { element, attribute } => {
                write!(f, "<{element}> missing required attribute `{attribute}`")
            }
            Self::BadAttribute { element, attribute, value } => write!(
                f,
                "<{element}> attribute `{attribute}` has invalid value `{value}`"
            ),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<quick_xml::Error> for ParseError {
    fn from(e: quick_xml::Error) -> Self {
        Self::Xml(e)
    }
}

/// Parse an in-memory profile XML document into a `Profile` struct.
pub fn parse_str(input: &str) -> Result<Profile, ParseError> {
    let mut reader = Reader::from_str(input);
    reader.config_mut().trim_text(true);

    let mut profile: Option<Profile> = None;
    let mut section: Option<Section> = None;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            // Start tags transition section state. <item> is self-
            // closing in practice but tolerate it being open-form too.
            Event::Start(e) => match e.name().as_ref() {
                b"root" => profile = Some(parse_root(&e)?),
                b"apps" => section = Some(Section::Apps),
                b"rules_config" => section = Some(Section::RulesConfig),
                b"rules_system" => section = Some(Section::RulesSystem),
                b"rules_custom" => section = Some(Section::RulesCustom),
                b"rules_blocklist" => section = Some(Section::RulesBlocklist),
                b"item" => collect_item(&e, profile.as_mut(), section)?,
                _ => {} // unknown element: ignore
            },
            // Empty tags = self-closing (<item ... />). Same item-
            // handling path; section transitions only happen on Start
            // (a self-closing <apps/> means "this section is empty").
            Event::Empty(e) => match e.name().as_ref() {
                b"root" => profile = Some(parse_root(&e)?),
                b"item" => collect_item(&e, profile.as_mut(), section)?,
                _ => {}
            },
            Event::End(e) => match e.name().as_ref() {
                b"apps" | b"rules_config" | b"rules_system" | b"rules_custom"
                | b"rules_blocklist" => {
                    section = None;
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {} // text / comment / decl / etc. — ignore
        }
        buf.clear();
    }

    profile.ok_or(ParseError::MissingRoot)
}

#[derive(Clone, Copy)]
enum Section {
    Apps,
    RulesConfig,
    RulesSystem,
    RulesCustom,
    RulesBlocklist,
}

fn collect_item(
    e: &BytesStart,
    profile: Option<&mut Profile>,
    section: Option<Section>,
) -> Result<(), ParseError> {
    let Some(p) = profile else { return Ok(()) }; // <item> outside <root>
    match section {
        Some(Section::Apps) => p.apps.push(parse_app(e)?),
        Some(Section::RulesConfig) => p.rule_configs.push(parse_rule_config(e)?),
        Some(Section::RulesSystem) => p.system_rules.push(parse_rule(e)?),
        Some(Section::RulesCustom) => p.custom_rules.push(parse_rule(e)?),
        Some(Section::RulesBlocklist) => p.blocklist_rules.push(parse_rule(e)?),
        None => {} // stray <item> outside any rules section: ignore
    }
    Ok(())
}

fn parse_root(e: &BytesStart) -> Result<Profile, ParseError> {
    let timestamp = attr_int::<i64>(e, "root", "timestamp")?;
    let raw_type = attr_int::<u32>(e, "root", "type")?;
    let version = attr_int::<u32>(e, "root", "version")?;

    let kind = match raw_type {
        4 => ProfileKind::User, // upstream encodes both User and Internal as 4
        other => ProfileKind::Other(other),
    };

    Ok(Profile {
        timestamp,
        kind,
        version,
        apps: Vec::new(),
        rule_configs: Vec::new(),
        system_rules: Vec::new(),
        custom_rules: Vec::new(),
        blocklist_rules: Vec::new(),
    })
}

fn parse_app(e: &BytesStart) -> Result<App, ParseError> {
    let path_str = attr_string(e, "item", "path")?
        .ok_or(ParseError::MissingAttribute { element: "item", attribute: "path" })?;
    Ok(App {
        path: PathBuf::from(path_str),
        is_enabled: attr_bool(e, "is_enabled")?.unwrap_or(false),
        is_silent: attr_bool(e, "is_silent")?.unwrap_or(false),
        is_undeletable: attr_bool(e, "is_undeletable")?.unwrap_or(false),
        timestamp: attr_int_opt::<i64>(e, "item", "timestamp")?.unwrap_or(0),
        timer: attr_int_opt::<i64>(e, "item", "timer")?.unwrap_or(0),
        hash: attr_string(e, "item", "hash")?,
        comment: attr_string(e, "item", "comment")?,
    })
}

fn parse_rule_config(e: &BytesStart) -> Result<RuleConfig, ParseError> {
    let name = attr_string(e, "item", "name")?
        .ok_or(ParseError::MissingAttribute { element: "item", attribute: "name" })?;
    Ok(RuleConfig {
        name,
        is_enabled: attr_bool(e, "is_enabled")?.unwrap_or(false),
        apps: attr_string(e, "item", "apps")?,
    })
}

fn parse_rule(e: &BytesStart) -> Result<Rule, ParseError> {
    let name = attr_string(e, "item", "name")?
        .ok_or(ParseError::MissingAttribute { element: "item", attribute: "name" })?;

    let direction = match attr_int_opt::<i32>(e, "item", "dir")? {
        Some(n) => Direction::from_raw(n),
        None => Direction::Outbound, // upstream treats absent dir as outbound
    };
    let action = match attr_bool(e, "is_block")? {
        Some(true) => Action::Block,
        _ => Action::Permit,
    };
    let address_family = attr_int_opt::<u32>(e, "item", "version")?
        .map(AddressFamily::from_raw);

    Ok(Rule {
        name,
        remote: attr_string(e, "item", "rule")?,
        local: attr_string(e, "item", "rule_local")?,
        direction,
        action,
        protocol: attr_int_opt::<u8>(e, "item", "protocol")?,
        address_family,
        apps: attr_string(e, "item", "apps")?,
        is_services: attr_bool(e, "is_services")?.unwrap_or(false),
        is_enabled: attr_bool(e, "is_enabled")?.unwrap_or(false),
        os_version: attr_string(e, "item", "os_version")?,
        comment: attr_string(e, "item", "comment")?,
    })
}

// ---- attribute helpers ----

fn attr_string(
    e: &BytesStart,
    _element: &'static str,
    attr: &'static str,
) -> Result<Option<String>, ParseError> {
    for a in e.attributes().with_checks(false) {
        let a = a.map_err(quick_xml::Error::from)?;
        if a.key.as_ref() == attr.as_bytes() {
            let v = a.unescape_value()?.into_owned();
            return Ok(Some(v));
        }
    }
    Ok(None)
}

fn attr_int<T: FromStr>(
    e: &BytesStart,
    element: &'static str,
    attr: &'static str,
) -> Result<T, ParseError>
where
    T::Err: std::fmt::Debug,
{
    let s = attr_string(e, element, attr)?
        .ok_or(ParseError::MissingAttribute { element, attribute: attr })?;
    s.parse::<T>().map_err(|_| ParseError::BadAttribute {
        element,
        attribute: attr,
        value: s,
    })
}

fn attr_int_opt<T: FromStr>(
    e: &BytesStart,
    element: &'static str,
    attr: &'static str,
) -> Result<Option<T>, ParseError>
where
    T::Err: std::fmt::Debug,
{
    let Some(s) = attr_string(e, element, attr)? else { return Ok(None) };
    s.parse::<T>().map(Some).map_err(|_| ParseError::BadAttribute {
        element,
        attribute: attr,
        value: s,
    })
}

fn attr_bool(e: &BytesStart, attr: &'static str) -> Result<Option<bool>, ParseError> {
    let Some(s) = attr_string(e, "item", attr)? else { return Ok(None) };
    match s.as_str() {
        "true" | "1" => Ok(Some(true)),
        "false" | "0" => Ok(Some(false)),
        _ => Err(ParseError::BadAttribute {
            element: "item",
            attribute: attr,
            value: s,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_USER: &str = r#"<?xml version="1.0" ?>
<root timestamp="1700000000" type="4" version="5">
  <apps>
    <item path="C:\Windows\System32\cmd.exe" is_enabled="true" />
  </apps>
  <rules_config>
    <item name="DNS" is_enabled="true" />
  </rules_config>
  <rules_custom>
    <item name="HTTP" rule="80;443" protocol="6" is_enabled="true" />
  </rules_custom>
</root>"#;

    #[test]
    fn parses_minimal_user_profile() {
        let profile = parse_str(MINIMAL_USER).expect("parse failed");
        assert_eq!(profile.timestamp, 1700000000);
        assert_eq!(profile.version, 5);
        assert_eq!(profile.kind, ProfileKind::User);

        assert_eq!(profile.apps.len(), 1);
        let app = &profile.apps[0];
        assert_eq!(app.path, PathBuf::from(r"C:\Windows\System32\cmd.exe"));
        assert!(app.is_enabled);
        assert!(!app.is_silent);

        assert_eq!(profile.rule_configs.len(), 1);
        assert_eq!(profile.rule_configs[0].name, "DNS");
        assert!(profile.rule_configs[0].is_enabled);

        assert_eq!(profile.custom_rules.len(), 1);
        let rule = &profile.custom_rules[0];
        assert_eq!(rule.name, "HTTP");
        assert_eq!(rule.remote.as_deref(), Some("80;443"));
        assert_eq!(rule.protocol, Some(6));
        assert!(rule.is_enabled);
        assert_eq!(rule.direction, Direction::Outbound); // dir absent → default
        assert_eq!(rule.action, Action::Permit); // is_block absent → default
    }

    #[test]
    fn missing_root_returns_error() {
        let err = parse_str("<?xml version=\"1.0\"?>").unwrap_err();
        assert!(matches!(err, ParseError::MissingRoot));
    }

    #[test]
    fn rule_with_dir_2_parses_as_any() {
        let xml = r#"<?xml version="1.0"?>
<root timestamp="0" type="4" version="5">
  <rules_custom>
    <item name="ICMPv4" dir="2" protocol="1" />
  </rules_custom>
</root>"#;
        let profile = parse_str(xml).expect("parse failed");
        assert_eq!(profile.custom_rules[0].direction, Direction::Any);
    }

    #[test]
    fn rule_with_is_block_true_parses_as_block() {
        let xml = r#"<?xml version="1.0"?>
<root timestamp="0" type="4" version="5">
  <rules_custom>
    <item name="block-it" is_block="true" />
  </rules_custom>
</root>"#;
        let profile = parse_str(xml).expect("parse failed");
        assert_eq!(profile.custom_rules[0].action, Action::Block);
    }

    #[test]
    fn unknown_dir_value_round_trips_via_other() {
        let xml = r#"<?xml version="1.0"?>
<root timestamp="0" type="4" version="5">
  <rules_custom>
    <item name="weird" dir="42" />
  </rules_custom>
</root>"#;
        let profile = parse_str(xml).expect("parse failed");
        assert_eq!(profile.custom_rules[0].direction, Direction::Other(42));
    }

    #[test]
    fn bad_protocol_returns_bad_attribute_error() {
        let xml = r#"<?xml version="1.0"?>
<root timestamp="0" type="4" version="5">
  <rules_custom>
    <item name="oops" protocol="not-a-number" />
  </rules_custom>
</root>"#;
        let err = parse_str(xml).unwrap_err();
        match err {
            ParseError::BadAttribute { attribute, value, .. } => {
                assert_eq!(attribute, "protocol");
                assert_eq!(value, "not-a-number");
            }
            other => panic!("expected BadAttribute, got {other:?}"),
        }
    }
}
