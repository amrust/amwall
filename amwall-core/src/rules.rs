//! Rule on-disk schema (TOML) and conversion to BPF-map keys/values.
//!
//! TOML schema:
//!
//! ```text
//! [[rule]]
//! comm   = "curl"          # process name (max 15 chars, matches BPF comm)
//! ip     = "any"           # "any", an IPv4 dotted-quad, or an IPv6 literal
//! port   = 443             # 0 = any
//! action = "allow"         # or "deny"
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Classification of a rule's destination for BPF-map routing. Produced
/// by [`Rule::dest_ip`]. `Any` is installed as a wildcard slot in BOTH
/// the v4 and v6 maps; `V4`/`V6` route to exactly one map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestIp {
    /// Wildcard — "any" / "0.0.0.0" / empty. Matches every destination.
    Any,
    /// A specific IPv4 address in NETWORK byte order (as the BPF sees it).
    V4(u32),
    /// A specific IPv6 address, 16 raw bytes in NETWORK byte order.
    V6([u8; 16]),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub comm: String,
    pub ip: String,
    pub port: u16,
    pub action: Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RulesFile {
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

impl Rule {
    pub fn comm_bytes(&self) -> [u8; 16] {
        let bytes = self.comm.as_bytes();
        let mut out = [0u8; 16];
        let n = bytes.len().min(15);
        out[..n].copy_from_slice(&bytes[..n]);
        out
    }

    pub fn ip4(&self) -> Result<u32> {
        let s = self.ip.trim();
        if s.eq_ignore_ascii_case("any") || s == "0.0.0.0" || s.is_empty() {
            return Ok(0);
        }
        let addr = Ipv4Addr::from_str(s)
            .with_context(|| format!("rule ip '{}' is not 'any' or a v4 address", s))?;
        Ok(u32::from(addr).to_be())
    }

    /// Classify the destination for BPF-map routing: wildcard, a specific
    /// IPv4, or a specific IPv6. v4 is network byte order (matching
    /// [`Rule::ip4`]); v6 is raw octets (also network order), matching
    /// what the BPF program reads from `sockaddr_in6`. Errors if `ip` is
    /// neither "any" nor a valid v4/v6 literal — unlike `ip4()`, this
    /// path accepts IPv6 so a v6 rule no longer fails the whole reload.
    pub fn dest_ip(&self) -> Result<DestIp> {
        let s = self.ip.trim();
        if s.eq_ignore_ascii_case("any") || s == "0.0.0.0" || s.is_empty() {
            return Ok(DestIp::Any);
        }
        if let Ok(a) = Ipv4Addr::from_str(s) {
            return Ok(DestIp::V4(u32::from(a).to_be()));
        }
        if let Ok(a) = Ipv6Addr::from_str(s) {
            return Ok(DestIp::V6(a.octets()));
        }
        anyhow::bail!("rule ip '{}' is not 'any', an IPv4, or an IPv6 address", s)
    }

    pub fn action_byte(&self) -> u8 {
        match self.action {
            Action::Allow => 1,
            Action::Deny => 0,
        }
    }
}

impl RulesFile {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        if text.trim().is_empty() {
            return Ok(Self::default());
        }
        toml::from_str(&text)
            .with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("mkdir -p {}", parent.display()))?;
            }
        }
        let text = toml::to_string_pretty(self).context("serializing rules to TOML")?;
        std::fs::write(path, text)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(ip: &str) -> Rule {
        Rule { comm: "curl".into(), ip: ip.into(), port: 443, action: Action::Allow }
    }

    #[test]
    fn dest_ip_classifies_wildcard() {
        assert_eq!(rule("any").dest_ip().unwrap(), DestIp::Any);
        assert_eq!(rule("0.0.0.0").dest_ip().unwrap(), DestIp::Any);
        assert_eq!(rule("").dest_ip().unwrap(), DestIp::Any);
        assert_eq!(rule("ANY").dest_ip().unwrap(), DestIp::Any);
    }

    #[test]
    fn dest_ip_classifies_v4_in_network_order() {
        // Same network-byte-order convention as ip4(): the BPF program
        // compares against the raw sockaddr_in.addr bytes.
        let expected = u32::from(Ipv4Addr::new(1, 2, 3, 4)).to_be();
        assert_eq!(rule("1.2.3.4").dest_ip().unwrap(), DestIp::V4(expected));
        assert_eq!(rule("1.2.3.4").dest_ip().unwrap(), DestIp::V4(rule("1.2.3.4").ip4().unwrap()));
    }

    #[test]
    fn dest_ip_classifies_v6_as_octets() {
        // octets() is already network byte order, matching sockaddr_in6.
        assert_eq!(rule("::1").dest_ip().unwrap(), DestIp::V6(Ipv6Addr::LOCALHOST.octets()));
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(rule("2001:db8::1").dest_ip().unwrap(), DestIp::V6(a.octets()));
    }

    #[test]
    fn dest_ip_rejects_garbage() {
        assert!(rule("not-an-ip").dest_ip().is_err());
        assert!(rule("1.2.3.4.5").dest_ip().is_err());
    }
}
