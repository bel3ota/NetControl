//! IEEE OUI / MA-M / MA-S vendor lookup.
//!
//! The database is a compact TSV generated from the public IEEE registry
//! (`assets/oui.tsv`). Lookups try the longest assignment first because MA-M
//! (28-bit) and MA-S (36-bit) prefixes are more specific than MA-L (24-bit).

use std::collections::HashMap;
use std::sync::OnceLock;

static RAW: &str = include_str!("../assets/oui.tsv");

struct Registry {
    vendors: HashMap<&'static str, &'static str>,
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut vendors = HashMap::with_capacity(41_000);
        for line in RAW.lines() {
            if let Some((prefix, org)) = line.split_once('\t') {
                if !prefix.is_empty() && !org.is_empty() {
                    vendors.insert(prefix, org);
                }
            }
        }
        Registry { vendors }
    })
}

/// Look up the organization that owns a MAC address.
pub fn lookup(mac: &str) -> Option<String> {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_uppercase();
    if hex.len() < 6 {
        return None;
    }
    let db = registry();
    for len in [9usize, 7, 6] {
        if hex.len() >= len {
            if let Some(vendor) = db.vendors.get(&hex[..len]) {
                return Some((*vendor).to_string());
            }
        }
    }
    None
}

/// Identify locally administered MAC addresses (randomized MACs on modern
/// phones) where vendor attribution is meaningless.
pub fn is_locally_administered(mac: &str) -> bool {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>();
    if hex.len() < 2 {
        return false;
    }
    u8::from_str_radix(&hex[..2], 16)
        .map(|first| first & 0b0000_0010 != 0)
        .unwrap_or(false)
}

pub fn vendor_count() -> usize {
    registry().vendors.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vendor() {
        // Raspberry Pi Foundation MA-L
        assert!(lookup("B8:27:EB:12:34:56").is_some());
        assert!(vendor_count() > 10_000);
    }

    #[test]
    fn local_mac_detection() {
        assert!(is_locally_administered("da:a1:19:00:00:01"));
        assert!(!is_locally_administered("b8:27:eb:00:00:01"));
    }
}
