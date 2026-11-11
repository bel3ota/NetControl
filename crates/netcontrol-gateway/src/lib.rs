//! Gateway enforcement adapters.
//!
//! Each adapter reports capabilities honestly and verifies every operation by
//! reading the resulting state back from the managed device. A block that was
//! accepted but not verified is never reported as successful.

pub mod linux;
pub mod mikrotik;
pub mod openwrt;
pub mod opnsense;
pub mod pfsense;
pub mod ssh;
pub mod traits;
pub mod unifi;

pub use traits::{verify_result, AdapterSecret, EnforcedRule, GatewayAdapter, Target};

use netcontrol_core::models::{GatewayConfig, GatewayKind};
use netcontrol_core::{Error, Result};

/// Build the adapter for a stored gateway configuration. The decrypted secret
/// is wrapped in `Zeroizing` inside the adapter and is never logged.
pub fn build_adapter(
    config: &GatewayConfig,
    secret: Option<String>,
) -> Result<Box<dyn GatewayAdapter>> {
    let secret = secret.map(AdapterSecret::new);
    Ok(match config.kind {
        GatewayKind::Linux => Box::new(linux::LinuxAdapter::new(config.clone(), secret)),
        GatewayKind::OpenWrt => Box::new(openwrt::OpenWrtAdapter::new(config.clone(), secret)?),
        GatewayKind::MikroTik => Box::new(mikrotik::MikroTikAdapter::new(config.clone(), secret)?),
        GatewayKind::UniFi => Box::new(unifi::UniFiAdapter::new(config.clone(), secret)?),
        GatewayKind::PfSense => Box::new(pfsense::PfSenseAdapter::new(config.clone(), secret)?),
        GatewayKind::OpnSense => Box::new(opnsense::OpnSenseAdapter::new(config.clone(), secret)?),
    })
}

pub fn kind_label(kind: GatewayKind) -> &'static str {
    match kind {
        GatewayKind::Linux => "Linux gateway",
        GatewayKind::OpenWrt => "OpenWrt",
        GatewayKind::MikroTik => "MikroTik RouterOS",
        GatewayKind::UniFi => "UniFi Network",
        GatewayKind::PfSense => "pfSense",
        GatewayKind::OpnSense => "OPNsense",
    }
}

pub fn require_secret(kind: GatewayKind) -> bool {
    matches!(
        kind,
        GatewayKind::MikroTik | GatewayKind::UniFi | GatewayKind::OpnSense
    )
}

pub fn validate_host(host: &str) -> Result<()> {
    let host = host.trim();
    if host.is_empty() {
        return Err(Error::Validation("gateway host is required".into()));
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'))
    {
        return Err(Error::Validation(
            "gateway host must be a hostname or IP address".into(),
        ));
    }
    Ok(())
}
