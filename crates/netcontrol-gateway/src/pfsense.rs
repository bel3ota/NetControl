//! pfSense adapter over SSH.
//!
//! Blocking uses the official `easyrule` CLI (which writes a persistent
//! firewall rule and reloads pf) and is verified by reading `pfctl -sr`.
//! Per-client bandwidth management is not implemented because pfSense
//! limiters/queues are interface- and direction-specific; the API reports the
//! capability as unsupported rather than pretending.

use crate::ssh::{sh_quote, SshClient};
use crate::traits::{verify_result, AdapterSecret, EnforcedRule, GatewayAdapter, Target};
use async_trait::async_trait;
use netcontrol_core::models::{
    BandwidthLimit, EnforcementResult, GatewayCapabilities, GatewayClient, GatewayConfig,
    GatewayKind, GatewayProbe,
};
use netcontrol_core::util::normalize_mac;
use netcontrol_core::{Error, Result};
use std::net::Ipv4Addr;
use std::time::Instant;

pub struct PfSenseAdapter {
    config: GatewayConfig,
    ssh: SshClient,
}

fn validate_iface(value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > 32
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(Error::Validation("invalid firewall interface".into()));
    }
    Ok(value.to_string())
}

impl PfSenseAdapter {
    pub fn new(config: GatewayConfig, secret: Option<AdapterSecret>) -> Result<Self> {
        let ssh = SshClient::new(&config, secret)?;
        Ok(Self { config, ssh })
    }

    fn firewall_interface(&self) -> Result<String> {
        validate_iface(
            self.config
                .interface_hint
                .as_deref()
                .filter(|v| !v.is_empty())
                .unwrap_or("lan"),
        )
    }

    async fn rules(&self) -> Result<String> {
        self.ssh.run("pfctl -sr 2>/dev/null").await
    }

    fn ip(target: &Target) -> Result<Ipv4Addr> {
        target
            .ip
            .as_deref()
            .ok_or_else(|| Error::Unsupported("pfSense enforcement requires an IP address".into()))?
            .parse()
            .map_err(|_| Error::Validation("invalid target IP".into()))
    }
}

#[async_trait]
impl GatewayAdapter for PfSenseAdapter {
    fn kind(&self) -> GatewayKind {
        GatewayKind::PfSense
    }

    fn name(&self) -> String {
        self.config.name.clone()
    }

    fn config(&self) -> &GatewayConfig {
        &self.config
    }

    fn capabilities(&self) -> GatewayCapabilities {
        GatewayCapabilities {
            discovery: true,
            dhcp_leases: false,
            block: true,
            unblock: true,
            bandwidth: false,
            priority: false,
            schedules: true,
            traffic_stats: false,
        }
    }

    async fn probe(&self) -> Result<GatewayProbe> {
        let started = Instant::now();
        match self
            .ssh
            .run(
                "cat /etc/version 2>/dev/null; command -v easyrule >/dev/null && echo EASYRULE_OK; pfctl -s info 2>/dev/null | head -2",
            )
            .await
        {
            Ok(output) => {
                let version = output
                    .lines()
                    .next()
                    .map(|v| format!("pfSense {}", v.trim()));
                let has_easyrule = output.contains("EASYRULE_OK");
                Ok(GatewayProbe {
                    ok: has_easyrule,
                    kind: GatewayKind::PfSense,
                    name: self.config.name.clone(),
                    version,
                    model: Some("pfSense".into()),
                    capabilities: self.capabilities(),
                    latency_ms: started.elapsed().as_millis() as u64,
                    message: if has_easyrule {
                        "pfSense reachable; easyrule available for block operations".into()
                    } else {
                        "pfSense reachable but easyrule was not found; blocking disabled".into()
                    },
                })
            }
            Err(err) => Ok(GatewayProbe {
                ok: false,
                kind: GatewayKind::PfSense,
                name: self.config.name.clone(),
                version: None,
                model: None,
                capabilities: self.capabilities(),
                latency_ms: started.elapsed().as_millis() as u64,
                message: format!("SSH probe failed: {err}"),
            }),
        }
    }

    async fn clients(&self) -> Result<Vec<GatewayClient>> {
        let output = self.ssh.run("arp -an 2>/dev/null").await?;
        let mut out = Vec::new();
        for line in output.lines() {
            let Some(open) = line.find('(') else { continue };
            let Some(close) = line[open..].find(')').map(|i| i + open) else {
                continue;
            };
            let ip = &line[open + 1..close];
            let hostname = line[..open].trim();
            let rest = &line[close + 1..];
            let Some(at) = rest.find(" at ") else {
                continue;
            };
            let mac_token = rest[at + 4..].split_whitespace().next().unwrap_or("");
            let Some(mac) = normalize_mac(mac_token) else {
                continue;
            };
            let iface = rest
                .split(" on ")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .map(str::to_string);
            out.push(GatewayClient {
                mac: Some(mac.clone()),
                ip: Some(ip.to_string()),
                hostname: Some(hostname.to_string()).filter(|h| !h.is_empty() && h != "?"),
                vendor: netcontrol_core::oui::lookup(&mac),
                interface: iface,
                ssid: None,
                online: true,
                rx_bytes: None,
                tx_bytes: None,
                rx_bps: None,
                tx_bps: None,
                blocked: None,
            });
        }
        Ok(out)
    }

    async fn block(&self, target: &Target, _expires_at: Option<&str>) -> Result<EnforcementResult> {
        let ip = Self::ip(target)?;
        let iface = self.firewall_interface()?;
        self.ssh
            .run(&format!(
                "easyrule block {} {}",
                sh_quote(&iface),
                sh_quote(&ip.to_string())
            ))
            .await?;
        let rules = self.rules().await?;
        let verified = rules.contains(&ip.to_string())
            && rules
                .lines()
                .any(|line| line.contains(&ip.to_string()) && line.contains("block"));
        Ok(verify_result(
            "pfsense",
            "block",
            target,
            verified,
            Some(ip.to_string()),
            if verified {
                format!("easyrule block applied and pfctl confirms a blocking rule for {ip}")
            } else {
                "easyrule reported success but pfctl does not show a blocking rule".into()
            },
        ))
    }

    async fn unblock(&self, target: &Target) -> Result<EnforcementResult> {
        let ip = Self::ip(target)?;
        let iface = self.firewall_interface()?;
        self.ssh
            .run(&format!(
                "easyrule unblock {} {}",
                sh_quote(&iface),
                sh_quote(&ip.to_string())
            ))
            .await?;
        let rules = self.rules().await?;
        let still_blocked = rules
            .lines()
            .any(|line| line.contains(&ip.to_string()) && line.contains("block"));
        Ok(verify_result(
            "pfsense",
            "unblock",
            target,
            !still_blocked,
            Some(ip.to_string()),
            if still_blocked {
                "pfctl still shows a blocking rule for this address".into()
            } else {
                format!("removed pfSense block for {ip}")
            },
        ))
    }

    async fn set_bandwidth(
        &self,
        target: &Target,
        _limit: &BandwidthLimit,
    ) -> Result<EnforcementResult> {
        Ok(EnforcementResult::unsupported(
            "pfsense",
            &target.label,
            "pfSense per-client bandwidth requires tailored limiter/queue configuration; NetControl does not automate it",
        ))
    }

    async fn clear_bandwidth(&self, target: &Target) -> Result<EnforcementResult> {
        Ok(EnforcementResult::unsupported(
            "pfsense",
            &target.label,
            "no NetControl limiter is managed on pfSense",
        ))
    }

    async fn list_enforced(&self) -> Result<Vec<EnforcedRule>> {
        let rules = self.rules().await?;
        Ok(rules
            .lines()
            .filter(|line| line.contains("block"))
            .filter_map(|line| {
                line.split_whitespace()
                    .find(|tok| tok.parse::<Ipv4Addr>().is_ok())
                    .map(|ip| EnforcedRule {
                        kind: "block".into(),
                        target: ip.into(),
                        rule_id: None,
                        detail: "pfSense blocking rule (pfctl)".into(),
                    })
            })
            .collect())
    }
}
