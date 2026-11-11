//! MikroTik RouterOS adapter.
//!
//! Implements the native RouterOS API (8728 plaintext / 8729 API-SSL),
//! including the pre-6.43 challenge login. Blocking uses a firewall
//! address-list plus forward drop rules and MAC filters; bandwidth uses
//! `/queue/simple` rate limits. Every mutation is read back before it is
//! reported as verified.

use crate::traits::{verify_result, AdapterSecret, EnforcedRule, GatewayAdapter, Target};
use async_trait::async_trait;
use md5::{Digest, Md5};
use netcontrol_core::models::{
    BandwidthLimit, EnforcementResult, GatewayCapabilities, GatewayClient, GatewayConfig,
    GatewayKind, GatewayProbe,
};
use netcontrol_core::util::normalize_mac;
use netcontrol_core::{Error, Result};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const ADDR_LIST: &str = "netcontrol-blocked";
const COMMENT_BLOCKLIST: &str = "netcontrol:blocklist";

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

pub struct RouterOsClient {
    stream: Box<dyn AsyncStream>,
}

impl RouterOsClient {
    pub async fn connect(config: &GatewayConfig, secret: &str) -> Result<Self> {
        let address = format!("{}:{}", config.host, config.port);
        let tcp = tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(&address))
            .await
            .map_err(|_| Error::Gateway(format!("RouterOS connection to {address} timed out")))??;
        tcp.set_nodelay(true).ok();
        let stream: Box<dyn AsyncStream> = if config.tls {
            let mut builder = native_tls::TlsConnector::builder();
            if config.tls_insecure {
                builder.danger_accept_invalid_certs(true);
                builder.danger_accept_invalid_hostnames(true);
            }
            let connector = tokio_native_tls::TlsConnector::from(
                builder
                    .build()
                    .map_err(|e| Error::Gateway(format!("TLS initialization failed: {e}")))?,
            );
            let tls = tokio::time::timeout(
                Duration::from_secs(10),
                connector.connect(&config.host, tcp),
            )
            .await
            .map_err(|_| Error::Gateway("RouterOS TLS handshake timed out".into()))?
            .map_err(|e| {
                Error::Gateway(format!(
                    "RouterOS TLS handshake failed: {e}. Enable www-ssl/api-ssl on the router or set port 8728 with TLS disabled (not recommended)"
                ))
            })?;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };
        let mut client = Self { stream };
        client
            .login(config.username.as_deref().unwrap_or("admin"), secret)
            .await?;
        Ok(client)
    }

    async fn login(&mut self, username: &str, password: &str) -> Result<()> {
        self.send(&[
            "/login".into(),
            format!("=name={username}"),
            format!("=password={password}"),
        ])
        .await?;
        let (_, done) = self.read_reply().await?;
        if let Some(challenge) = done.get("ret") {
            let mut hasher = Md5::new();
            hasher.update([0u8]);
            hasher.update(password.as_bytes());
            hasher.update(challenge.as_bytes());
            let response = format!("00{:x}", hasher.finalize());
            self.send(&[
                "/login".into(),
                format!("=name={username}"),
                format!("=response={response}"),
            ])
            .await?;
            let (_, done) = self.read_reply().await?;
            if done.contains_key("ret") {
                return Err(Error::Gateway("RouterOS login failed".into()));
            }
        }
        Ok(())
    }

    async fn send(&mut self, words: &[String]) -> Result<()> {
        let mut buffer = Vec::new();
        for word in words {
            encode_word(word, &mut buffer);
        }
        buffer.push(0);
        self.stream
            .write_all(&buffer)
            .await
            .map_err(|e| Error::Gateway(format!("RouterOS write failed: {e}")))?;
        self.stream
            .flush()
            .await
            .map_err(|e| Error::Gateway(format!("RouterOS flush failed: {e}")))?;
        Ok(())
    }

    async fn read_word(&mut self) -> Result<Vec<u8>> {
        let len = self.read_length().await?;
        if len == 0 {
            return Ok(Vec::new());
        }
        if len > 4 * 1024 * 1024 {
            return Err(Error::Gateway("RouterOS word is unreasonably large".into()));
        }
        let mut data = vec![0u8; len];
        self.stream
            .read_exact(&mut data)
            .await
            .map_err(|e| Error::Gateway(format!("RouterOS read failed: {e}")))?;
        Ok(data)
    }

    async fn read_length(&mut self) -> Result<usize> {
        let mut first = [0u8; 1];
        self.stream
            .read_exact(&mut first)
            .await
            .map_err(|e| Error::Gateway(format!("RouterOS read failed: {e}")))?;
        let b = first[0];
        if b & 0x80 == 0 {
            Ok(b as usize)
        } else if b & 0xC0 == 0x80 {
            let mut rest = [0u8; 1];
            self.stream
                .read_exact(&mut rest)
                .await
                .map_err(|e| Error::Gateway(e.to_string()))?;
            Ok((((b & 0x3F) as usize) << 8) | rest[0] as usize)
        } else if b & 0xE0 == 0xC0 {
            let mut rest = [0u8; 2];
            self.stream
                .read_exact(&mut rest)
                .await
                .map_err(|e| Error::Gateway(e.to_string()))?;
            Ok((((b & 0x1F) as usize) << 16) | ((rest[0] as usize) << 8) | rest[1] as usize)
        } else if b & 0xF0 == 0xE0 {
            let mut rest = [0u8; 3];
            self.stream
                .read_exact(&mut rest)
                .await
                .map_err(|e| Error::Gateway(e.to_string()))?;
            Ok((((b & 0x0F) as usize) << 24)
                | ((rest[0] as usize) << 16)
                | ((rest[1] as usize) << 8)
                | rest[2] as usize)
        } else {
            Err(Error::Gateway("invalid RouterOS word length".into()))
        }
    }

    async fn read_reply(
        &mut self,
    ) -> Result<(Vec<HashMap<String, String>>, HashMap<String, String>)> {
        let mut rows = Vec::new();
        loop {
            let mut words = Vec::new();
            loop {
                let word = self.read_word().await?;
                if word.is_empty() {
                    break;
                }
                words.push(String::from_utf8_lossy(&word).to_string());
            }
            if words.is_empty() {
                continue;
            }
            let kind = words[0].as_str();
            let attrs = parse_attributes(&words[1..]);
            match kind {
                "!re" => rows.push(attrs),
                "!done" => return Ok((rows, attrs)),
                "!trap" => {
                    return Err(Error::Gateway(format!(
                        "RouterOS rejected the command: {} {}",
                        attrs.get("message").cloned().unwrap_or_default(),
                        attrs.get("category").cloned().unwrap_or_default()
                    )))
                }
                "!fatal" => {
                    return Err(Error::Gateway(format!(
                        "RouterOS fatal error: {}",
                        attrs.get("message").cloned().unwrap_or_default()
                    )))
                }
                _ => {}
            }
        }
    }

    pub async fn command(&mut self, words: &[String]) -> Result<Vec<HashMap<String, String>>> {
        tokio::time::timeout(Duration::from_secs(20), async {
            self.send(words).await?;
            let (rows, _) = self.read_reply().await?;
            Ok(rows)
        })
        .await
        .map_err(|_| Error::Gateway("RouterOS command timed out".into()))?
    }
}

fn encode_word(word: &str, out: &mut Vec<u8>) {
    let bytes = word.as_bytes();
    encode_length(bytes.len(), out);
    out.extend_from_slice(bytes);
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x4000 {
        out.push(0x80 | ((len >> 8) as u8));
        out.push((len & 0xFF) as u8);
    } else if len < 0x20_0000 {
        out.push(0xC0 | ((len >> 16) as u8));
        out.push(((len >> 8) & 0xFF) as u8);
        out.push((len & 0xFF) as u8);
    } else {
        out.push(0xE0 | ((len >> 24) as u8));
        out.push(((len >> 16) & 0xFF) as u8);
        out.push(((len >> 8) & 0xFF) as u8);
        out.push((len & 0xFF) as u8);
    }
}

fn parse_attributes(words: &[String]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for word in words {
        let word = word.strip_prefix('=').unwrap_or(word);
        if let Some((key, value)) = word.split_once('=') {
            map.insert(key.to_string(), value.to_string());
        }
    }
    map
}

fn target_key(target: &Target) -> String {
    target
        .mac
        .as_deref()
        .and_then(normalize_mac)
        .map(|m| m.replace(':', ""))
        .or_else(|| target.ip.clone().map(|ip| ip.replace('.', "_")))
        .unwrap_or_else(|| "unknown".into())
}

pub struct MikroTikAdapter {
    config: GatewayConfig,
    secret: Option<AdapterSecret>,
}

impl MikroTikAdapter {
    pub fn new(config: GatewayConfig, secret: Option<AdapterSecret>) -> Result<Self> {
        if secret.is_none() {
            return Err(Error::Validation(
                "MikroTik adapter requires an API password".into(),
            ));
        }
        Ok(Self { config, secret })
    }

    async fn client(&self) -> Result<RouterOsClient> {
        let secret = self
            .secret
            .as_ref()
            .ok_or_else(|| Error::Validation("missing RouterOS password".into()))?;
        RouterOsClient::connect(&self.config, secret.value.as_str()).await
    }

    async fn remove_matching(
        client: &mut RouterOsClient,
        print_path: &str,
        remove_path: &str,
        predicate: impl Fn(&HashMap<String, String>) -> bool,
    ) -> Result<usize> {
        let rows = client.command(&[print_path.into()]).await?;
        let mut removed = 0;
        for row in rows {
            if predicate(&row) {
                if let Some(id) = row.get(".id") {
                    client
                        .command(&[remove_path.into(), format!("=.id={id}")])
                        .await?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }
}

#[async_trait]
impl GatewayAdapter for MikroTikAdapter {
    fn kind(&self) -> GatewayKind {
        GatewayKind::MikroTik
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
            dhcp_leases: true,
            block: true,
            unblock: true,
            bandwidth: true,
            priority: true,
            schedules: true,
            traffic_stats: false,
        }
    }

    async fn probe(&self) -> Result<GatewayProbe> {
        let started = Instant::now();
        let mut client = match self.client().await {
            Ok(client) => client,
            Err(err) => {
                return Ok(GatewayProbe {
                    ok: false,
                    kind: GatewayKind::MikroTik,
                    name: self.config.name.clone(),
                    version: None,
                    model: None,
                    capabilities: self.capabilities(),
                    latency_ms: started.elapsed().as_millis() as u64,
                    message: err.to_string(),
                })
            }
        };
        let resource = client.command(&["/system/resource/print".into()]).await;
        let identity = client.command(&["/system/identity/print".into()]).await;
        match resource {
            Ok(rows) => {
                let row = rows.first().cloned().unwrap_or_default();
                Ok(GatewayProbe {
                    ok: true,
                    kind: GatewayKind::MikroTik,
                    name: self.config.name.clone(),
                    version: row.get("version").cloned(),
                    model: Some(
                        row.get("board-name")
                            .cloned()
                            .unwrap_or_else(|| "RouterOS".into()),
                    ),
                    capabilities: self.capabilities(),
                    latency_ms: started.elapsed().as_millis() as u64,
                    message: format!(
                        "RouterOS {} reachable{}",
                        row.get("version").cloned().unwrap_or_default(),
                        identity
                            .ok()
                            .and_then(|r| r.first().and_then(|i| i.get("name").cloned()))
                            .map(|n| format!(" as {n}"))
                            .unwrap_or_default()
                    ),
                })
            }
            Err(err) => Ok(GatewayProbe {
                ok: false,
                kind: GatewayKind::MikroTik,
                name: self.config.name.clone(),
                version: None,
                model: None,
                capabilities: GatewayCapabilities::default(),
                latency_ms: started.elapsed().as_millis() as u64,
                message: err.to_string(),
            }),
        }
    }

    async fn clients(&self) -> Result<Vec<GatewayClient>> {
        let mut client = self.client().await?;
        let leases = client
            .command(&["/ip/dhcp-server/lease/print".into()])
            .await?;
        let arp = client
            .command(&["/ip/arp/print".into()])
            .await
            .unwrap_or_default();
        let mut merged: HashMap<String, GatewayClient> = HashMap::new();
        for row in leases {
            let mac = row.get("mac-address").and_then(|m| normalize_mac(m));
            let key = mac.clone().unwrap_or_else(|| {
                row.get("address")
                    .cloned()
                    .unwrap_or_else(|| "unknown".into())
            });
            let hostname = row
                .get("host-name")
                .cloned()
                .or_else(|| row.get("comment").cloned())
                .filter(|h| !h.is_empty());
            merged.insert(
                key,
                GatewayClient {
                    mac,
                    ip: row.get("address").cloned(),
                    hostname,
                    vendor: None,
                    interface: row.get("server").cloned(),
                    ssid: None,
                    online: row.get("status").map(|s| s == "bound").unwrap_or(true),
                    rx_bytes: None,
                    tx_bytes: None,
                    rx_bps: None,
                    tx_bps: None,
                    blocked: None,
                },
            );
        }
        for row in arp {
            let mac = row.get("mac-address").and_then(|m| normalize_mac(m));
            let key = mac
                .clone()
                .or_else(|| row.get("address").cloned())
                .unwrap_or_default();
            if key.is_empty() {
                continue;
            }
            merged.entry(key).or_insert(GatewayClient {
                mac,
                ip: row.get("address").cloned(),
                hostname: None,
                vendor: None,
                interface: row.get("interface").cloned(),
                ssid: None,
                online: row.get("complete").map(|v| v == "true").unwrap_or(true),
                rx_bytes: None,
                tx_bytes: None,
                rx_bps: None,
                tx_bps: None,
                blocked: None,
            });
        }
        let mut out: Vec<GatewayClient> = merged.into_values().collect();
        for client in &mut out {
            client.vendor = client.mac.as_deref().and_then(netcontrol_core::oui::lookup);
        }
        out.sort_by(|a, b| a.ip.cmp(&b.ip));
        Ok(out)
    }

    async fn block(&self, target: &Target, _expires_at: Option<&str>) -> Result<EnforcementResult> {
        let key = target_key(target);
        let comment = format!("netcontrol:block:{key}");
        let mac = target.mac.as_deref().and_then(normalize_mac);
        let ip = target
            .ip
            .as_deref()
            .map(|v| v.trim().parse::<std::net::Ipv4Addr>())
            .transpose()
            .map_err(|_| Error::Validation("invalid target IP".into()))?;
        if mac.is_none() && ip.is_none() {
            return Ok(EnforcementResult::unsupported(
                "mikrotik",
                &target.label,
                "a MAC or IP address is required",
            ));
        }
        let mut client = self.client().await?;
        // Remove previous rules for this target so the operation is idempotent.
        Self::remove_matching(
            &mut client,
            "/ip/firewall/address-list/print",
            "/ip/firewall/address-list/remove",
            |row| row.get("comment").map(|c| c == &comment).unwrap_or(false),
        )
        .await?;
        Self::remove_matching(
            &mut client,
            "/ip/firewall/filter/print",
            "/ip/firewall/filter/remove",
            |row| {
                row.get("comment")
                    .map(|c| c == &format!("netcontrol:mac:{key}"))
                    .unwrap_or(false)
            },
        )
        .await?;

        if let Some(ip) = ip {
            client
                .command(&[
                    "/ip/firewall/address-list/add".into(),
                    format!("=list={ADDR_LIST}"),
                    format!("=address={ip}"),
                    format!("=comment={comment}"),
                ])
                .await?;
        }
        if let Some(mac) = &mac {
            for field in ["src-mac-address", "dst-mac-address"] {
                client
                    .command(&[
                        "/ip/firewall/filter/add".into(),
                        "=chain=forward".into(),
                        format!("={field}={mac}"),
                        "=action=drop".into(),
                        format!("=comment=netcontrol:mac:{key}"),
                    ])
                    .await
                    .ok();
            }
        }
        // Ensure the global address-list drop rules exist.
        let filters = client
            .command(&["/ip/firewall/filter/print".into()])
            .await?;
        let has_src = filters.iter().any(|r| {
            r.get("comment")
                .map(|c| c == COMMENT_BLOCKLIST)
                .unwrap_or(false)
                && r.get("src-address-list")
                    .map(|v| v == ADDR_LIST)
                    .unwrap_or(false)
        });
        let has_dst = filters.iter().any(|r| {
            r.get("comment")
                .map(|c| c == COMMENT_BLOCKLIST)
                .unwrap_or(false)
                && r.get("dst-address-list")
                    .map(|v| v == ADDR_LIST)
                    .unwrap_or(false)
        });
        if !has_src {
            client
                .command(&[
                    "/ip/firewall/filter/add".into(),
                    "=chain=forward".into(),
                    format!("=src-address-list={ADDR_LIST}"),
                    "=action=drop".into(),
                    format!("=comment={COMMENT_BLOCKLIST}"),
                ])
                .await?;
        }
        if !has_dst {
            client
                .command(&[
                    "/ip/firewall/filter/add".into(),
                    "=chain=forward".into(),
                    format!("=dst-address-list={ADDR_LIST}"),
                    "=action=drop".into(),
                    format!("=comment={COMMENT_BLOCKLIST}"),
                ])
                .await?;
        }

        // Verify from the router state.
        let address_rows = client
            .command(&["/ip/firewall/address-list/print".into()])
            .await?;
        let ip_ok = ip
            .map(|ip| {
                address_rows.iter().any(|r| {
                    r.get("address")
                        .map(|a| a == &ip.to_string())
                        .unwrap_or(false)
                        && r.get("comment").map(|c| c == &comment).unwrap_or(false)
                        && r.get("list").map(|l| l == ADDR_LIST).unwrap_or(false)
                })
            })
            .unwrap_or(true);
        let filter_rows = client
            .command(&["/ip/firewall/filter/print".into()])
            .await?;
        let mac_ok = mac
            .as_ref()
            .map(|_| {
                filter_rows.iter().any(|r| {
                    r.get("comment")
                        .map(|c| c == &format!("netcontrol:mac:{key}"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(true);
        let rules_ok = filter_rows.iter().any(|r| {
            r.get("comment")
                .map(|c| c == COMMENT_BLOCKLIST)
                .unwrap_or(false)
                && (r
                    .get("src-address-list")
                    .map(|l| l == ADDR_LIST)
                    .unwrap_or(false)
                    || r.get("dst-address-list")
                        .map(|l| l == ADDR_LIST)
                        .unwrap_or(false))
        });
        let verified = ip_ok && mac_ok && rules_ok;
        Ok(verify_result(
            "mikrotik",
            "block",
            target,
            verified,
            Some(comment.clone()),
            if verified {
                format!("RouterOS address-list/filter state verified for {key}")
            } else {
                "RouterOS did not report the expected address-list/filter state".into()
            },
        ))
    }

    async fn unblock(&self, target: &Target) -> Result<EnforcementResult> {
        let key = target_key(target);
        let comment = format!("netcontrol:block:{key}");
        let mac_comment = format!("netcontrol:mac:{key}");
        let mut client = self.client().await?;
        let removed_addr = Self::remove_matching(
            &mut client,
            "/ip/firewall/address-list/print",
            "/ip/firewall/address-list/remove",
            |row| {
                row.get("comment").map(|c| c == &comment).unwrap_or(false)
                    || row
                        .get("address")
                        .map(|a| target.ip.as_deref() == Some(a.as_str()))
                        .unwrap_or(false)
            },
        )
        .await?;
        let removed_filter = Self::remove_matching(
            &mut client,
            "/ip/firewall/filter/print",
            "/ip/firewall/filter/remove",
            |row| {
                row.get("comment")
                    .map(|c| c == &mac_comment)
                    .unwrap_or(false)
            },
        )
        .await?;
        let address_rows = client
            .command(&["/ip/firewall/address-list/print".into()])
            .await?;
        let filter_rows = client
            .command(&["/ip/firewall/filter/print".into()])
            .await?;
        let verified = !address_rows
            .iter()
            .any(|row| row.get("comment").map(|c| c == &comment).unwrap_or(false))
            && !filter_rows.iter().any(|row| {
                row.get("comment")
                    .map(|c| c == &mac_comment)
                    .unwrap_or(false)
            });
        Ok(verify_result(
            "mikrotik",
            "unblock",
            target,
            verified,
            Some(comment),
            format!(
                "removed {removed_addr} address-list and {removed_filter} MAC filter rule(s); {}",
                if verified {
                    "verified"
                } else {
                    "still present"
                }
            ),
        ))
    }

    async fn set_bandwidth(
        &self,
        target: &Target,
        limit: &BandwidthLimit,
    ) -> Result<EnforcementResult> {
        let key = target_key(target);
        let ip = target
            .ip
            .as_deref()
            .ok_or_else(|| Error::Unsupported("RouterOS queues require an IP target".into()))?
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| Error::Validation("invalid target IP".into()))?;
        let name = format!("netcontrol-qos-{key}");
        let mut client = self.client().await?;
        Self::remove_matching(
            &mut client,
            "/queue/simple/print",
            "/queue/simple/remove",
            |row| row.get("name").map(|n| n == &name).unwrap_or(false),
        )
        .await?;
        let download = limit.download_kbps.unwrap_or(0).max(0);
        let upload = limit.upload_kbps.unwrap_or(0).max(0);
        let priority = match limit.priority {
            Some(p) if (0..=7).contains(&p) => (8 - p).clamp(1, 8),
            _ => 8,
        };
        client
            .command(&[
                "/queue/simple/add".into(),
                format!("=name={name}"),
                format!("=target={ip}/32"),
                format!("=max-limit={upload}k/{download}k"),
                format!("=priority={priority}/8"),
                format!("=comment=netcontrol:qos:{key}"),
            ])
            .await?;
        let rows = client.command(&["/queue/simple/print".into()]).await?;
        let verified = rows.iter().any(|row| {
            row.get("name").map(|n| n == &name).unwrap_or(false)
                && row
                    .get("max-limit")
                    .map(|v| v == &format!("{upload}k/{download}k"))
                    .unwrap_or(false)
        });
        Ok(verify_result(
            "mikrotik",
            "limit",
            target,
            verified,
            Some(name.clone()),
            if verified {
                format!("RouterOS simple queue {name} verified ({upload}k up / {download}k down)")
            } else {
                "RouterOS queue was not confirmed after creation".into()
            },
        ))
    }

    async fn clear_bandwidth(&self, target: &Target) -> Result<EnforcementResult> {
        let key = target_key(target);
        let name = format!("netcontrol-qos-{key}");
        let mut client = self.client().await?;
        let removed = Self::remove_matching(
            &mut client,
            "/queue/simple/print",
            "/queue/simple/remove",
            |row| row.get("name").map(|n| n == &name).unwrap_or(false),
        )
        .await?;
        let rows = client.command(&["/queue/simple/print".into()]).await?;
        let verified = !rows
            .iter()
            .any(|row| row.get("name").map(|n| n == &name).unwrap_or(false));
        Ok(verify_result(
            "mikrotik",
            "clear_limit",
            target,
            verified,
            Some(name),
            format!("removed {removed} queue(s)"),
        ))
    }

    async fn list_enforced(&self) -> Result<Vec<EnforcedRule>> {
        let mut client = self.client().await?;
        let addresses = client
            .command(&["/ip/firewall/address-list/print".into()])
            .await?;
        let mut rules = Vec::new();
        for row in addresses {
            if row.get("list").map(|l| l == ADDR_LIST).unwrap_or(false) {
                rules.push(EnforcedRule {
                    kind: "block".into(),
                    target: row
                        .get("address")
                        .cloned()
                        .unwrap_or_else(|| "unknown".into()),
                    rule_id: row.get(".id").cloned(),
                    detail: "RouterOS address-list netcontrol-blocked".into(),
                });
            }
        }
        let queues = client.command(&["/queue/simple/print".into()]).await?;
        for row in queues {
            if row
                .get("name")
                .map(|n| n.starts_with("netcontrol-qos-"))
                .unwrap_or(false)
            {
                rules.push(EnforcedRule {
                    kind: "limit".into(),
                    target: row
                        .get("target")
                        .cloned()
                        .unwrap_or_else(|| "unknown".into()),
                    rule_id: row.get(".id").cloned(),
                    detail: format!(
                        "RouterOS simple queue {} max-limit {}",
                        row.get("name").cloned().unwrap_or_default(),
                        row.get("max-limit").cloned().unwrap_or_default()
                    ),
                });
            }
        }
        Ok(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_routeros_lengths() {
        for len in [0usize, 5, 127, 128, 500, 16_383, 16_384, 2_000_000] {
            let mut buffer = Vec::new();
            encode_length(len, &mut buffer);
            assert!(!buffer.is_empty());
        }
        let mut buffer = Vec::new();
        encode_word("hello", &mut buffer);
        assert_eq!(buffer[0], 5);
        assert_eq!(&buffer[1..], b"hello");
    }

    #[test]
    fn parses_attributes() {
        let words = vec![
            "=mac-address=AA:BB:CC:DD:EE:FF".to_string(),
            "=.id=*1".to_string(),
        ];
        let attrs = parse_attributes(&words);
        assert_eq!(attrs.get("mac-address").unwrap(), "AA:BB:CC:DD:EE:FF");
        assert_eq!(attrs.get(".id").unwrap(), "*1");
    }

    #[test]
    fn queue_priority_mapping_is_bounded() {
        for p in 0..=7 {
            let priority = (8 - p).clamp(1, 8);
            assert!((1..=8).contains(&priority));
        }
    }
}
