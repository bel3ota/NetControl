//! Optional Nmap integration.
//!
//! Nmap is invoked with an argument vector (never a shell) and the target is
//! always a validated CIDR or a list of validated IPs passed over stdin. XML
//! output is parsed into the shared host observation model.

use netcontrol_core::models::HostObservation;
use netcontrol_core::{Error, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

pub async fn available(nmap_path: &str) -> bool {
    Command::new(nmap_path)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Host discovery only (`nmap -sn`). Root enables ARP; without root Nmap
/// falls back to TCP/ICMP probes and reports what it can.
pub async fn discover(
    nmap_path: &str,
    cidr: &str,
    timeout: Duration,
) -> Result<Vec<HostObservation>> {
    let output = tokio::time::timeout(
        timeout,
        Command::new(nmap_path)
            .args(["-sn", "-oX", "-", "--host-timeout", "5s", cidr])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| Error::Gateway("nmap host discovery timed out".into()))??;
    if !output.status.success() {
        return Err(Error::Gateway(format!(
            "nmap failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(parse_xml(&String::from_utf8_lossy(&output.stdout)))
}

/// Explicit, authorized TCP port scan against already discovered hosts.
/// Passing an empty host list is an error rather than scanning the internet.
pub async fn port_scan(
    nmap_path: &str,
    hosts: &[String],
    timeout: Duration,
) -> Result<Vec<HostObservation>> {
    if hosts.is_empty() {
        return Ok(Vec::new());
    }
    let mut child = Command::new(nmap_path)
        .args([
            "-sT",
            "-Pn",
            "--top-ports",
            "100",
            "-T4",
            "-oX",
            "-",
            "-iL",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        let payload = format!("{}\n", hosts.join("\n"));
        stdin.write_all(payload.as_bytes()).await?;
        stdin.shutdown().await?;
    }
    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| Error::Gateway("nmap port scan timed out".into()))??;
    if !output.status.success() {
        return Err(Error::Gateway(format!(
            "nmap port scan failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(parse_xml(&String::from_utf8_lossy(&output.stdout)))
}

pub fn parse_xml(xml: &str) -> Vec<HostObservation> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut hosts = Vec::new();
    let mut current: Option<HostObservation> = None;
    let mut pending_port: Option<u16> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                let name = String::from_utf8_lossy(event.name().as_ref()).to_string();
                match name.as_str() {
                    "host" => {
                        current = Some(HostObservation {
                            ip: None,
                            ipv6: None,
                            mac: None,
                            hostname: None,
                            vendor: None,
                            category: netcontrol_core::models::DeviceCategory::Unknown,
                            rtt_ms: None,
                            open_ports: Vec::new(),
                            services: Vec::new(),
                            sources: vec!["nmap".into()],
                        })
                    }
                    "address" => {
                        if let Some(host) = current.as_mut() {
                            let attrs = attributes(&event);
                            match attrs.get("addrtype").map(String::as_str) {
                                Some("ipv4") => {
                                    if let Some(addr) = attrs.get("addr") {
                                        host.ip = Some(addr.clone());
                                    }
                                }
                                Some("ipv6") => {
                                    if let Some(addr) = attrs.get("addr") {
                                        host.ipv6 = Some(addr.clone());
                                    }
                                }
                                Some("mac") => {
                                    host.mac = attrs.get("addr").cloned();
                                    host.vendor = attrs.get("vendor").cloned();
                                }
                                _ => {}
                            }
                        }
                    }
                    "hostname" => {
                        if let Some(host) = current.as_mut() {
                            let attrs = attributes(&event);
                            if let Some(name) = attrs.get("name") {
                                host.hostname = Some(name.clone());
                            }
                        }
                    }
                    "port" => {
                        let attrs = attributes(&event);
                        pending_port = attrs.get("portid").and_then(|p| p.parse::<u16>().ok());
                    }
                    "state" => {
                        if let (Some(host), Some(port)) = (current.as_mut(), pending_port) {
                            let attrs = attributes(&event);
                            if attrs.get("state").map(String::as_str) == Some("open")
                                && !host.open_ports.contains(&port)
                            {
                                host.open_ports.push(port);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(event)) => {
                let name = String::from_utf8_lossy(event.name().as_ref()).to_string();
                match name.as_str() {
                    "status" => {
                        if let Some(host) = current.as_mut() {
                            let attrs = attributes(&event);
                            if attrs.get("state").map(String::as_str) == Some("down") {
                                host.sources.clear();
                                host.ip = None;
                            }
                        }
                    }
                    "address" => {
                        if let Some(host) = current.as_mut() {
                            let attrs = attributes(&event);
                            match attrs.get("addrtype").map(String::as_str) {
                                Some("ipv4") => {
                                    if let Some(addr) = attrs.get("addr") {
                                        host.ip = Some(addr.clone());
                                    }
                                }
                                Some("ipv6") => {
                                    if let Some(addr) = attrs.get("addr") {
                                        host.ipv6 = Some(addr.clone());
                                    }
                                }
                                Some("mac") => {
                                    host.mac = attrs.get("addr").cloned();
                                    host.vendor = attrs.get("vendor").cloned();
                                }
                                _ => {}
                            }
                        }
                    }
                    "hostname" => {
                        if let Some(host) = current.as_mut() {
                            let attrs = attributes(&event);
                            if let Some(name) = attrs.get("name") {
                                host.hostname = Some(name.clone());
                            }
                        }
                    }
                    "state" => {
                        if let (Some(host), Some(port)) = (current.as_mut(), pending_port) {
                            let attrs = attributes(&event);
                            if attrs.get("state").map(String::as_str) == Some("open")
                                && !host.open_ports.contains(&port)
                            {
                                host.open_ports.push(port);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(event)) => {
                if event.name().as_ref() == b"host" {
                    if let Some(host) = current.take() {
                        if host.ip.is_some() || host.ipv6.is_some() {
                            if !host.sources.is_empty() {
                                hosts.push(host);
                            }
                        }
                    }
                } else if event.name().as_ref() == b"port" {
                    pending_port = None;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }
    hosts
}

fn attributes(
    event: &quick_xml::events::BytesStart<'_>,
) -> std::collections::HashMap<String, String> {
    event
        .attributes()
        .flatten()
        .filter_map(|attr| {
            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
            let value = attr.unescape_value().ok()?.to_string();
            Some((key, value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme"/>
<hostnames><hostname name="printer.local" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="80"><state state="open"/></port>
<port protocol="tcp" portid="9100"><state state="open"/></port></ports></host>
<host><status state="down"/><address addr="192.168.1.11" addrtype="ipv4"/></host>
</nmaprun>"#;

    #[test]
    fn parses_nmap_xml() {
        let hosts = parse_xml(XML);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip.as_deref(), Some("192.168.1.10"));
        assert_eq!(hosts[0].hostname.as_deref(), Some("printer.local"));
        assert_eq!(hosts[0].vendor.as_deref(), Some("Acme"));
        assert_eq!(hosts[0].open_ports, vec![80, 9100]);
    }
}
