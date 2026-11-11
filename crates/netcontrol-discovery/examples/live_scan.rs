//! Developer utility: run a real scan and print the result.
//!
//! Usage: cargo run -p netcontrol-discovery --example live_scan -- [interface]

use netcontrol_core::models::ScanOptions;
use netcontrol_discovery::{DiscoveryEngine, InterfaceManager};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let interface = std::env::args().nth(1);
    let interfaces = InterfaceManager::list()?;
    println!("== interfaces ==");
    for iface in &interfaces {
        println!(
            "{:<16} {:<14} up={:<5} default={:<5} mac={:<17} v4={:?} gw={:?} ssid={:?}",
            iface.name,
            iface.kind.as_str(),
            iface.is_up,
            iface.is_default,
            iface.mac.clone().unwrap_or_default(),
            iface
                .ipv4
                .iter()
                .map(|v| v.cidr.clone())
                .collect::<Vec<_>>(),
            iface.gateway4,
            iface.ssid
        );
    }
    let engine = DiscoveryEngine::new();
    println!("tools: {:?}", engine.tools);
    let opts = ScanOptions {
        interface: interface.clone(),
        confirmed: true,
        ports: std::env::var("NETCONTROL_SCAN_PORTS").is_ok(),
        nmap: std::env::var("NETCONTROL_SCAN_NMAP").is_ok(),
        methods: vec![
            netcontrol_core::models::ScanMethod::Neighbor,
            netcontrol_core::models::ScanMethod::Icmp,
            netcontrol_core::models::ScanMethod::Mdns,
        ],
        ..Default::default()
    };
    let (iface, net, report) = engine.scan_active(&opts).await?;
    println!("\n== scan ==");
    println!(
        "interface={} cidr={} gateway={:?} ssid={:?}",
        iface.name, net.cidr, net.gateway, net.ssid
    );
    println!(
        "methods={:?} privileged={} hosts={}",
        report.methods_used,
        report.privileged,
        report.hosts.len()
    );
    for warning in &report.warnings {
        println!("warning: {warning}");
    }
    for host in &report.hosts {
        println!(
            "{:<16} {:<17} {:<28} {:<12} vendor={:?} ports={:?} services={:?} sources={:?} rtt={:?}",
            host.ip.clone().or(host.ipv6.clone()).unwrap_or_default(),
            host.mac.clone().unwrap_or_default(),
            host.hostname.clone().unwrap_or_default(),
            host.category.as_str(),
            host.vendor,
            host.open_ports,
            host.services,
            host.sources,
            host.rtt_ms
        );
    }
    Ok(())
}
