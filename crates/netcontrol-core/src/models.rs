//! Shared domain model. These types are serialized by the CLI, REST API,
//! desktop application and Android client, so their wire representation is a
//! public contract. Field names use snake_case on the wire.

use serde::{Deserialize, Serialize};
use std::fmt;

pub type Timestamp = String;
pub type DeviceId = String;

/// High level device classification. This is intentionally conservative:
/// `Unknown` is preferred over an incorrect guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeviceCategory {
    Smartphone,
    Tablet,
    Laptop,
    Desktop,
    Server,
    Printer,
    SmartTv,
    Streaming,
    Router,
    Switch,
    AccessPoint,
    Camera,
    Speaker,
    GameConsole,
    Wearable,
    Iot,
    Nas,
    #[default]
    Unknown,
}

impl DeviceCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Smartphone => "smartphone",
            Self::Tablet => "tablet",
            Self::Laptop => "laptop",
            Self::Desktop => "desktop",
            Self::Server => "server",
            Self::Printer => "printer",
            Self::SmartTv => "smart_tv",
            Self::Streaming => "streaming",
            Self::Router => "router",
            Self::Switch => "switch",
            Self::AccessPoint => "access_point",
            Self::Camera => "camera",
            Self::Speaker => "speaker",
            Self::GameConsole => "game_console",
            Self::Wearable => "wearable",
            Self::Iot => "iot",
            Self::Nas => "nas",
            Self::Unknown => "unknown",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Smartphone => "Smartphone",
            Self::Tablet => "Tablet",
            Self::Laptop => "Laptop",
            Self::Desktop => "Desktop",
            Self::Server => "Server",
            Self::Printer => "Printer",
            Self::SmartTv => "Smart TV",
            Self::Streaming => "Streaming device",
            Self::Router => "Router",
            Self::Switch => "Switch",
            Self::AccessPoint => "Access point",
            Self::Camera => "Camera",
            Self::Speaker => "Speaker",
            Self::GameConsole => "Game console",
            Self::Wearable => "Wearable",
            Self::Iot => "IoT device",
            Self::Nas => "NAS",
            Self::Unknown => "Unknown",
        }
    }

    pub const ALL: [DeviceCategory; 18] = [
        Self::Smartphone,
        Self::Tablet,
        Self::Laptop,
        Self::Desktop,
        Self::Server,
        Self::Printer,
        Self::SmartTv,
        Self::Streaming,
        Self::Router,
        Self::Switch,
        Self::AccessPoint,
        Self::Camera,
        Self::Speaker,
        Self::GameConsole,
        Self::Wearable,
        Self::Iot,
        Self::Nas,
        Self::Unknown,
    ];
}

impl fmt::Display for DeviceCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for DeviceCategory {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "smartphone" => Self::Smartphone,
            "tablet" => Self::Tablet,
            "laptop" => Self::Laptop,
            "desktop" => Self::Desktop,
            "server" => Self::Server,
            "printer" => Self::Printer,
            "smart_tv" => Self::SmartTv,
            "streaming" => Self::Streaming,
            "router" => Self::Router,
            "switch" => Self::Switch,
            "access_point" => Self::AccessPoint,
            "camera" => Self::Camera,
            "speaker" => Self::Speaker,
            "game_console" => Self::GameConsole,
            "wearable" => Self::Wearable,
            "iot" => Self::Iot,
            "nas" => Self::Nas,
            "unknown" => Self::Unknown,
            other => {
                return Err(crate::Error::Validation(format!(
                    "unknown device category: {other}"
                )))
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CategorySource {
    #[default]
    Auto,
    Manual,
}

impl CategorySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementState {
    #[default]
    None,
    Pending,
    Applied,
    Failed,
    Unsupported,
    Expired,
}

impl EnforcementState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Failed => "failed",
            Self::Unsupported => "unsupported",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: DeviceId,
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub ipv6: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub category: DeviceCategory,
    pub category_source: CategorySource,
    pub custom_name: Option<String>,
    pub notes: Option<String>,
    pub interface: Option<String>,
    pub ssid: Option<String>,
    pub online: bool,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub open_ports: Vec<u16>,
    pub services: Vec<String>,
    pub sources: Vec<String>,
    pub is_trusted: bool,
    pub is_blocked: bool,
    pub blocked_until: Option<Timestamp>,
    pub block_source: Option<String>,
    pub limit_download_kbps: Option<i64>,
    pub limit_upload_kbps: Option<i64>,
    pub limit_expires_at: Option<Timestamp>,
    pub priority: Option<i32>,
    pub enforcement: EnforcementState,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl Device {
    pub fn display_name(&self) -> String {
        self.custom_name
            .clone()
            .or_else(|| self.hostname.clone())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| {
                self.ip
                    .clone()
                    .or_else(|| self.mac.clone())
                    .unwrap_or_else(|| "Unnamed device".to_string())
            })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DevicePatch {
    pub custom_name: Option<String>,
    pub category: Option<DeviceCategory>,
    pub notes: Option<String>,
    pub is_trusted: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFilter {
    pub query: Option<String>,
    pub online: Option<bool>,
    pub blocked: Option<bool>,
    pub trusted: Option<bool>,
    pub category: Option<DeviceCategory>,
    pub interface: Option<String>,
    pub sort: Option<String>,
    pub descending: bool,
    pub limit: u32,
    pub offset: u32,
}

impl Default for DeviceFilter {
    fn default() -> Self {
        Self {
            query: None,
            online: None,
            blocked: None,
            trusted: None,
            category: None,
            interface: None,
            sort: None,
            descending: false,
            limit: 100,
            offset: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Paged<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceHistory {
    pub id: i64,
    pub device_id: DeviceId,
    pub ts: Timestamp,
    pub event: String,
    pub detail: Option<String>,
    pub scan_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    Wifi,
    Ethernet,
    UsbEthernet,
    Virtual,
    Loopback,
    Other,
}

impl InterfaceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wifi => "wifi",
            Self::Ethernet => "ethernet",
            Self::UsbEthernet => "usb_ethernet",
            Self::Virtual => "virtual",
            Self::Loopback => "loopback",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for InterfaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Info {
    pub address: String,
    pub prefix: u8,
    pub netmask: String,
    pub broadcast: Option<String>,
    pub cidr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub kind: InterfaceKind,
    pub mac: Option<String>,
    pub is_up: bool,
    pub is_loopback: bool,
    pub is_default: bool,
    pub ipv4: Vec<Ipv4Info>,
    pub ipv6: Vec<String>,
    pub gateway4: Option<String>,
    pub gateway6: Option<String>,
    pub dns: Vec<String>,
    pub ssid: Option<String>,
    pub speed_mbps: Option<u64>,
    pub driver: Option<String>,
    pub usb: bool,
}

impl NetworkInterface {
    pub fn primary_ipv4(&self) -> Option<&Ipv4Info> {
        self.ipv4.first()
    }

    pub fn display(&self) -> String {
        match self.primary_ipv4() {
            Some(v4) => format!("{} ({}, {})", self.name, v4.cidr, self.kind),
            None => format!("{} ({})", self.name, self.kind),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub id: Option<String>,
    pub interface: String,
    pub kind: InterfaceKind,
    pub ssid: Option<String>,
    pub cidr: String,
    pub local_ip: String,
    pub gateway: Option<String>,
    pub dns: Vec<String>,
    pub mac: Option<String>,
    pub online: bool,
    pub first_seen: Option<Timestamp>,
    pub last_seen: Option<Timestamp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ScanMethod {
    Neighbor,
    Icmp,
    Arp,
    Tcp,
    Nmap,
    Mdns,
}

impl ScanMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Neighbor => "neighbor",
            Self::Icmp => "icmp",
            Self::Arp => "arp",
            Self::Tcp => "tcp",
            Self::Nmap => "nmap",
            Self::Mdns => "mdns",
        }
    }
}

impl std::str::FromStr for ScanMethod {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "neighbor" | "arp-cache" => Self::Neighbor,
            "icmp" | "ping" => Self::Icmp,
            "arp" | "arp-scan" => Self::Arp,
            "tcp" => Self::Tcp,
            "nmap" => Self::Nmap,
            "mdns" => Self::Mdns,
            other => {
                return Err(crate::Error::Validation(format!(
                    "unknown scan method: {other}"
                )))
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub interface: Option<String>,
    pub methods: Vec<ScanMethod>,
    pub nmap: bool,
    pub ports: bool,
    pub timeout_ms: u64,
    pub max_hosts: u32,
    pub mdns: bool,
    /// Permit scanning non-RFC1918/ULA destinations. Off by default.
    pub allow_public: bool,
    /// Explicit acknowledgement that the operator is authorized to scan.
    pub confirmed: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            interface: None,
            methods: vec![ScanMethod::Neighbor, ScanMethod::Icmp, ScanMethod::Mdns],
            nmap: false,
            ports: false,
            timeout_ms: 1200,
            max_hosts: 1024,
            mdns: true,
            allow_public: false,
            confirmed: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostObservation {
    pub ip: Option<String>,
    pub ipv6: Option<String>,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub category: DeviceCategory,
    pub rtt_ms: Option<f64>,
    pub open_ports: Vec<u16>,
    pub services: Vec<String>,
    pub sources: Vec<String>,
}

impl HostObservation {
    pub fn new(ip: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            ip: Some(ip.into()),
            ipv6: None,
            mac: None,
            hostname: None,
            vendor: None,
            category: DeviceCategory::Unknown,
            rtt_ms: None,
            open_ports: Vec::new(),
            services: Vec::new(),
            sources: vec![source.into()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub session_id: String,
    pub interface: String,
    pub cidr: String,
    pub gateway: Option<String>,
    pub started_at: Timestamp,
    pub finished_at: Timestamp,
    pub methods_used: Vec<ScanMethod>,
    pub privileged: bool,
    pub hosts: Vec<HostObservation>,
    pub new_devices: u32,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSession {
    pub id: String,
    pub interface: String,
    pub cidr: String,
    pub methods: Vec<ScanMethod>,
    pub started_at: Timestamp,
    pub finished_at: Option<Timestamp>,
    pub status: String,
    pub hosts_found: u32,
    pub error: Option<String>,
    pub privileged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GatewayKind {
    OpenWrt,
    MikroTik,
    UniFi,
    PfSense,
    OpnSense,
    Linux,
}

impl GatewayKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenWrt => "openwrt",
            Self::MikroTik => "mikrotik",
            Self::UniFi => "unifi",
            Self::PfSense => "pfsense",
            Self::OpnSense => "opnsense",
            Self::Linux => "linux",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::OpenWrt => 22,
            Self::MikroTik => 8729,
            Self::UniFi => 443,
            Self::PfSense | Self::OpnSense => 443,
            Self::Linux => 0,
        }
    }
}

impl fmt::Display for GatewayKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for GatewayKind {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "openwrt" => Self::OpenWrt,
            "mikrotik" | "routeros" => Self::MikroTik,
            "unifi" | "ubiquiti" => Self::UniFi,
            "pfsense" => Self::PfSense,
            "opnsense" => Self::OpnSense,
            "linux" | "local" => Self::Linux,
            other => {
                return Err(crate::Error::Validation(format!(
                    "unknown gateway kind: {other}"
                )))
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GatewayCapabilities {
    pub discovery: bool,
    pub dhcp_leases: bool,
    pub block: bool,
    pub unblock: bool,
    pub bandwidth: bool,
    pub priority: bool,
    pub schedules: bool,
    pub traffic_stats: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub id: String,
    pub name: String,
    pub kind: GatewayKind,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub site: Option<String>,
    pub interface_hint: Option<String>,
    pub tls: bool,
    pub tls_insecure: bool,
    pub enabled: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfigInput {
    pub name: String,
    pub kind: GatewayKind,
    pub host: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub secret: Option<String>,
    pub site: Option<String>,
    pub interface_hint: Option<String>,
    pub tls: Option<bool>,
    pub tls_insecure: Option<bool>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayProbe {
    pub ok: bool,
    pub kind: GatewayKind,
    pub name: String,
    pub version: Option<String>,
    pub model: Option<String>,
    pub capabilities: GatewayCapabilities,
    pub latency_ms: u64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayClient {
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub interface: Option<String>,
    pub ssid: Option<String>,
    pub online: bool,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub rx_bps: Option<u64>,
    pub tx_bps: Option<u64>,
    pub blocked: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementResult {
    pub success: bool,
    pub verified: bool,
    pub action: String,
    pub target: String,
    pub adapter: String,
    pub detail: String,
    pub applied_at: Timestamp,
    pub rule_id: Option<String>,
}

impl EnforcementResult {
    pub fn unsupported(adapter: &str, target: &str, detail: impl Into<String>) -> Self {
        Self {
            success: false,
            verified: false,
            action: "unsupported".into(),
            target: target.into(),
            adapter: adapter.into(),
            detail: detail.into(),
            applied_at: crate::util::now_ts(),
            rule_id: None,
        }
    }

    pub fn failed(adapter: &str, target: &str, detail: impl Into<String>) -> Self {
        Self {
            success: false,
            verified: false,
            action: "failed".into(),
            target: target.into(),
            adapter: adapter.into(),
            detail: detail.into(),
            applied_at: crate::util::now_ts(),
            rule_id: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessAction {
    Block,
    Pause,
    Allow,
}

impl AccessAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Pause => "pause",
            Self::Allow => "allow",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRule {
    pub id: String,
    pub device_id: Option<String>,
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub action: AccessAction,
    pub reason: Option<String>,
    pub gateway_config_id: Option<String>,
    pub state: EnforcementState,
    pub created_by: Option<String>,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthLimit {
    pub download_kbps: Option<i64>,
    pub upload_kbps: Option<i64>,
    pub priority: Option<i32>,
    pub expires_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthRule {
    pub id: String,
    pub device_id: Option<String>,
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub download_kbps: Option<i64>,
    pub upload_kbps: Option<i64>,
    pub priority: Option<i32>,
    pub gateway_config_id: Option<String>,
    pub state: EnforcementState,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringSample {
    pub ts: Timestamp,
    pub interface: Option<String>,
    pub device_id: Option<String>,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficOverview {
    pub interface: Option<String>,
    pub sampled_at: Timestamp,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub rx_total_bytes: u64,
    pub tx_total_bytes: u64,
    pub source: String,
    pub per_device_supported: bool,
    pub per_device_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: i64,
    pub ts: Timestamp,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub outcome: String,
    pub detail: Option<String>,
    pub remote_addr: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Viewer,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Viewer => "viewer",
        }
    }
}

impl std::str::FromStr for Role {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "admin" => Self::Admin,
            "viewer" => Self::Viewer,
            other => return Err(crate::Error::Validation(format!("unknown role: {other}"))),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub role: Role,
    pub created_at: Timestamp,
    pub disabled: bool,
    #[serde(skip_serializing)]
    pub password_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSummary {
    pub id: String,
    pub username: String,
    pub role: Role,
    pub created_at: Timestamp,
    pub disabled: bool,
}

impl From<User> for UserSummary {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            username: u.username,
            role: u.role,
            created_at: u.created_at,
            disabled: u.disabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub token: String,
    pub expires_at: Timestamp,
    pub user: UserSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSummary {
    pub network: Option<NetworkInfo>,
    pub interfaces: Vec<NetworkInterface>,
    pub total_devices: u64,
    pub online_devices: u64,
    pub offline_devices: u64,
    pub blocked_devices: u64,
    pub trusted_devices: u64,
    pub unknown_devices: u64,
    pub gateway: Option<GatewayProbe>,
    pub traffic: Option<TrafficOverview>,
    pub last_scan: Option<ScanSession>,
    pub enforcement_available: bool,
    pub generated_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub version: String,
    pub hostname: String,
    pub platform: String,
    pub database: String,
    pub uptime_seconds: u64,
    pub listening: Option<String>,
    pub tls: bool,
    pub privileged: bool,
    pub gateway_configured: bool,
    pub device_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    pub scan_interval_seconds: u64,
    pub preferred_interface: Option<String>,
    pub default_scan_methods: Vec<ScanMethod>,
    pub enable_nmap: bool,
    pub enable_mdns: bool,
    pub theme: String,
    pub notifications: bool,
    pub scan_on_start: bool,
    pub auto_scan: bool,
    pub retention_days: u32,
    pub max_hosts: u32,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            scan_interval_seconds: 120,
            preferred_interface: None,
            default_scan_methods: vec![ScanMethod::Neighbor, ScanMethod::Icmp, ScanMethod::Mdns],
            enable_nmap: false,
            enable_mdns: true,
            theme: "dark".into(),
            notifications: true,
            scan_on_start: false,
            auto_scan: false,
            retention_days: 90,
            max_hosts: 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationEvent {
    pub id: String,
    pub ts: Timestamp,
    pub level: String,
    pub title: String,
    pub message: String,
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostTraffic {
    pub device_id: String,
    pub rx_bps: Option<u64>,
    pub tx_bps: Option<u64>,
    pub source: String,
}
