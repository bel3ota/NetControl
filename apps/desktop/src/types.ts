export type DeviceCategory =
  | "smartphone"
  | "tablet"
  | "laptop"
  | "desktop"
  | "server"
  | "printer"
  | "smart_tv"
  | "streaming"
  | "router"
  | "switch"
  | "access_point"
  | "camera"
  | "speaker"
  | "game_console"
  | "wearable"
  | "iot"
  | "nas"
  | "unknown";

export type EnforcementState =
  | "none"
  | "pending"
  | "applied"
  | "failed"
  | "unsupported"
  | "expired";

export interface Device {
  id: string;
  mac: string | null;
  ip: string | null;
  ipv6: string | null;
  hostname: string | null;
  vendor: string | null;
  category: DeviceCategory;
  category_source: "auto" | "manual";
  custom_name: string | null;
  notes: string | null;
  interface: string | null;
  ssid: string | null;
  online: boolean;
  first_seen: string;
  last_seen: string;
  open_ports: number[];
  services: string[];
  sources: string[];
  is_trusted: boolean;
  is_blocked: boolean;
  blocked_until: string | null;
  block_source: string | null;
  limit_download_kbps: number | null;
  limit_upload_kbps: number | null;
  limit_expires_at: string | null;
  priority: number | null;
  enforcement: EnforcementState;
  created_at: string;
  updated_at: string;
}

export interface DeviceHistory {
  id: number;
  device_id: string;
  ts: string;
  event: string;
  detail: string | null;
  scan_id: string | null;
}

export interface AccessRule {
  id: string;
  device_id: string | null;
  mac: string | null;
  ip: string | null;
  action: "block" | "pause" | "allow";
  reason: string | null;
  gateway_config_id: string | null;
  state: EnforcementState;
  created_by: string | null;
  created_at: string;
  expires_at: string | null;
  last_error: string | null;
}

export interface BandwidthRule {
  id: string;
  device_id: string | null;
  mac: string | null;
  ip: string | null;
  download_kbps: number | null;
  upload_kbps: number | null;
  priority: number | null;
  gateway_config_id: string | null;
  state: EnforcementState;
  created_at: string;
  expires_at: string | null;
  last_error: string | null;
}

export interface DeviceDetail {
  device: Device;
  history: DeviceHistory[];
  traffic: MonitoringSample | null;
  access_rules: AccessRule[];
  bandwidth_rules: BandwidthRule[];
}

export interface Paged<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Ipv4Info {
  address: string;
  prefix: number;
  netmask: string;
  broadcast: string | null;
  cidr: string;
}

export interface NetworkInterface {
  name: string;
  kind: string;
  mac: string | null;
  is_up: boolean;
  is_loopback: boolean;
  is_default: boolean;
  ipv4: Ipv4Info[];
  ipv6: string[];
  gateway4: string | null;
  gateway6: string | null;
  dns: string[];
  ssid: string | null;
  speed_mbps: number | null;
  driver: string | null;
  usb: boolean;
}

export interface NetworkInfo {
  id: string | null;
  interface: string;
  kind: string;
  ssid: string | null;
  cidr: string;
  local_ip: string;
  gateway: string | null;
  dns: string[];
  mac: string | null;
  online: boolean;
  first_seen: string | null;
  last_seen: string | null;
}

export interface GatewayCapabilities {
  discovery: boolean;
  dhcp_leases: boolean;
  block: boolean;
  unblock: boolean;
  bandwidth: boolean;
  priority: boolean;
  schedules: boolean;
  traffic_stats: boolean;
}

export interface GatewayProbe {
  ok: boolean;
  kind: string;
  name: string;
  version: string | null;
  model: string | null;
  capabilities: GatewayCapabilities;
  latency_ms: number;
  message: string;
}

export interface GatewayConfig {
  id: string;
  name: string;
  kind: "openwrt" | "mikrotik" | "unifi" | "pfsense" | "opnsense" | "linux";
  host: string;
  port: number;
  username: string | null;
  site: string | null;
  interface_hint: string | null;
  tls: boolean;
  tls_insecure: boolean;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface GatewayView extends GatewayConfig {
  active: boolean;
  has_secret: boolean;
  capabilities: GatewayCapabilities;
}

export interface GatewayInput {
  name: string;
  kind: GatewayConfig["kind"];
  host: string;
  port?: number | null;
  username?: string | null;
  secret?: string | null;
  site?: string | null;
  interface_hint?: string | null;
  tls?: boolean;
  tls_insecure?: boolean;
  enabled?: boolean;
}

export interface TrafficOverview {
  interface: string | null;
  sampled_at: string;
  rx_bps: number;
  tx_bps: number;
  rx_total_bytes: number;
  tx_total_bytes: number;
  source: "measured" | "gateway" | "estimated" | "unavailable" | string;
  per_device_supported: boolean;
  per_device_source: string | null;
}

export interface MonitoringSample {
  ts: string;
  interface: string | null;
  device_id: string | null;
  rx_bps: number;
  tx_bps: number;
  rx_bytes: number | null;
  tx_bytes: number | null;
  source: string;
}

export interface DashboardSummary {
  network: NetworkInfo | null;
  interfaces: NetworkInterface[];
  total_devices: number;
  online_devices: number;
  offline_devices: number;
  blocked_devices: number;
  trusted_devices: number;
  unknown_devices: number;
  gateway: GatewayProbe | null;
  traffic: TrafficOverview | null;
  last_scan: ScanSession | null;
  enforcement_available: boolean;
  generated_at: string;
}

export interface ScanSession {
  id: string;
  interface: string;
  cidr: string;
  methods: string[];
  started_at: string;
  finished_at: string | null;
  status: string;
  hosts_found: number;
  error: string | null;
  privileged: boolean;
}

export interface ScanReport {
  session_id: string;
  interface: string;
  cidr: string;
  gateway: string | null;
  started_at: string;
  finished_at: string;
  methods_used: string[];
  privileged: boolean;
  hosts: Array<{
    ip: string | null;
    ipv6: string | null;
    mac: string | null;
    hostname: string | null;
    vendor: string | null;
    category: DeviceCategory;
    rtt_ms: number | null;
    open_ports: number[];
    services: string[];
    sources: string[];
  }>;
  new_devices: number;
  warnings: string[];
}

export interface ScanResult {
  report: ScanReport;
  devices: Device[];
  new_devices: number;
}

export interface EnforcementResult {
  success: boolean;
  verified: boolean;
  action: string;
  target: string;
  adapter: string;
  detail: string;
  applied_at: string;
  rule_id: string | null;
}

export interface ActionResult {
  result: EnforcementResult;
  device: Device;
}

export interface UserSummary {
  id: string;
  username: string;
  role: "admin" | "viewer";
  created_at: string;
  disabled: boolean;
}

export interface AuthSession {
  token: string;
  expires_at: string;
  user: UserSummary;
}

export interface AppSettings {
  scan_interval_seconds: number;
  preferred_interface: string | null;
  default_scan_methods: string[];
  enable_nmap: boolean;
  enable_mdns: boolean;
  theme: string;
  notifications: boolean;
  scan_on_start: boolean;
  auto_scan: boolean;
  retention_days: number;
  max_hosts: number;
}

export interface AuditLog {
  id: number;
  ts: string;
  actor: string;
  action: string;
  target: string | null;
  outcome: string;
  detail: string | null;
  remote_addr: string | null;
}

export interface SystemStatus {
  version: string;
  hostname: string;
  platform: string;
  database: string;
  uptime_seconds: number;
  listening: string | null;
  tls: boolean;
  privileged: boolean;
  gateway_configured: boolean;
  device_count: number;
}

export interface DeviceFilter {
  query?: string;
  online?: boolean;
  blocked?: boolean;
  trusted?: boolean;
  category?: DeviceCategory;
  interface?: string;
  sort?: string;
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

export interface RestrictionRequest {
  duration_seconds?: number | null;
  until?: string | null;
  reason?: string | null;
  confirm: true;
}

export interface BandwidthRequest {
  download_kbps?: number | null;
  upload_kbps?: number | null;
  priority?: number | null;
  expires_at?: string | null;
  confirm: true;
}

export interface ScanRequest {
  interface?: string | null;
  methods?: string[];
  nmap?: boolean;
  ports?: boolean;
  mdns?: boolean;
  timeout_ms?: number;
  max_hosts?: number;
  allow_public?: boolean;
  confirm: true;
}
