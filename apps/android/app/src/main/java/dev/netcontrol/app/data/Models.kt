package dev.netcontrol.app.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class User(
    val id: String = "",
    val username: String = "",
    val role: String = "viewer",
    @SerialName("created_at") val createdAt: String = "",
    val disabled: Boolean = false,
)

@Serializable
data class AuthSession(
    val token: String = "",
    @SerialName("expires_at") val expiresAt: String = "",
    val user: User = User(),
)

@Serializable
data class NetworkInfo(
    @SerialName("interface") val iface: String = "",
    val kind: String = "",
    val ssid: String? = null,
    val cidr: String = "",
    @SerialName("local_ip") val localIp: String = "",
    val gateway: String? = null,
    val dns: List<String> = emptyList(),
    val online: Boolean = true,
)

@Serializable
data class Ipv4(
    val address: String = "",
    val cidr: String = "",
    val prefix: Int = 24,
)

@Serializable
data class InterfaceInfo(
    val name: String = "",
    val kind: String = "",
    val mac: String? = null,
    @SerialName("is_up") val isUp: Boolean = false,
    @SerialName("is_default") val isDefault: Boolean = false,
    val ipv4: List<Ipv4> = emptyList(),
    @SerialName("gateway4") val gateway4: String? = null,
    val ssid: String? = null,
)

@Serializable
data class Capabilities(
    val discovery: Boolean = false,
    @SerialName("dhcp_leases") val dhcpLeases: Boolean = false,
    val block: Boolean = false,
    val unblock: Boolean = false,
    val bandwidth: Boolean = false,
    val priority: Boolean = false,
    val schedules: Boolean = false,
    @SerialName("traffic_stats") val trafficStats: Boolean = false,
)

@Serializable
data class GatewayProbe(
    val ok: Boolean = false,
    val kind: String = "",
    val name: String = "",
    val version: String? = null,
    val model: String? = null,
    val capabilities: Capabilities = Capabilities(),
    @SerialName("latency_ms") val latencyMs: Long = 0,
    val message: String = "",
)

@Serializable
data class Traffic(
    @SerialName("interface") val iface: String? = null,
    @SerialName("sampled_at") val sampledAt: String = "",
    @SerialName("rx_bps") val rxBps: Long = 0,
    @SerialName("tx_bps") val txBps: Long = 0,
    @SerialName("rx_total_bytes") val rxTotal: Long = 0,
    @SerialName("tx_total_bytes") val txTotal: Long = 0,
    val source: String = "unavailable",
    @SerialName("per_device_supported") val perDeviceSupported: Boolean = false,
)

@Serializable
data class ScanSession(
    val id: String = "",
    @SerialName("interface") val iface: String = "",
    val cidr: String = "",
    val methods: List<String> = emptyList(),
    @SerialName("started_at") val startedAt: String = "",
    val status: String = "",
    @SerialName("hosts_found") val hostsFound: Int = 0,
)

@Serializable
data class DashboardSummary(
    val network: NetworkInfo? = null,
    val interfaces: List<InterfaceInfo> = emptyList(),
    @SerialName("total_devices") val totalDevices: Long = 0,
    @SerialName("online_devices") val onlineDevices: Long = 0,
    @SerialName("offline_devices") val offlineDevices: Long = 0,
    @SerialName("blocked_devices") val blockedDevices: Long = 0,
    @SerialName("trusted_devices") val trustedDevices: Long = 0,
    @SerialName("unknown_devices") val unknownDevices: Long = 0,
    val gateway: GatewayProbe? = null,
    val traffic: Traffic? = null,
    @SerialName("last_scan") val lastScan: ScanSession? = null,
    @SerialName("enforcement_available") val enforcementAvailable: Boolean = false,
)

@Serializable
data class Device(
    val id: String = "",
    val mac: String? = null,
    val ip: String? = null,
    val ipv6: String? = null,
    val hostname: String? = null,
    val vendor: String? = null,
    val category: String = "unknown",
    @SerialName("category_source") val categorySource: String = "auto",
    @SerialName("custom_name") val customName: String? = null,
    val notes: String? = null,
    @SerialName("interface") val iface: String? = null,
    val ssid: String? = null,
    val online: Boolean = false,
    @SerialName("first_seen") val firstSeen: String = "",
    @SerialName("last_seen") val lastSeen: String = "",
    @SerialName("open_ports") val openPorts: List<Int> = emptyList(),
    val services: List<String> = emptyList(),
    val sources: List<String> = emptyList(),
    @SerialName("is_trusted") val isTrusted: Boolean = false,
    @SerialName("is_blocked") val isBlocked: Boolean = false,
    @SerialName("blocked_until") val blockedUntil: String? = null,
    @SerialName("limit_download_kbps") val limitDownloadKbps: Long? = null,
    @SerialName("limit_upload_kbps") val limitUploadKbps: Long? = null,
    @SerialName("limit_expires_at") val limitExpiresAt: String? = null,
    val priority: Int? = null,
    val enforcement: String = "none",
) {
    val displayName: String
        get() = customName?.takeIf { it.isNotBlank() }
            ?: hostname?.takeIf { it.isNotBlank() }
            ?: ip
            ?: mac
            ?: "Unnamed device"
}

@Serializable
data class Paged<T>(
    val items: List<T> = emptyList(),
    val total: Long = 0,
    val limit: Int = 100,
    val offset: Int = 0,
)

@Serializable
data class EnforcementResult(
    val success: Boolean = false,
    val verified: Boolean = false,
    val action: String = "",
    val target: String = "",
    val adapter: String = "",
    val detail: String = "",
    @SerialName("applied_at") val appliedAt: String = "",
)

@Serializable
data class ActionResult(
    val result: EnforcementResult = EnforcementResult(),
    val device: Device = Device(),
)

@Serializable
data class DeviceHistory(
    val id: Long = 0,
    @SerialName("device_id") val deviceId: String = "",
    val ts: String = "",
    val event: String = "",
    val detail: String? = null,
)

@Serializable
data class AccessRule(
    val id: String = "",
    @SerialName("device_id") val deviceId: String? = null,
    val mac: String? = null,
    val ip: String? = null,
    val action: String = "",
    val state: String = "",
    @SerialName("created_at") val createdAt: String = "",
    @SerialName("expires_at") val expiresAt: String? = null,
    @SerialName("last_error") val lastError: String? = null,
)

@Serializable
data class BandwidthRule(
    val id: String = "",
    @SerialName("device_id") val deviceId: String? = null,
    @SerialName("download_kbps") val downloadKbps: Long? = null,
    @SerialName("upload_kbps") val uploadKbps: Long? = null,
    val state: String = "",
    @SerialName("created_at") val createdAt: String = "",
    @SerialName("last_error") val lastError: String? = null,
)

@Serializable
data class DeviceDetail(
    val device: Device = Device(),
    val history: List<DeviceHistory> = emptyList(),
    val traffic: MonitoringSample? = null,
    @SerialName("access_rules") val accessRules: List<AccessRule> = emptyList(),
    @SerialName("bandwidth_rules") val bandwidthRules: List<BandwidthRule> = emptyList(),
)

@Serializable
data class MonitoringSample(
    val ts: String = "",
    @SerialName("interface") val iface: String? = null,
    @SerialName("device_id") val deviceId: String? = null,
    @SerialName("rx_bps") val rxBps: Long = 0,
    @SerialName("tx_bps") val txBps: Long = 0,
    val source: String = "",
)

@Serializable
data class HostObservation(
    val ip: String? = null,
    val ipv6: String? = null,
    val mac: String? = null,
    val hostname: String? = null,
    val vendor: String? = null,
    val category: String = "unknown",
)

@Serializable
data class ScanReport(
    @SerialName("session_id") val sessionId: String = "",
    @SerialName("interface") val iface: String = "",
    val cidr: String = "",
    @SerialName("methods_used") val methodsUsed: List<String> = emptyList(),
    val privileged: Boolean = false,
    val hosts: List<HostObservation> = emptyList(),
    @SerialName("new_devices") val newDevices: Int = 0,
    val warnings: List<String> = emptyList(),
)

@Serializable
data class ScanResult(
    val report: ScanReport = ScanReport(),
    val devices: List<Device> = emptyList(),
    @SerialName("new_devices") val newDevices: Int = 0,
)

@Serializable
data class AppSettings(
    @SerialName("scan_interval_seconds") val scanIntervalSeconds: Long = 120,
    @SerialName("preferred_interface") val preferredInterface: String? = null,
    @SerialName("default_scan_methods") val defaultScanMethods: List<String> = emptyList(),
    @SerialName("enable_nmap") val enableNmap: Boolean = false,
    @SerialName("enable_mdns") val enableMdns: Boolean = true,
    val theme: String = "dark",
    val notifications: Boolean = true,
    @SerialName("scan_on_start") val scanOnStart: Boolean = false,
    @SerialName("auto_scan") val autoScan: Boolean = false,
    @SerialName("retention_days") val retentionDays: Int = 90,
    @SerialName("max_hosts") val maxHosts: Int = 1024,
)

@Serializable
data class GatewayView(
    val id: String = "",
    val name: String = "",
    val kind: String = "",
    val host: String = "",
    val port: Int = 0,
    @SerialName("interface_hint") val interfaceHint: String? = null,
    val active: Boolean = false,
    @SerialName("has_secret") val hasSecret: Boolean = false,
    val capabilities: Capabilities = Capabilities(),
)

@Serializable
data class AuditLog(
    val id: Long = 0,
    val ts: String = "",
    val actor: String = "",
    val action: String = "",
    val target: String? = null,
    val outcome: String = "",
    val detail: String? = null,
)

@Serializable
data class LoginRequest(val username: String, val password: String)

@Serializable
data class ScanRequest(
    @SerialName("interface") val iface: String? = null,
    val methods: List<String> = listOf("neighbor", "icmp", "mdns"),
    val nmap: Boolean = false,
    val ports: Boolean = false,
    val mdns: Boolean = true,
    @SerialName("max_hosts") val maxHosts: Int? = null,
    val confirm: Boolean = true,
)

@Serializable
data class TrustRequest(val trusted: Boolean)

@Serializable
data class RestrictionRequest(
    @SerialName("duration_seconds") val durationSeconds: Long? = null,
    val until: String? = null,
    val reason: String? = null,
    val confirm: Boolean = true,
)

@Serializable
data class BandwidthRequest(
    @SerialName("download_kbps") val downloadKbps: Long? = null,
    @SerialName("upload_kbps") val uploadKbps: Long? = null,
    val priority: Int? = null,
    @SerialName("expires_at") val expiresAt: String? = null,
    val confirm: Boolean = true,
)

@Serializable
data class DevicePatch(
    @SerialName("custom_name") val customName: String? = null,
    val category: String? = null,
    val notes: String? = null,
    @SerialName("is_trusted") val isTrusted: Boolean? = null,
)

@Serializable
data class ErrorEnvelope(val error: ErrorDetail = ErrorDetail())

@Serializable
data class ErrorDetail(val code: String = "", val message: String = "")
