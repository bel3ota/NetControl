package dev.netcontrol.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.ChevronRight
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material.icons.outlined.GppGood
import androidx.compose.material.icons.outlined.Hub
import androidx.compose.material.icons.outlined.Radar
import androidx.compose.material.icons.outlined.Router
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Upload
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.netcontrol.app.data.DashboardSummary
import dev.netcontrol.app.data.Device
import dev.netcontrol.app.data.MonitoringSample

@Composable
fun DashboardScreen(
    dashboard: DashboardSummary?,
    trafficHistory: List<MonitoringSample>,
    devices: List<Device>,
    onScan: () -> Unit,
    onDevice: (Device) -> Unit,
    onOpenSettings: () -> Unit,
) {
    val network = dashboard?.network
    LazyColumn(
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp, 8.dp, 16.dp, 96.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(22.dp))
                    .background(
                        Brush.linearGradient(
                            listOf(Color(0xFF0C1B19), Color(0xFF0A121A), Color(0xFF0B1620)),
                        ),
                    )
                    .padding(18.dp),
            ) {
                Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        StatusDot(network?.online == true)
                        Spacer(Modifier.width(7.dp))
                        Text(
                            "CURRENT NETWORK",
                            style = MaterialTheme.typography.labelMedium,
                            color = Faint,
                        )
                        Spacer(Modifier.weight(1f))
                        Pill(
                            if (dashboard?.enforcementAvailable == true) "enforcement active" else "discovery only",
                            if (dashboard?.enforcementAvailable == true) Success else Amber,
                            if (dashboard?.enforcementAvailable == true) Success.copy(alpha = 0.08f) else Amber.copy(alpha = 0.08f),
                            if (dashboard?.enforcementAvailable == true) Success.copy(alpha = 0.24f) else Amber.copy(alpha = 0.24f),
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            if (network?.kind == "wifi") Icons.Outlined.Wifi else Icons.Outlined.Router,
                            null,
                            tint = Mint,
                            modifier = Modifier.size(24.dp),
                        )
                        Spacer(Modifier.width(10.dp))
                        Text(
                            network?.ssid ?: if (network != null) {
                                if (network.kind == "wifi") "Wi-Fi network" else "Wired network"
                            } else "No active network",
                            style = MaterialTheme.typography.headlineMedium,
                            color = Ink,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    Spacer(Modifier.height(14.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        MetaChip("SUBNET", network?.cidr ?: "-", Modifier.weight(1f))
                        MetaChip("GATEWAY", network?.gateway ?: "-", Modifier.weight(1f))
                    }
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        MetaChip("INTERFACE", network?.iface ?: "-", Modifier.weight(1f))
                        MetaChip(
                            "LAST SCAN",
                            dashboard?.lastScan?.let { relativeTime(it.startedAt) } ?: "never",
                            Modifier.weight(1f),
                        )
                    }
                    Spacer(Modifier.height(16.dp))
                    Button(
                        onClick = onScan,
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Mint, contentColor = Color(0xFF04120D)),
                        modifier = Modifier.fillMaxWidth().height(44.dp),
                    ) {
                        Icon(Icons.Outlined.Radar, null, modifier = Modifier.size(17.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Scan network", fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Box(Modifier.weight(1f)) {
                    StatCard(
                        "Devices",
                        "${dashboard?.totalDevices ?: 0}",
                        "${dashboard?.unknownDevices ?: 0} awaiting identity",
                        Azure,
                    )
                }
                Box(Modifier.weight(1f)) {
                    StatCard(
                        "Online",
                        "${dashboard?.onlineDevices ?: 0}",
                        "${dashboard?.offlineDevices ?: 0} offline retained",
                        Success,
                    )
                }
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Box(Modifier.weight(1f)) {
                    StatCard(
                        "Blocked",
                        "${dashboard?.blockedDevices ?: 0}",
                        if (dashboard?.enforcementAvailable == true) "gateway-verified" else "needs a gateway",
                        Rose,
                    )
                }
                Box(Modifier.weight(1f)) {
                    StatCard(
                        "Trusted",
                        "${dashboard?.trustedDevices ?: 0}",
                        "protected from accidents",
                        Mint,
                    )
                }
            }
        }

        item {
            NCard {
                Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            SectionHeader("Measured throughput")
                            Text(
                                dashboard?.traffic?.iface ?: "interface",
                                style = MaterialTheme.typography.titleMedium,
                                color = Ink,
                                modifier = Modifier.padding(top = 5.dp),
                            )
                        }
                        Column(horizontalAlignment = Alignment.End) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Outlined.Download, null, tint = Mint, modifier = Modifier.size(12.dp))
                                Text(
                                    " ${formatBps(dashboard?.traffic?.rxBps)}",
                                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                                    color = Mint,
                                )
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Outlined.Upload, null, tint = Azure, modifier = Modifier.size(12.dp))
                                Text(
                                    " ${formatBps(dashboard?.traffic?.txBps)}",
                                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                                    color = Azure,
                                )
                            }
                        }
                    }
                    Spacer(Modifier.height(10.dp))
                    TrafficSpark(trafficHistory)
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        StatusDot(dashboard?.traffic?.source == "measured")
                        Spacer(Modifier.width(6.dp))
                        Text(
                            "source: ${dashboard?.traffic?.source ?: "unavailable"}",
                            style = MaterialTheme.typography.labelSmall,
                            color = Faint,
                        )
                        Spacer(Modifier.weight(1f))
                        Text(
                            "↓ ${dashboard?.traffic?.rxTotal?.let { formatBytes(it) } ?: "-"}   ↑ ${dashboard?.traffic?.txTotal?.let { formatBytes(it) } ?: "-"}",
                            style = MaterialTheme.typography.labelSmall,
                            color = Faint,
                        )
                    }
                }
            }
        }

        item {
            val probe = dashboard?.gateway
            NCard {
                Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            SectionHeader("Authorized enforcement")
                            Text(
                                probe?.name ?: "Gateway",
                                style = MaterialTheme.typography.titleMedium,
                                color = Ink,
                                modifier = Modifier.padding(top = 5.dp),
                            )
                        }
                        Pill(
                            when {
                                probe?.ok == true -> "connected"
                                probe != null -> "not ready"
                                else -> "not configured"
                            },
                            when {
                                probe?.ok == true -> Success
                                probe != null -> Amber
                                else -> Faint
                            },
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    if (probe != null) {
                        Text(
                            probe.message,
                            style = MaterialTheme.typography.bodySmall,
                            color = Muted,
                            maxLines = 3,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Spacer(Modifier.height(10.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            CapabilityChip("block", probe.capabilities.block)
                            CapabilityChip("bandwidth", probe.capabilities.bandwidth)
                            CapabilityChip("leases", probe.capabilities.dhcpLeases)
                            CapabilityChip("stats", probe.capabilities.trafficStats)
                        }
                    } else {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Outlined.WarningAmber, null, tint = Amber, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(8.dp))
                            Text(
                                "Discovery and monitoring only. NetControl never claims a block without a gateway confirming it.",
                                style = MaterialTheme.typography.bodySmall,
                                color = Muted,
                            )
                        }
                    }
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .padding(top = 12.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .clickable(onClick = onOpenSettings)
                            .padding(vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(Icons.Outlined.Shield, null, tint = Mint, modifier = Modifier.size(14.dp))
                        Spacer(Modifier.width(7.dp))
                        Text(
                            "Manage gateways in Settings",
                            style = MaterialTheme.typography.bodySmall,
                            color = Mint,
                        )
                        Spacer(Modifier.weight(1f))
                        Icon(Icons.Outlined.ChevronRight, null, tint = Faint, modifier = Modifier.size(16.dp))
                    }
                }
            }
        }

        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "RECENTLY OBSERVED",
                    style = MaterialTheme.typography.labelMedium,
                    color = Faint,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    "${devices.size} shown",
                    style = MaterialTheme.typography.labelSmall,
                    color = Faint,
                )
            }
        }

        if (devices.isEmpty()) {
            item {
                NCard {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Outlined.Hub, null, tint = Faint, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(10.dp))
                        Text(
                            "No devices yet. Run an authorized scan to populate the inventory.",
                            style = MaterialTheme.typography.bodySmall,
                            color = Muted,
                        )
                    }
                }
            }
        } else {
            items(devices.take(6), key = { it.id }) { device ->
                DeviceRow(device = device, onClick = { onDevice(device) })
            }
        }

        item {
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(top = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(Icons.Outlined.GppGood, null, tint = Faint, modifier = Modifier.size(12.dp))
                Spacer(Modifier.width(7.dp))
                Text(
                    "scoped probing · encrypted credentials · verified state",
                    style = MaterialTheme.typography.labelSmall,
                    color = Faint,
                )
            }
        }
    }
}

@Composable
fun DeviceRow(device: Device, onClick: () -> Unit) {
    NCard(padding = 12, modifier = Modifier.clickable(onClick = onClick)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .size(38.dp)
                    .clip(RoundedCornerShape(11.dp))
                    .background(Panel2),
                contentAlignment = Alignment.Center,
            ) {
                DeviceGlyph(device.category)
            }
            Spacer(Modifier.width(11.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    StatusDot(device.online, 6)
                    Spacer(Modifier.width(6.dp))
                    Text(
                        device.displayName,
                        style = MaterialTheme.typography.titleSmall,
                        color = Ink,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Text(
                    "${device.ip ?: "-"} · ${device.vendor ?: "vendor unknown"}",
                    style = MaterialTheme.typography.bodySmall,
                    color = Faint,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
            Spacer(Modifier.width(8.dp))
            Column(horizontalAlignment = Alignment.End) {
                AccessPill(device)
                Text(
                    relativeTime(device.lastSeen),
                    style = MaterialTheme.typography.labelSmall,
                    color = Faint,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
        }
    }
}

@Composable
private fun MetaChip(label: String, value: String, modifier: Modifier = Modifier) {
    Column(
        modifier
            .clip(RoundedCornerShape(10.dp))
            .background(Color.White.copy(alpha = 0.03f))
            .padding(horizontal = 10.dp, vertical = 8.dp),
    ) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = Faint)
        Text(
            value,
            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            color = Ink,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(top = 3.dp),
        )
    }
}

@Composable
private fun CapabilityChip(label: String, supported: Boolean) {
    Pill(
        label,
        if (supported) Success else Faint,
        if (supported) Success.copy(alpha = 0.07f) else Panel2,
        if (supported) Success.copy(alpha = 0.20f) else Line,
    )
}

fun formatBytes(bytes: Long): String {
    val units = listOf("B", "KB", "MB", "GB", "TB")
    var value = bytes.toDouble().coerceAtLeast(0.0)
    var index = 0
    while (value >= 1000 && index < units.lastIndex) {
        value /= 1000
        index++
    }
    return if (index == 0) "${value.toLong()} B" else "%.2f %s".format(value, units[index])
}
