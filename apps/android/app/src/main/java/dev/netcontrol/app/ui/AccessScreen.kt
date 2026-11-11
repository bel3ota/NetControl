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
import androidx.compose.material.icons.outlined.GppGood
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Speed
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.netcontrol.app.data.AccessRule
import dev.netcontrol.app.data.Device

private enum class AccessTab(val label: String) {
    Blocked("Blocked"),
    Trusted("Trusted"),
    Limits("Limits"),
    Rules("Rules"),
}

@Composable
fun AccessScreen(
    devices: List<Device>,
    accessRules: List<AccessRule>,
    enforcementAvailable: Boolean,
    busy: Boolean,
    onUnblock: (Device) -> Unit,
    onClearLimit: (Device) -> Unit,
    onUntrust: (Device) -> Unit,
) {
    var tab by rememberSaveable { mutableStateOf(AccessTab.Blocked) }
    var confirmUnblock by remember { mutableStateOf<Device?>(null) }
    var confirmClear by remember { mutableStateOf<Device?>(null) }
    var confirmUntrust by remember { mutableStateOf<Device?>(null) }

    val blocked = devices.filter { it.isBlocked }
    val trusted = devices.filter { it.isTrusted }
    val limited = devices.filter { it.limitDownloadKbps != null || it.limitUploadKbps != null }

    Column(Modifier.fillMaxWidth()) {
        if (!enforcementAvailable) {
            Row(
                Modifier
                    .padding(horizontal = 16.dp, vertical = 6.dp)
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(Amber.copy(alpha = 0.07f))
                    .padding(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(Icons.Outlined.WarningAmber, null, tint = Amber, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(8.dp))
                Text(
                    "No enforcement gateway is ready. Discovery and monitoring remain available; access changes will be rejected.",
                    style = MaterialTheme.typography.bodySmall,
                    color = Amber,
                )
            }
        }
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            AccessTab.entries.forEach { entry ->
                val count = when (entry) {
                    AccessTab.Blocked -> blocked.size
                    AccessTab.Trusted -> trusted.size
                    AccessTab.Limits -> limited.size
                    AccessTab.Rules -> accessRules.size
                }
                Box(
                    Modifier
                        .clip(RoundedCornerShape(10.dp))
                        .background(if (tab == entry) Panel2 else Color.Transparent)
                        .clickable { tab = entry }
                        .padding(horizontal = 11.dp, vertical = 7.dp),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            entry.label,
                            style = MaterialTheme.typography.bodySmall,
                            color = if (tab == entry) Ink else Muted,
                        )
                        Spacer(Modifier.width(5.dp))
                        Text(
                            "$count",
                            style = MaterialTheme.typography.labelSmall,
                            color = if (tab == entry) Mint else Faint,
                        )
                    }
                }
            }
        }

        LazyColumn(
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp, 4.dp, 16.dp, 96.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            when (tab) {
                AccessTab.Blocked -> {
                    if (blocked.isEmpty()) {
                        item { AccessEmpty(Icons.Outlined.Block, "No blocked devices", "Blocks are shown only after a gateway verifies them.") }
                    } else {
                        items(blocked, key = { it.id }) { device ->
                            AccessDeviceCard(device, "Restore access", Mint) { confirmUnblock = device }
                        }
                    }
                }
                AccessTab.Trusted -> {
                    if (trusted.isEmpty()) {
                        item { AccessEmpty(Icons.Outlined.GppGood, "No trusted devices", "Trust is only a safeguard label; it does not alter gateway rules.") }
                    } else {
                        items(trusted, key = { it.id }) { device ->
                            AccessDeviceCard(device, "Remove trust", Muted) { confirmUntrust = device }
                        }
                    }
                }
                AccessTab.Limits -> {
                    if (limited.isEmpty()) {
                        item { AccessEmpty(Icons.Outlined.Speed, "No bandwidth limits", "Apply limits from a device's detail sheet.") }
                    } else {
                        items(limited, key = { it.id }) { device ->
                            AccessDeviceCard(
                                device,
                                "Clear limits",
                                Rose,
                                subtitle = "↓ ${formatKbps(device.limitDownloadKbps)}   ↑ ${formatKbps(device.limitUploadKbps)}",
                            ) { confirmClear = device }
                        }
                    }
                }
                AccessTab.Rules -> {
                    if (accessRules.isEmpty()) {
                        item { AccessEmpty(Icons.Outlined.History, "No rule history", "Access and bandwidth operations are recorded with their verification state.") }
                    } else {
                        items(accessRules.take(60), key = { it.id }) { rule ->
                            RuleRow(rule)
                        }
                    }
                }
            }
        }
    }

    confirmUnblock?.let { device ->
        AlertDialog(
            onDismissRequest = { confirmUnblock = null },
            containerColor = Panel,
            title = { Text("Restore access?") },
            text = { Text("The gateway must confirm removal of the block for ${device.displayName}.", style = MaterialTheme.typography.bodySmall) },
            confirmButton = {
                TextButton(onClick = { onUnblock(device); confirmUnblock = null }) { Text("Restore", color = Mint) }
            },
            dismissButton = { TextButton(onClick = { confirmUnblock = null }) { Text("Cancel") } },
        )
    }
    confirmClear?.let { device ->
        AlertDialog(
            onDismissRequest = { confirmClear = null },
            containerColor = Panel,
            title = { Text("Clear bandwidth limits?") },
            text = { Text("The gateway must confirm removal before the limits disappear.", style = MaterialTheme.typography.bodySmall) },
            confirmButton = {
                TextButton(onClick = { onClearLimit(device); confirmClear = null }) { Text("Clear", color = Rose) }
            },
            dismissButton = { TextButton(onClick = { confirmClear = null }) { Text("Cancel") } },
        )
    }
    confirmUntrust?.let { device ->
        AlertDialog(
            onDismissRequest = { confirmUntrust = null },
            containerColor = Panel,
            title = { Text("Remove trusted status?") },
            text = { Text("No gateway rule is changed.", style = MaterialTheme.typography.bodySmall) },
            confirmButton = {
                TextButton(onClick = { onUntrust(device); confirmUntrust = null }) { Text("Remove", color = Muted) }
            },
            dismissButton = { TextButton(onClick = { confirmUntrust = null }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun AccessDeviceCard(
    device: Device,
    action: String,
    actionColor: Color,
    subtitle: String? = null,
    onAction: () -> Unit,
) {
    NCard(padding = 13) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(38.dp).clip(RoundedCornerShape(11.dp)).background(Panel2),
                contentAlignment = Alignment.Center,
            ) { DeviceGlyph(device.category) }
            Spacer(Modifier.width(10.dp))
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
                    subtitle ?: "${device.ip ?: "-"} · ${relativeTime(device.lastSeen)}",
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    color = Faint,
                    maxLines = 1,
                )
                if (device.blockedUntil != null) {
                    Text(
                        "until ${shortDate(device.blockedUntil)}",
                        style = MaterialTheme.typography.labelSmall,
                        color = Amber,
                        modifier = Modifier.padding(top = 2.dp),
                    )
                }
            }
            TextButton(onClick = onAction) {
                Text(action, color = actionColor, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun RuleRow(rule: AccessRule) {
    NCard(padding = 12) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Pill(
                        rule.action,
                        when (rule.action) {
                            "allow" -> Success
                            "pause" -> Amber
                            else -> Rose
                        },
                    )
                    Spacer(Modifier.width(7.dp))
                    EnforcementPill(rule.state)
                }
                Text(
                    "${rule.ip ?: rule.mac ?: "unknown"} · ${shortDate(rule.createdAt)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = Faint,
                    modifier = Modifier.padding(top = 5.dp),
                )
                rule.lastError?.let {
                    Text(
                        it,
                        style = MaterialTheme.typography.bodySmall,
                        color = Rose,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.padding(top = 3.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun AccessEmpty(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    description: String,
) {
    Column(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 46.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            Modifier.size(46.dp).clip(RoundedCornerShape(14.dp)).background(Panel),
            contentAlignment = Alignment.Center,
        ) {
            Icon(icon, null, tint = Faint, modifier = Modifier.size(22.dp))
        }
        Text(title, style = MaterialTheme.typography.titleSmall, color = Ink, modifier = Modifier.padding(top = 12.dp))
        Text(
            description,
            style = MaterialTheme.typography.bodySmall,
            color = Muted,
            modifier = Modifier.padding(top = 4.dp, start = 20.dp, end = 20.dp),
        )
    }
}
