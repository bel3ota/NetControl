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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Cloud
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Logout
import androidx.compose.material.icons.outlined.Router
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Storage
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.netcontrol.app.data.AppSettings
import dev.netcontrol.app.data.DashboardSummary
import dev.netcontrol.app.data.GatewayView
import dev.netcontrol.app.data.User

@Composable
fun SettingsScreen(
    user: User,
    serverUrl: String?,
    dashboard: DashboardSummary?,
    settings: AppSettings?,
    gateways: List<GatewayView>,
    busy: Boolean,
    onSave: (AppSettings) -> Unit,
    onTestGateway: (String) -> Unit,
    onActivateGateway: (String) -> Unit,
    onLogout: () -> Unit,
) {
    var autoScan by remember(settings) { mutableStateOf(settings?.autoScan ?: false) }
    var interval by remember(settings) { mutableStateOf((settings?.scanIntervalSeconds ?: 120).toString()) }
    var scanOnStart by remember(settings) { mutableStateOf(settings?.scanOnStart ?: false) }
    var enableNmap by remember(settings) { mutableStateOf(settings?.enableNmap ?: false) }

    LazyColumn(
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp, 8.dp, 16.dp, 96.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            NCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        Modifier.size(46.dp).clip(RoundedCornerShape(13.dp)).background(Violet.copy(alpha = 0.13f)),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            user.username.take(2).uppercase(),
                            style = MaterialTheme.typography.titleMedium,
                            color = Violet,
                        )
                    }
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(user.username, style = MaterialTheme.typography.titleLarge, color = Ink)
                        Text(
                            "${user.role} · authenticated session",
                            style = MaterialTheme.typography.labelSmall,
                            color = Faint,
                        )
                    }
                    Pill(if (dashboard?.enforcementAvailable == true) "enforcing" else "monitoring", if (dashboard?.enforcementAvailable == true) Success else Amber)
                }
                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Outlined.Cloud, null, tint = Faint, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(7.dp))
                    Text(
                        serverUrl ?: "-",
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        color = Muted,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }

        item {
            SectionHeader("Authorized gateways", "${gateways.size} configured")
        }
        if (gateways.isEmpty()) {
            item {
                NCard {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Outlined.WarningAmber, null, tint = Amber, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(
                            "No gateway configured. Add one through the desktop app or API to enable enforcement.",
                            style = MaterialTheme.typography.bodySmall,
                            color = Muted,
                        )
                    }
                }
            }
        } else {
            items(gateways.size) { index ->
                val gateway = gateways[index]
                NCard {
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Outlined.Router, null, tint = if (gateway.active) Mint else Muted, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(9.dp))
                            Column(Modifier.weight(1f)) {
                                Text(gateway.name, style = MaterialTheme.typography.titleSmall, color = Ink)
                                Text(
                                    "${gateway.kind} · ${gateway.host}${if (gateway.port > 0) ":${gateway.port}" else ""}",
                                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                                    color = Faint,
                                )
                            }
                            if (gateway.active) Pill("active", Mint)
                        }
                        Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            TextButton(onClick = { onTestGateway(gateway.id) }, enabled = !busy) {
                                Text("Test", color = Azure, style = MaterialTheme.typography.bodySmall)
                            }
                            if (!gateway.active) {
                                TextButton(onClick = { onActivateGateway(gateway.id) }, enabled = !busy) {
                                    Text("Activate", color = Mint, style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                    }
                }
            }
        }

        item { SectionHeader("Scanner settings") }
        item {
            NCard {
                Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Automatic scanning", style = MaterialTheme.typography.titleSmall, color = Ink)
                            Text(
                                "Periodically scan the preferred interface on the service",
                                style = MaterialTheme.typography.bodySmall,
                                color = Faint,
                            )
                        }
                        Switch(
                            checked = autoScan,
                            onCheckedChange = { autoScan = it },
                            colors = SwitchDefaults.colors(checkedTrackColor = Mint.copy(alpha = 0.6f), checkedThumbColor = Mint),
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    OutlinedTextField(
                        value = interval,
                        onValueChange = { interval = it.filter(Char::isDigit) },
                        label = { Text("Interval (seconds)", style = MaterialTheme.typography.bodySmall) },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        textStyle = MaterialTheme.typography.bodySmall,
                        colors = OutlinedTextFieldDefaults.colors(unfocusedBorderColor = Line, focusedBorderColor = Mint),
                    )
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Scan on service start", style = MaterialTheme.typography.titleSmall, color = Ink)
                            Text("One discovery pass when the backend starts", style = MaterialTheme.typography.bodySmall, color = Faint)
                        }
                        Switch(
                            checked = scanOnStart,
                            onCheckedChange = { scanOnStart = it },
                            colors = SwitchDefaults.colors(checkedTrackColor = Mint.copy(alpha = 0.6f), checkedThumbColor = Mint),
                        )
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Enable Nmap", style = MaterialTheme.typography.titleSmall, color = Ink)
                            Text("Only when nmap is installed on the service", style = MaterialTheme.typography.bodySmall, color = Faint)
                        }
                        Switch(
                            checked = enableNmap,
                            onCheckedChange = { enableNmap = it },
                            colors = SwitchDefaults.colors(checkedTrackColor = Mint.copy(alpha = 0.6f), checkedThumbColor = Mint),
                        )
                    }
                    Button(
                        onClick = {
                            settings?.let {
                                onSave(
                                    it.copy(
                                        autoScan = autoScan,
                                        scanIntervalSeconds = interval.toLongOrNull() ?: it.scanIntervalSeconds,
                                        scanOnStart = scanOnStart,
                                        enableNmap = enableNmap,
                                    ),
                                )
                            }
                        },
                        enabled = settings != null && !busy,
                        modifier = Modifier.fillMaxWidth().padding(top = 12.dp).height(44.dp),
                        shape = RoundedCornerShape(11.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Mint, contentColor = Color(0xFF04120D)),
                    ) {
                        if (busy) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = Color(0xFF04120D))
                        } else {
                            Text("Save settings", fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }
        }

        item { SectionHeader("Security") }
        item {
            NCard {
                Column(verticalArrangement = Arrangement.spacedBy(9.dp)) {
                    SecurityRow(Icons.Outlined.Key, "Session sealed with Android Keystore AES-256-GCM; only a token digest is stored server-side.")
                    SecurityRow(Icons.Outlined.Security, "Cleartext HTTP is intended only for a trusted LAN. Use HTTPS for remote management.")
                    SecurityRow(Icons.Outlined.Storage, "Enforcement always happens on an authorized gateway, never on the phone.")
                }
            }
        }

        item { SectionHeader("About") }
        item {
            NCard {
                Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("NetControl for Android", style = MaterialTheme.typography.titleSmall, color = Ink)
                            Text("Version 0.1.0 · native Compose client", style = MaterialTheme.typography.bodySmall, color = Faint)
                        }
                        Pill("APK", Muted)
                    }
                    Text(
                        "Shared engine: Rust discovery + gateway adapters. This app is a secure management client for an authorized service.",
                        style = MaterialTheme.typography.bodySmall,
                        color = Muted,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
            }
        }

        item {
            TextButton(
                onClick = onLogout,
                modifier = Modifier.fillMaxWidth().height(48.dp),
                shape = RoundedCornerShape(12.dp),
            ) {
                Icon(Icons.Outlined.Logout, null, tint = Rose, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(8.dp))
                Text("Sign out", color = Rose)
            }
        }
    }
}

@Composable
private fun SecurityRow(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String) {
    Row(verticalAlignment = Alignment.Top) {
        Icon(icon, null, tint = Mint.copy(alpha = 0.8f), modifier = Modifier.size(14.dp).padding(top = 1.dp))
        Spacer(Modifier.width(8.dp))
        Text(text, style = MaterialTheme.typography.bodySmall, color = Muted)
    }
}
