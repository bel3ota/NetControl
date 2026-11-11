package dev.netcontrol.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowBack
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Radar
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.netcontrol.app.data.DashboardSummary
import dev.netcontrol.app.data.ScanResult

private data class Method(val id: String, val title: String, val hint: String)

private val METHODS = listOf(
    Method("neighbor", "Neighbor / ARP cache", "Kernel ARP + NDP table"),
    Method("icmp", "ICMP echo", "Unprivileged ping sweep"),
    Method("mdns", "mDNS / DNS-SD", "Hostnames and service types"),
    Method("arp", "Active ARP", "Raw arp-scan if the service is privileged"),
    Method("tcp", "TCP liveness", "Connect probes on common ports"),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(
    dashboard: DashboardSummary?,
    running: Boolean,
    result: ScanResult?,
    onScan: (iface: String?, methods: List<String>, nmap: Boolean) -> Unit,
    onClose: () -> Unit,
) {
    val interfaces = dashboard?.interfaces?.filter { it.isUp && it.ipv4.isNotEmpty() && it.kind != "loopback" } ?: emptyList()
    var selectedIface by rememberSaveable { mutableStateOf(dashboard?.network?.iface ?: interfaces.firstOrNull()?.name) }
    var methods by remember { mutableStateOf(setOf("neighbor", "icmp", "mdns")) }
    var nmap by remember { mutableStateOf(false) }
    var authorized by remember { mutableStateOf(false) }

    Surface(color = Base, modifier = Modifier.fillMaxSize()) {
        Scaffold(
            containerColor = Base,
            topBar = {
                TopAppBar(
                    title = {
                        Column {
                            Text("Scan network", style = MaterialTheme.typography.titleMedium, color = Ink)
                            Text(
                                "Executed by the management service",
                                style = MaterialTheme.typography.labelSmall,
                                color = Faint,
                            )
                        }
                    },
                    navigationIcon = {
                        IconButton(onClick = onClose) {
                            Icon(Icons.Outlined.ArrowBack, null, tint = Ink)
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = Base),
                )
            },
        ) { padding ->
            Column(
                Modifier
                    .padding(padding)
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                NCard {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            Modifier.size(42.dp).clip(RoundedCornerShape(12.dp)).background(Mint.copy(alpha = 0.08f)),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(Icons.Outlined.Radar, null, tint = Mint)
                        }
                        Spacer(Modifier.width(11.dp))
                        Column {
                            Text("Active discovery", style = MaterialTheme.typography.titleSmall, color = Ink)
                            Text(
                                "The service merges neighbor tables, ICMP, mDNS, optional Nmap and explicit port probes.",
                                style = MaterialTheme.typography.bodySmall,
                                color = Muted,
                            )
                        }
                    }
                }

                if (result != null) {
                    NCard {
                        Column {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Outlined.CheckCircle, null, tint = Success, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Column(Modifier.weight(1f)) {
                                    Text("Scan complete", style = MaterialTheme.typography.titleSmall, color = Ink)
                                    Text(
                                        "on ${result.report.cidr} · ${result.report.methodsUsed.joinToString(", ")}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = Muted,
                                    )
                                }
                                Pill("${result.report.hosts.size} hosts", Mint)
                            }
                            Text(
                                "${result.newDevices} new device${if (result.newDevices == 1) "" else "s"} added to the inventory.",
                                style = MaterialTheme.typography.bodySmall,
                                color = Muted,
                                modifier = Modifier.padding(top = 8.dp),
                            )
                            result.report.warnings.forEach { warning ->
                                Row(Modifier.padding(top = 6.dp)) {
                                    Icon(Icons.Outlined.WarningAmber, null, tint = Amber, modifier = Modifier.size(13.dp))
                                    Spacer(Modifier.width(6.dp))
                                    Text(warning, style = MaterialTheme.typography.bodySmall, color = Amber)
                                }
                            }
                        }
                    }
                }

                Text("NETWORK INTERFACE", style = MaterialTheme.typography.labelMedium, color = Faint)
                NCard(padding = 6) {
                    Column {
                        if (interfaces.isEmpty()) {
                            Text(
                                "No active IPv4 interface reported by the service.",
                                style = MaterialTheme.typography.bodySmall,
                                color = Amber,
                                modifier = Modifier.padding(10.dp),
                            )
                        } else {
                            interfaces.forEach { iface ->
                                val selected = selectedIface == iface.name
                                Row(
                                    Modifier
                                        .fillMaxWidth()
                                        .clip(RoundedCornerShape(10.dp))
                                        .background(if (selected) Mint.copy(alpha = 0.07f) else Color.Transparent)
                                        .clickable { selectedIface = iface.name }
                                        .padding(horizontal = 10.dp, vertical = 9.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Column(Modifier.weight(1f)) {
                                        Text(
                                            iface.name,
                                            style = MaterialTheme.typography.titleSmall,
                                            color = if (selected) Mint else Ink,
                                        )
                                        Text(
                                            "${iface.ipv4.firstOrNull()?.cidr ?: "no IPv4"} · ${iface.kind}${if (iface.isDefault) " · default" else ""}",
                                            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                                            color = Faint,
                                        )
                                    }
                                    if (selected) {
                                        Pill("selected", Mint)
                                    }
                                }
                            }
                        }
                    }
                }

                Text("DISCOVERY METHODS", style = MaterialTheme.typography.labelMedium, color = Faint)
                NCard(padding = 8) {
                    Column {
                        METHODS.forEach { method ->
                            Row(
                                Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(9.dp))
                                    .clickable {
                                        methods = if (methods.contains(method.id)) methods - method.id else methods + method.id
                                    }
                                    .padding(horizontal = 6.dp, vertical = 3.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Checkbox(
                                    checked = methods.contains(method.id),
                                    onCheckedChange = {
                                        methods = if (it) methods + method.id else methods - method.id
                                    },
                                    colors = CheckboxDefaults.colors(checkedColor = Mint, uncheckedColor = LineStrong),
                                )
                                Column(Modifier.weight(1f)) {
                                    Text(method.title, style = MaterialTheme.typography.titleSmall, color = Ink)
                                    Text(method.hint, style = MaterialTheme.typography.bodySmall, color = Faint)
                                }
                            }
                        }
                        Row(
                            Modifier.fillMaxWidth().padding(horizontal = 6.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text("Nmap discovery", style = MaterialTheme.typography.titleSmall, color = Ink)
                                Text("Only if nmap is installed on the service host", style = MaterialTheme.typography.bodySmall, color = Faint)
                            }
                            Switch(
                                checked = nmap,
                                onCheckedChange = { nmap = it },
                                colors = SwitchDefaults.colors(checkedTrackColor = Mint.copy(alpha = 0.6f), checkedThumbColor = Mint),
                            )
                        }
                    }
                }

                Row(
                    Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(14.dp))
                        .background(Panel)
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("Authorized scan", style = MaterialTheme.typography.titleSmall, color = Ink)
                        Text(
                            "I am authorized to probe this network. Public address space is blocked by the scope guard.",
                            style = MaterialTheme.typography.bodySmall,
                            color = Muted,
                        )
                    }
                    Switch(
                        checked = authorized,
                        onCheckedChange = { authorized = it },
                        colors = SwitchDefaults.colors(checkedTrackColor = Mint.copy(alpha = 0.6f), checkedThumbColor = Mint),
                    )
                }

                Button(
                    onClick = { onScan(selectedIface, methods.toList(), nmap) },
                    enabled = authorized && !running && selectedIface != null,
                    modifier = Modifier.fillMaxWidth().height(50.dp),
                    shape = RoundedCornerShape(13.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Mint, contentColor = Color(0xFF04120D)),
                ) {
                    if (running) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = Color(0xFF04120D))
                        Spacer(Modifier.width(10.dp))
                        Text("Scanning…", fontWeight = FontWeight.SemiBold)
                    } else {
                        Icon(Icons.Outlined.Radar, null, modifier = Modifier.size(17.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Start scan", fontWeight = FontWeight.SemiBold)
                    }
                }

                Text(
                    "Android cannot perform raw ARP or control other devices' traffic. This screen asks an authorized NetControl service to perform the scan; enforcement likewise happens on the gateway.",
                    style = MaterialTheme.typography.bodySmall,
                    color = Faint,
                    modifier = Modifier.padding(bottom = 24.dp),
                )
            }
        }
    }
}
