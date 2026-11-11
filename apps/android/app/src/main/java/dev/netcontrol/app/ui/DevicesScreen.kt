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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.PauseCircle
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Speed
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.netcontrol.app.data.Device

private enum class DeviceFilter { All, Online, Blocked, Trusted, Offline }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DevicesScreen(
    devices: List<Device>,
    enforcementAvailable: Boolean,
    busy: Boolean,
    onScan: () -> Unit,
    onBlock: (Device, Long?, String?) -> Unit,
    onPause: (Device, Long) -> Unit,
    onUnblock: (Device) -> Unit,
    onLimit: (Device, Long?, Long?, Int?) -> Unit,
    onClearLimit: (Device) -> Unit,
    onTrust: (Device, Boolean) -> Unit,
    onRename: (Device, String, String) -> Unit,
) {
    var query by rememberSaveable { mutableStateOf("") }
    var filter by rememberSaveable { mutableStateOf(DeviceFilter.All) }
    var selected by remember { mutableStateOf<Device?>(null) }
    var blockTarget by remember { mutableStateOf<Device?>(null) }
    var pauseTarget by remember { mutableStateOf<Device?>(null) }
    var limitTarget by remember { mutableStateOf<Device?>(null) }
    var renameTarget by remember { mutableStateOf<Device?>(null) }
    var confirmUnblock by remember { mutableStateOf<Device?>(null) }
    var confirmClear by remember { mutableStateOf<Device?>(null) }

    val filtered = remember(devices, query, filter) {
        devices.filter { device ->
            val matchesQuery = query.isBlank() ||
                device.displayName.contains(query, true) ||
                device.ip?.contains(query, true) == true ||
                device.mac?.contains(query, true) == true ||
                device.vendor?.contains(query, true) == true
            val matchesFilter = when (filter) {
                DeviceFilter.All -> true
                DeviceFilter.Online -> device.online
                DeviceFilter.Blocked -> device.isBlocked
                DeviceFilter.Trusted -> device.isTrusted
                DeviceFilter.Offline -> !device.online
            }
            matchesQuery && matchesFilter
        }
    }

    Column(Modifier.fillMaxWidth()) {
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
            placeholder = { Text("Search name, IP, MAC or vendor", style = MaterialTheme.typography.bodySmall) },
            leadingIcon = { Icon(Icons.Outlined.Search, null, tint = Faint, modifier = Modifier.size(18.dp)) },
            singleLine = true,
            shape = RoundedCornerShape(12.dp),
            textStyle = MaterialTheme.typography.bodyMedium,
            colors = OutlinedTextFieldDefaults.colors(
                unfocusedBorderColor = Line,
                focusedBorderColor = Mint.copy(alpha = 0.5f),
                unfocusedContainerColor = Panel,
                focusedContainerColor = Panel,
            ),
        )
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            DeviceFilter.entries.forEach { entry ->
                FilterChip(
                    selected = filter == entry,
                    onClick = { filter = entry },
                    label = {
                        Text(
                            entry.name,
                            style = MaterialTheme.typography.bodySmall,
                            maxLines = 1,
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = Mint.copy(alpha = 0.12f),
                        selectedLabelColor = Mint,
                        containerColor = Panel,
                        labelColor = Muted,
                    ),
                    border = FilterChipDefaults.filterChipBorder(
                        enabled = true,
                        selected = filter == entry,
                        borderColor = Line,
                        selectedBorderColor = Mint.copy(alpha = 0.35f),
                    ),
                )
            }
        }

        LazyColumn(
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp, 4.dp, 16.dp, 96.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            item {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "${filtered.size} devices",
                        style = MaterialTheme.typography.labelSmall,
                        color = Faint,
                        modifier = Modifier.weight(1f),
                    )
                    if (!enforcementAvailable) {
                        Icon(Icons.Outlined.WarningAmber, null, tint = Amber, modifier = Modifier.size(12.dp))
                        Text(
                            "  no gateway",
                            style = MaterialTheme.typography.labelSmall,
                            color = Amber,
                        )
                    }
                }
            }
            if (filtered.isEmpty()) {
                item {
                    NCard {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                if (devices.isEmpty()) "No devices yet. Run a scan." else "No devices match.",
                                style = MaterialTheme.typography.bodySmall,
                                color = Muted,
                                modifier = Modifier.weight(1f),
                            )
                            if (devices.isEmpty()) {
                                TextButton(onClick = onScan) { Text("Scan", color = Mint) }
                            }
                        }
                    }
                }
            } else {
                items(filtered, key = { it.id }) { device ->
                    DeviceListCard(device) { selected = device }
                }
            }
        }
    }

    selected?.let { device ->
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(
            onDismissRequest = { selected = null },
            sheetState = sheetState,
            containerColor = Panel,
        ) {
            DeviceSheet(
                device = device,
                enforcementAvailable = enforcementAvailable,
                onClose = { selected = null },
                onBlock = {
                    selected = null
                    if (device.isBlocked) confirmUnblock = device else blockTarget = device
                },
                onPause = {
                    selected = null
                    pauseTarget = device
                },
                onLimit = {
                    selected = null
                    limitTarget = device
                },
                onTrust = {
                    onTrust(device, !device.isTrusted)
                    selected = null
                },
                onRename = {
                    selected = null
                    renameTarget = device
                },
            )
        }
    }

    blockTarget?.let { device ->
        BlockDialog(
            device = device,
            enforcementAvailable = enforcementAvailable,
            busy = busy,
            onDismiss = { blockTarget = null },
            onConfirm = { duration, reason ->
                onBlock(device, duration, reason)
                blockTarget = null
            },
        )
    }
    pauseTarget?.let { device ->
        PauseDialog(
            device = device,
            enforcementAvailable = enforcementAvailable,
            busy = busy,
            onDismiss = { pauseTarget = null },
            onConfirm = { duration ->
                onPause(device, duration)
                pauseTarget = null
            },
        )
    }
    limitTarget?.let { device ->
        LimitDialog(
            device = device,
            enforcementAvailable = enforcementAvailable,
            busy = busy,
            onDismiss = { limitTarget = null },
            onConfirm = { down, up, priority ->
                onLimit(device, down, up, priority)
                limitTarget = null
            },
            onClear = {
                onClearLimit(device)
                limitTarget = null
            },
        )
    }
    renameTarget?.let { device ->
        RenameDialog(
            device = device,
            onDismiss = { renameTarget = null },
            onConfirm = { name, category ->
                onRename(device, name, category)
                renameTarget = null
            },
        )
    }
    confirmUnblock?.let { device ->
        AlertDialog(
            onDismissRequest = { confirmUnblock = null },
            title = { Text("Restore access?") },
            text = {
                Text(
                    "NetControl will ask the active gateway to remove the block for ${device.displayName} and will only update the device if the gateway confirms it.",
                    style = MaterialTheme.typography.bodySmall,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    onUnblock(device)
                    confirmUnblock = null
                }) { Text("Restore", color = Mint) }
            },
            dismissButton = { TextButton(onClick = { confirmUnblock = null }) { Text("Cancel") } },
            containerColor = Panel,
        )
    }
    confirmClear?.let { device ->
        AlertDialog(
            onDismissRequest = { confirmClear = null },
            title = { Text("Clear bandwidth limits?") },
            text = { Text("The gateway must confirm removal before the device state changes.", style = MaterialTheme.typography.bodySmall) },
            confirmButton = {
                TextButton(onClick = {
                    onClearLimit(device)
                    confirmClear = null
                }) { Text("Clear", color = Rose) }
            },
            dismissButton = { TextButton(onClick = { confirmClear = null }) { Text("Cancel") } },
            containerColor = Panel,
        )
    }
}

@Composable
private fun DeviceListCard(device: Device, onClick: () -> Unit) {
    NCard(padding = 13, modifier = Modifier.clickable(onClick = onClick)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(40.dp).clip(RoundedCornerShape(12.dp)).background(Panel2),
                contentAlignment = Alignment.Center,
            ) { DeviceGlyph(device.category) }
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
                    "${device.ip ?: "—"}  ·  ${categoryLabel(device.category)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = Faint,
                    modifier = Modifier.padding(top = 2.dp),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    device.mac ?: device.vendor ?: "unknown",
                    style = MaterialTheme.typography.labelSmall,
                    color = Faint,
                    modifier = Modifier.padding(top = 2.dp),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(Modifier.width(8.dp))
            Column(horizontalAlignment = Alignment.End) {
                AccessPill(device)
                if (device.limitDownloadKbps != null || device.limitUploadKbps != null) {
                    Text(
                        "↓${formatKbps(device.limitDownloadKbps)}",
                        style = MaterialTheme.typography.labelSmall,
                        color = Azure,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun DeviceSheet(
    device: Device,
    enforcementAvailable: Boolean,
    onClose: () -> Unit,
    onBlock: () -> Unit,
    onPause: () -> Unit,
    onLimit: () -> Unit,
    onTrust: () -> Unit,
    onRename: () -> Unit,
) {
    Column(Modifier.padding(start = 20.dp, end = 20.dp, bottom = 32.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(46.dp).clip(RoundedCornerShape(13.dp)).background(Panel2),
                contentAlignment = Alignment.Center,
            ) { DeviceGlyph(device.category, size = 24) }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(device.displayName, style = MaterialTheme.typography.titleLarge, color = Ink)
                Text(
                    "${device.ip ?: "no IP"} · ${device.iface ?: "unknown iface"}",
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    color = Faint,
                )
            }
            IconButton(onClick = onClose) {
                Icon(Icons.Outlined.Close, null, tint = Faint)
            }
        }
        Spacer(Modifier.height(14.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            AccessPill(device)
            Spacer(Modifier.width(6.dp))
            EnforcementPill(device.enforcement)
        }
        if (!enforcementAvailable) {
            Row(
                Modifier
                    .padding(top = 12.dp)
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(Amber.copy(alpha = 0.07f))
                    .padding(10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(Icons.Outlined.WarningAmber, null, tint = Amber, modifier = Modifier.size(15.dp))
                Spacer(Modifier.width(8.dp))
                Text(
                    "No authorized gateway is ready. Access changes will be reported as unsupported and will not modify the device.",
                    style = MaterialTheme.typography.bodySmall,
                    color = Amber,
                )
            }
        }
        Spacer(Modifier.height(16.dp))
        SheetInfo("MAC address", device.mac)
        SheetInfo("Vendor", device.vendor)
        SheetInfo("Category", categoryLabel(device.category))
        SheetInfo("First seen", shortDate(device.firstSeen))
        SheetInfo("Last seen", shortDate(device.lastSeen))
        SheetInfo("Download limit", formatKbps(device.limitDownloadKbps))
        SheetInfo("Upload limit", formatKbps(device.limitUploadKbps))
        SheetInfo("SSID", device.ssid)
        if (device.openPorts.isNotEmpty()) {
            SheetInfo("Open ports", device.openPorts.joinToString(", "))
        }
        if (device.services.isNotEmpty()) {
            SheetInfo("Services", device.services.take(4).joinToString(", "))
        }
        Spacer(Modifier.height(18.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = onBlock,
                modifier = Modifier.weight(1f).height(44.dp),
                shape = RoundedCornerShape(11.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (device.isBlocked) Mint else Rose.copy(alpha = 0.14f),
                    contentColor = if (device.isBlocked) Color(0xFF04120D) else Rose,
                ),
            ) {
                Icon(Icons.Outlined.Block, null, modifier = Modifier.size(15.dp))
                Spacer(Modifier.width(6.dp))
                Text(if (device.isBlocked) "Unblock" else "Block", style = MaterialTheme.typography.bodySmall)
            }
            Button(
                onClick = onPause,
                modifier = Modifier.weight(1f).height(44.dp),
                shape = RoundedCornerShape(11.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Panel2, contentColor = Ink),
            ) {
                Icon(Icons.Outlined.PauseCircle, null, modifier = Modifier.size(15.dp))
                Spacer(Modifier.width(6.dp))
                Text("Pause", style = MaterialTheme.typography.bodySmall)
            }
        }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = onLimit,
                modifier = Modifier.weight(1f).height(44.dp),
                shape = RoundedCornerShape(11.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Panel2, contentColor = Ink),
            ) {
                Icon(Icons.Outlined.Speed, null, modifier = Modifier.size(15.dp))
                Spacer(Modifier.width(6.dp))
                Text("Limits", style = MaterialTheme.typography.bodySmall)
            }
            Button(
                onClick = onTrust,
                modifier = Modifier.weight(1f).height(44.dp),
                shape = RoundedCornerShape(11.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Panel2, contentColor = Ink),
            ) {
                Icon(Icons.Outlined.Shield, null, modifier = Modifier.size(15.dp))
                Spacer(Modifier.width(6.dp))
                Text(if (device.isTrusted) "Untrust" else "Trust", style = MaterialTheme.typography.bodySmall)
            }
        }
        TextButton(onClick = onRename, modifier = Modifier.padding(top = 6.dp)) {
            Text("Edit name and category", color = Mint, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun SheetInfo(label: String, value: String?) {
    Row(Modifier.fillMaxWidth().padding(vertical = 5.dp)) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = Faint, modifier = Modifier.weight(1f))
        Text(
            value ?: "—",
            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            color = Ink,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1.2f),
        )
    }
}

@Composable
private fun BlockDialog(
    device: Device,
    enforcementAvailable: Boolean,
    busy: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (Long?, String?) -> Unit,
) {
    var duration by remember { mutableStateOf<Long?>(null) }
    var reason by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Panel,
        title = { Text("Restrict ${device.displayName}") },
        text = {
            Column {
                Text("Duration", style = MaterialTheme.typography.labelSmall, color = Faint)
                Row(horizontalArrangement = Arrangement.spacedBy(5.dp), modifier = Modifier.padding(vertical = 6.dp)) {
                    listOf(null to "Permanent", 900L to "15m", 3600L to "1h", 86400L to "24h").forEach { (value, label) ->
                        FilterChip(
                            selected = duration == value,
                            onClick = { duration = value },
                            label = { Text(label, style = MaterialTheme.typography.bodySmall) },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = Rose.copy(alpha = 0.14f),
                                selectedLabelColor = Rose,
                                containerColor = Panel2,
                                labelColor = Muted,
                            ),
                            border = FilterChipDefaults.filterChipBorder(
                                enabled = true,
                                selected = duration == value,
                                borderColor = Line,
                                selectedBorderColor = Rose.copy(alpha = 0.35f),
                            ),
                        )
                    }
                }
                OutlinedTextField(
                    value = reason,
                    onValueChange = { reason = it },
                    placeholder = { Text("Reason (optional)", style = MaterialTheme.typography.bodySmall) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    shape = RoundedCornerShape(10.dp),
                    textStyle = MaterialTheme.typography.bodySmall,
                    colors = OutlinedTextFieldDefaults.colors(unfocusedBorderColor = Line, focusedBorderColor = Mint),
                )
                if (!enforcementAvailable) {
                    Text(
                        "No enforcement gateway is ready. This will be rejected as unsupported.",
                        style = MaterialTheme.typography.bodySmall,
                        color = Amber,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(duration, reason.ifBlank { null }) }, enabled = !busy) {
                Text("Block", color = Rose)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun PauseDialog(
    device: Device,
    enforcementAvailable: Boolean,
    busy: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (Long) -> Unit,
) {
    var duration by remember { mutableStateOf(3600L) }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Panel,
        title = { Text("Pause ${device.displayName}") },
        text = {
            Column {
                Text("Temporarily pause internet access. NetControl removes the rule automatically when the timer expires.", style = MaterialTheme.typography.bodySmall, color = Muted)
                Row(horizontalArrangement = Arrangement.spacedBy(5.dp), modifier = Modifier.padding(vertical = 10.dp)) {
                    listOf(900L to "15m", 3600L to "1h", 21600L to "6h", 86400L to "24h").forEach { (value, label) ->
                        FilterChip(
                            selected = duration == value,
                            onClick = { duration = value },
                            label = { Text(label, style = MaterialTheme.typography.bodySmall) },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = Amber.copy(alpha = 0.12f),
                                selectedLabelColor = Amber,
                                containerColor = Panel2,
                                labelColor = Muted,
                            ),
                            border = FilterChipDefaults.filterChipBorder(
                                enabled = true,
                                selected = duration == value,
                                borderColor = Line,
                                selectedBorderColor = Amber.copy(alpha = 0.35f),
                            ),
                        )
                    }
                }
                if (!enforcementAvailable) {
                    Text("No gateway is ready; this will be reported as unsupported.", style = MaterialTheme.typography.bodySmall, color = Amber)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(duration) }, enabled = !busy) { Text("Pause", color = Amber) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun LimitDialog(
    device: Device,
    enforcementAvailable: Boolean,
    busy: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (Long?, Long?, Int?) -> Unit,
    onClear: () -> Unit,
) {
    var download by remember { mutableStateOf(device.limitDownloadKbps?.div(1000)?.toString() ?: "10") }
    var upload by remember { mutableStateOf(device.limitUploadKbps?.div(1000)?.toString() ?: "2") }
    var priority by remember { mutableStateOf(device.priority?.toString() ?: "") }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Panel,
        title = { Text("Bandwidth limits") },
        text = {
            Column {
                Text(device.displayName, style = MaterialTheme.typography.bodySmall, color = Faint)
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(
                    value = download,
                    onValueChange = { download = it },
                    label = { Text("Download (Mbps)", style = MaterialTheme.typography.bodySmall) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    textStyle = MaterialTheme.typography.bodySmall,
                    colors = OutlinedTextFieldDefaults.colors(unfocusedBorderColor = Line, focusedBorderColor = Mint),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = upload,
                    onValueChange = { upload = it },
                    label = { Text("Upload (Mbps)", style = MaterialTheme.typography.bodySmall) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    textStyle = MaterialTheme.typography.bodySmall,
                    colors = OutlinedTextFieldDefaults.colors(unfocusedBorderColor = Line, focusedBorderColor = Mint),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = priority,
                    onValueChange = { priority = it.filter(Char::isDigit) },
                    label = { Text("Priority 0–7 (optional)", style = MaterialTheme.typography.bodySmall) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    textStyle = MaterialTheme.typography.bodySmall,
                    colors = OutlinedTextFieldDefaults.colors(unfocusedBorderColor = Line, focusedBorderColor = Mint),
                )
                if (!enforcementAvailable) {
                    Text("No enforcement gateway is ready. This will be reported as unsupported.", style = MaterialTheme.typography.bodySmall, color = Amber, modifier = Modifier.padding(top = 8.dp))
                }
                if (device.limitDownloadKbps != null || device.limitUploadKbps != null) {
                    TextButton(onClick = onClear, enabled = !busy) {
                        Text("Clear applied limits", color = Rose)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val down = download.toDoubleOrNull()?.times(1000)?.toLong()?.takeIf { it > 0 }
                    val up = upload.toDoubleOrNull()?.times(1000)?.toLong()?.takeIf { it > 0 }
                    onConfirm(down, up, priority.toIntOrNull())
                },
                enabled = !busy,
            ) { Text("Apply", color = Mint) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun RenameDialog(
    device: Device,
    onDismiss: () -> Unit,
    onConfirm: (String, String) -> Unit,
) {
    var name by remember { mutableStateOf(device.customName ?: "") }
    var category by remember { mutableStateOf(device.category) }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Panel,
        title = { Text("Edit device") },
        text = {
            Column {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Friendly name", style = MaterialTheme.typography.bodySmall) },
                    placeholder = { Text(device.hostname ?: "e.g. Living room TV", style = MaterialTheme.typography.bodySmall) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    textStyle = MaterialTheme.typography.bodySmall,
                    colors = OutlinedTextFieldDefaults.colors(unfocusedBorderColor = Line, focusedBorderColor = Mint),
                )
                Spacer(Modifier.height(10.dp))
                Text("Category", style = MaterialTheme.typography.labelSmall, color = Faint)
                Column(Modifier.padding(top = 4.dp)) {
                    CategoryLabels.entries.chunked(3).take(3).forEach { row ->
                        Row(horizontalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.padding(vertical = 2.dp)) {
                            row.forEach { (value, label) ->
                                FilterChip(
                                    selected = category == value,
                                    onClick = { category = value },
                                    label = { Text(label, style = MaterialTheme.typography.labelSmall) },
                                    colors = FilterChipDefaults.filterChipColors(
                                        selectedContainerColor = Mint.copy(alpha = 0.12f),
                                        selectedLabelColor = Mint,
                                        containerColor = Panel2,
                                        labelColor = Muted,
                                    ),
                                    border = FilterChipDefaults.filterChipBorder(
                                        enabled = true,
                                        selected = category == value,
                                        borderColor = Line,
                                        selectedBorderColor = Mint.copy(alpha = 0.35f),
                                    ),
                                )
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(name.trim(), category) }) { Text("Save", color = Mint) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
