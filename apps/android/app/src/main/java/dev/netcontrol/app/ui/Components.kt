package dev.netcontrol.app.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.DesktopWindows
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.HelpOutline
import androidx.compose.material.icons.outlined.LaptopMac
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material.icons.outlined.Print
import androidx.compose.material.icons.outlined.Router
import androidx.compose.material.icons.outlined.Smartphone
import androidx.compose.material.icons.outlined.Speaker
import androidx.compose.material.icons.outlined.SportsEsports
import androidx.compose.material.icons.outlined.Storage
import androidx.compose.material.icons.outlined.TabletMac
import androidx.compose.material.icons.outlined.Tv
import androidx.compose.material.icons.outlined.Videocam
import androidx.compose.material.icons.outlined.Watch
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.netcontrol.app.data.Device
import dev.netcontrol.app.data.MonitoringSample
import java.time.Duration
import java.time.Instant

val CategoryLabels = mapOf(
    "smartphone" to "Smartphone",
    "tablet" to "Tablet",
    "laptop" to "Laptop",
    "desktop" to "Desktop",
    "server" to "Server",
    "printer" to "Printer",
    "smart_tv" to "Smart TV",
    "streaming" to "Streaming",
    "router" to "Router",
    "switch" to "Switch",
    "access_point" to "Access point",
    "camera" to "Camera",
    "speaker" to "Speaker",
    "game_console" to "Console",
    "wearable" to "Wearable",
    "iot" to "IoT",
    "nas" to "NAS",
    "unknown" to "Unknown",
)

fun categoryLabel(category: String): String = CategoryLabels[category] ?: category

@Composable
fun DeviceGlyph(category: String, tint: Color = Muted, size: Int = 20) {
    val icon = when (category) {
        "smartphone" -> Icons.Outlined.Smartphone
        "tablet" -> Icons.Outlined.TabletMac
        "laptop" -> Icons.Outlined.LaptopMac
        "desktop" -> Icons.Outlined.DesktopWindows
        "server" -> Icons.Outlined.Dns
        "printer" -> Icons.Outlined.Print
        "smart_tv" -> Icons.Outlined.Tv
        "streaming" -> Icons.Outlined.Tv
        "router" -> Icons.Outlined.Router
        "switch" -> Icons.Outlined.Devices
        "access_point" -> Icons.Outlined.Wifi
        "camera" -> Icons.Outlined.Videocam
        "speaker" -> Icons.Outlined.Speaker
        "game_console" -> Icons.Outlined.SportsEsports
        "wearable" -> Icons.Outlined.Watch
        "iot" -> Icons.Outlined.Memory
        "nas" -> Icons.Outlined.Storage
        else -> Icons.Outlined.HelpOutline
    }
    Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(size.dp))
}

@Composable
fun NCard(
    modifier: Modifier = Modifier,
    padding: Int = 16,
    content: @Composable () -> Unit,
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = Panel,
        shape = RoundedCornerShape(18.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, Line),
    ) {
        Column(Modifier.padding(padding.dp)) { content() }
    }
}

@Composable
fun SectionHeader(title: String, trailing: String? = null) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            title.uppercase(),
            style = MaterialTheme.typography.labelMedium,
            color = Faint,
        )
        trailing?.let {
            Text(it, style = MaterialTheme.typography.labelSmall, color = Faint)
        }
    }
}

@Composable
fun Pill(
    text: String,
    color: Color = Muted,
    background: Color = Panel2,
    border: Color = Line,
) {
    Box(
        Modifier
            .clip(CircleShape)
            .background(background)
            .border(1.dp, border, CircleShape)
            .padding(horizontal = 9.dp, vertical = 4.dp),
    ) {
        Text(
            text,
            style = MaterialTheme.typography.labelSmall,
            color = color,
            maxLines = 1,
        )
    }
}

@Composable
fun AccessPill(device: Device) {
    when {
        device.isBlocked -> Pill("blocked", Rose, Rose.copy(alpha = 0.10f), Rose.copy(alpha = 0.28f))
        device.isTrusted -> Pill("trusted", Success, Success.copy(alpha = 0.10f), Success.copy(alpha = 0.26f))
        else -> Pill("allowed", Muted)
    }
}

@Composable
fun EnforcementPill(state: String) {
    when (state) {
        "applied" -> Pill("enforced", Success, Success.copy(alpha = 0.10f), Success.copy(alpha = 0.28f))
        "failed" -> Pill("failed", Rose, Rose.copy(alpha = 0.10f), Rose.copy(alpha = 0.28f))
        "unsupported" -> Pill("unsupported", Amber, Amber.copy(alpha = 0.08f), Amber.copy(alpha = 0.24f))
        "pending" -> Pill("pending", Azure, Azure.copy(alpha = 0.08f), Azure.copy(alpha = 0.24f))
        "expired" -> Pill("expired", Faint)
        else -> Unit
    }
}

@Composable
fun StatusDot(online: Boolean, size: Int = 7) {
    Box(
        Modifier
            .size(size.dp)
            .clip(CircleShape)
            .background(if (online) Success else Faint),
    )
}

@Composable
fun StatCard(label: String, value: String, hint: String, accent: Color) {
    NCard(padding = 14) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier
                        .size(6.dp)
                        .clip(CircleShape)
                        .background(accent),
                )
                Text(
                    "  ${label.uppercase()}",
                    style = MaterialTheme.typography.labelMedium,
                    color = Faint,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Text(
                value,
                style = MaterialTheme.typography.headlineMedium,
                color = Ink,
                modifier = Modifier.padding(top = 7.dp),
            )
            Text(
                hint,
                style = MaterialTheme.typography.bodySmall,
                color = Muted,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(top = 3.dp),
            )
        }
    }
}

@Composable
fun TrafficSpark(
    samples: List<MonitoringSample>,
    modifier: Modifier = Modifier,
) {
    val rx = samples.map { it.rxBps.toFloat() }
    val tx = samples.map { it.txBps.toFloat() }
    val max = maxOf((rx + tx).maxOrNull() ?: 1f, 1f)
    Canvas(modifier = modifier.fillMaxWidth().height(84.dp)) {
        if (samples.size < 2) return@Canvas
        fun path(values: List<Float>): Path {
            val p = Path()
            values.forEachIndexed { index, value ->
                val x = size.width * index / (values.size - 1).toFloat()
                val y = size.height - (value / max) * (size.height * 0.88f) - size.height * 0.06f
                if (index == 0) p.moveTo(x, y) else p.lineTo(x, y)
            }
            return p
        }
        drawPath(path(tx), color = Azure.copy(alpha = 0.7f), style = Stroke(width = 2.4f, cap = StrokeCap.Round))
        drawPath(path(rx), color = Mint, style = Stroke(width = 2.8f, cap = StrokeCap.Round))
        drawCircle(
            color = Mint,
            radius = 3.5f,
            center = Offset(size.width, size.height - (rx.last() / max) * (size.height * 0.88f) - size.height * 0.06f),
        )
    }
}

fun formatBps(bps: Long?): String {
    val value = (bps ?: 0).toDouble().coerceAtLeast(0.0)
    val units = listOf("bps", "Kbps", "Mbps", "Gbps")
    var scaled = value
    var index = 0
    while (scaled >= 1000 && index < units.lastIndex) {
        scaled /= 1000
        index++
    }
    return if (index == 0) "${scaled.toLong()} bps" else "%.2f %s".format(scaled, units[index])
}

fun formatKbps(kbps: Long?): String {
    if (kbps == null || kbps <= 0) return "Unlimited"
    return if (kbps >= 1_000_000) "%.2f Gbps".format(kbps / 1_000_000.0)
    else if (kbps >= 1000) "%.2f Mbps".format(kbps / 1000.0)
    else "$kbps Kbps"
}

fun relativeTime(iso: String?): String {
    if (iso.isNullOrBlank()) return "—"
    return runCatching {
        val then = Instant.parse(iso)
        val seconds = Duration.between(then, Instant.now()).seconds.coerceAtLeast(0)
        when {
            seconds < 10 -> "just now"
            seconds < 60 -> "${seconds}s ago"
            seconds < 3600 -> "${seconds / 60}m ago"
            seconds < 86400 -> "${seconds / 3600}h ago"
            else -> "${seconds / 86400}d ago"
        }
    }.getOrDefault("—")
}

fun shortDate(iso: String?): String {
    if (iso.isNullOrBlank()) return "—"
    return runCatching {
        val instant = Instant.parse(iso)
        val formatter = java.time.format.DateTimeFormatter.ofPattern("MMM d, HH:mm")
            .withZone(java.time.ZoneId.systemDefault())
        formatter.format(instant)
    }.getOrDefault(iso)
}
