package dev.netcontrol.app

import dev.netcontrol.app.data.NetControlApi
import dev.netcontrol.app.ui.formatBps
import dev.netcontrol.app.ui.formatKbps
import dev.netcontrol.app.ui.relativeTime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FormattingTest {
    @Test
    fun normalizesServerUrls() {
        assertEquals("https://host:8787/api/v1", NetControlApi.normalizeServer("host:8787"))
        assertEquals("http://10.0.2.2:8787/api/v1", NetControlApi.normalizeServer("http://10.0.2.2:8787/"))
        assertEquals("https://host/api/v1", NetControlApi.normalizeServer("https://host/api/v1"))
    }

    @Test
    fun formatsRates() {
        assertEquals("1.50 Mbps", formatBps(1_500_000))
        assertEquals("10.00 Mbps", formatKbps(10_000))
        assertEquals("Unlimited", formatKbps(null))
    }

    @Test
    fun handlesBadTimestamps() {
        assertEquals("—", relativeTime(null))
        assertEquals("—", relativeTime("not-a-time"))
        assertTrue(relativeTime(java.time.Instant.now().toString()).isNotBlank())
    }
}
