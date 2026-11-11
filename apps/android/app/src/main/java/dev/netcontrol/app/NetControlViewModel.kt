package dev.netcontrol.app

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.netcontrol.app.data.*
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch

class NetControlViewModel(application: Application) : AndroidViewModel(application) {
    private val api = NetControlApi(SecureStore(application))

    var booting by mutableStateOf(true)
        private set
    var user by mutableStateOf<User?>(null)
        private set
    var dashboard by mutableStateOf<DashboardSummary?>(null)
        private set
    var devices by mutableStateOf<List<Device>>(emptyList())
        private set
    var accessRules by mutableStateOf<List<AccessRule>>(emptyList())
        private set
    var bandwidthRules by mutableStateOf<List<BandwidthRule>>(emptyList())
        private set
    var trafficHistory by mutableStateOf<List<MonitoringSample>>(emptyList())
        private set
    var settings by mutableStateOf<AppSettings?>(null)
        private set
    var gateways by mutableStateOf<List<GatewayView>>(emptyList())
        private set
    var loading by mutableStateOf(false)
        private set
    var busy by mutableStateOf(false)
        private set
    var scanRunning by mutableStateOf(false)
        private set
    var scanResult by mutableStateOf<ScanResult?>(null)
        private set
    var loginError by mutableStateOf<String?>(null)
        private set
    var message by mutableStateOf<String?>(null)
        private set
    var messageIsError by mutableStateOf(false)
        private set

    val serverUrl: String?
        get() = api.server

    init {
        if (api.hasSession()) {
            viewModelScope.launch {
                try {
                    user = api.me()
                    refreshAll()
                } catch (error: Throwable) {
                    if (error is ApiException && error.status == 401) {
                        api.clearSession()
                        user = null
                    }
                } finally {
                    booting = false
                }
            }
        } else {
            booting = false
        }
    }

    fun login(server: String, username: String, password: String) {
        viewModelScope.launch {
            busy = true
            loginError = null
            try {
                val session = api.login(server, username, password)
                user = session.user
                refreshAll()
            } catch (error: Throwable) {
                loginError = friendly(error)
            } finally {
                busy = false
            }
        }
    }

    fun logout() {
        viewModelScope.launch {
            api.logout()
            user = null
            dashboard = null
            devices = emptyList()
            scanResult = null
        }
    }

    fun refreshAll() {
        viewModelScope.launch {
            loading = true
            try {
                coroutineScope {
                    launch {
                        refreshDashboardInternal()
                        refreshMonitoringInternal()
                    }
                    launch { refreshDevicesInternal() }
                    launch { refreshAccessInternal() }
                    launch { refreshSettingsInternal() }
                    launch {
                        gateways = runCatching { api.gateways() }.getOrDefault(emptyList())
                    }
                }
            } finally {
                loading = false
            }
        }
    }

    fun refreshDashboard(silent: Boolean = false) {
        viewModelScope.launch {
            if (!silent) loading = true
            try {
                refreshDashboardInternal()
            } catch (error: Throwable) {
                handle(error)
            } finally {
                if (!silent) loading = false
            }
        }
    }

    private var historyIface: String? = null

    private suspend fun refreshDashboardInternal() {
        try {
            dashboard = api.dashboard()
            val iface = dashboard?.network?.iface
            if (iface != historyIface) {
                historyIface = iface
                refreshMonitoringInternal()
            }
        } catch (error: Throwable) {
            handle(error)
        }
    }

    fun refreshDevices() {
        viewModelScope.launch {
            loading = true
            try {
                refreshDevicesInternal()
            } finally {
                loading = false
            }
        }
    }

    private suspend fun refreshDevicesInternal() {
        try {
            devices = api.devices(limit = 500).items
        } catch (error: Throwable) {
            handle(error)
        }
    }

    fun refreshAccess() {
        viewModelScope.launch {
            loading = true
            try {
                refreshAccessInternal()
            } finally {
                loading = false
            }
        }
    }

    private suspend fun refreshAccessInternal() {
        try {
            accessRules = api.accessRules()
        } catch (error: Throwable) {
            handle(error)
        }
        try {
            bandwidthRules = api.bandwidthRules()
        } catch (_: Throwable) {
        }
    }

    fun refreshMonitoring() {
        viewModelScope.launch {
            loading = true
            try {
                refreshMonitoringInternal()
            } finally {
                loading = false
            }
        }
    }

    private suspend fun refreshMonitoringInternal() {
        try {
            trafficHistory = api.monitoringHistory(dashboard?.network?.iface, 120)
        } catch (_: Throwable) {
        }
    }

    fun refreshSettings() {
        viewModelScope.launch {
            loading = true
            try {
                refreshSettingsInternal()
            } finally {
                loading = false
            }
        }
    }

    private suspend fun refreshSettingsInternal() {
        try {
            settings = api.settings()
        } catch (_: Throwable) {
        }
    }

    fun scan(iface: String?, methods: List<String>, nmap: Boolean) {
        viewModelScope.launch {
            scanRunning = true
            scanResult = null
            try {
                val result = api.scan(iface, methods, nmap)
                scanResult = result
                message = "Scan complete: ${result.report.hosts.size} hosts, ${result.newDevices} new"
                messageIsError = false
                refreshAll()
            } catch (error: Throwable) {
                handle(error)
            } finally {
                scanRunning = false
            }
        }
    }

    fun block(device: Device, durationSeconds: Long?, reason: String?) {
        act {
            val result = api.block(device.id, durationSeconds, reason)
            report(result)
        }
    }

    fun pause(device: Device, durationSeconds: Long = 3600) {
        act {
            report(api.pause(device.id, durationSeconds))
        }
    }

    fun unblock(device: Device) {
        act {
            report(api.unblock(device.id))
        }
    }

    fun setLimit(device: Device, downloadKbps: Long?, uploadKbps: Long?, priority: Int?) {
        act {
            report(api.setLimit(device.id, downloadKbps, uploadKbps, priority))
        }
    }

    fun clearLimit(device: Device) {
        act {
            report(api.clearLimit(device.id))
        }
    }

    fun trust(device: Device, trusted: Boolean) {
        act {
            api.trust(device.id, trusted)
            message = if (trusted) "Device trusted" else "Trust removed"
            messageIsError = false
            refreshDevicesInternal()
        }
    }

    fun rename(device: Device, name: String, category: String) {
        act {
            api.updateDevice(device.id, DevicePatch(customName = name.ifBlank { null }, category = category))
            message = "Device updated"
            messageIsError = false
            refreshDevicesInternal()
        }
    }

    fun saveSettings(updated: AppSettings) {
        act {
            settings = api.saveSettings(updated)
            message = "Settings saved"
            messageIsError = false
        }
    }

    fun testGateway(id: String) {
        act {
            val probe = api.testGateway(id)
            message = if (probe.ok) "${probe.name} reachable: ${probe.message}" else probe.message
            messageIsError = !probe.ok
            gateways = runCatching { api.gateways() }.getOrDefault(gateways)
        }
    }

    fun activateGateway(id: String) {
        act {
            api.activateGateway(id)
            message = "Active gateway updated"
            messageIsError = false
            refreshAll()
        }
    }

    fun consumeMessage() {
        message = null
    }

    fun clearScanResult() {
        scanResult = null
    }

    private fun act(block: suspend () -> Unit) {
        viewModelScope.launch {
            busy = true
            try {
                block()
            } catch (error: Throwable) {
                handle(error)
            } finally {
                busy = false
            }
        }
    }

    private suspend fun report(result: ActionResult) {
        message = if (result.result.verified) {
            "Verified: ${result.result.detail}"
        } else {
            "Not enforced: ${result.result.detail}"
        }
        messageIsError = !result.result.verified
        refreshDashboardInternal()
        refreshDevicesInternal()
        refreshAccessInternal()
    }

    private fun handle(error: Throwable) {
        if (error is ApiException && error.status == 401) {
            api.clearSession()
            user = null
            return
        }
        message = friendly(error)
        messageIsError = true
    }

    private fun friendly(error: Throwable): String = when (error) {
        is ApiException -> error.message
        else -> error.message ?: "Unexpected error"
    }
}
