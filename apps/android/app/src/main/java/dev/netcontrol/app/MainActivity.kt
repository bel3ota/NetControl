package dev.netcontrol.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.core.view.WindowCompat
import androidx.compose.foundation.background
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Dashboard
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.Radar
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FloatingActionButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.netcontrol.app.ui.Base
import dev.netcontrol.app.ui.DashboardScreen
import dev.netcontrol.app.ui.DevicesScreen
import dev.netcontrol.app.ui.AccessScreen
import dev.netcontrol.app.ui.Faint
import dev.netcontrol.app.ui.Ink
import dev.netcontrol.app.ui.Line
import dev.netcontrol.app.ui.LoginScreen
import dev.netcontrol.app.ui.Mint
import dev.netcontrol.app.ui.Muted
import dev.netcontrol.app.ui.NetControlTheme
import dev.netcontrol.app.ui.Panel
import dev.netcontrol.app.ui.ScanScreen
import dev.netcontrol.app.ui.SettingsScreen
import dev.netcontrol.app.ui.StatusDot
import kotlinx.coroutines.delay

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        WindowCompat.getInsetsController(window, window.decorView).apply {
            isAppearanceLightStatusBars = false
            isAppearanceLightNavigationBars = false
        }
        setContent {
            NetControlTheme {
                val viewModel: NetControlViewModel = viewModel()
                when {
                    viewModel.booting -> Splash()
                    viewModel.user == null -> LoginScreen(
                        busy = viewModel.busy,
                        error = viewModel.loginError,
                        onLogin = viewModel::login,
                    )
                    else -> MainShell(viewModel)
                }
            }
        }
    }
}

@Composable
private fun Splash() {
    Box(Modifier.fillMaxSize().background(Base), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Box(
                Modifier
                    .size(68.dp)
                    .clip(CircleShape)
                    .background(Panel),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Outlined.Radar, null, tint = Mint, modifier = Modifier.size(32.dp))
            }
            Spacer(Modifier.height(18.dp))
            Text(
                "NETCONTROL",
                style = MaterialTheme.typography.titleLarge,
                color = Ink,
                letterSpacing = androidx.compose.ui.unit.TextUnit.Unspecified,
            )
            Spacer(Modifier.height(14.dp))
            CircularProgressIndicator(
                modifier = Modifier.size(18.dp),
                strokeWidth = 2.dp,
                color = Mint,
            )
        }
    }
}

private enum class Tab(val label: String, val icon: ImageVector) {
    Dashboard("Dashboard", Icons.Outlined.Dashboard),
    Devices("Devices", Icons.Outlined.Devices),
    Access("Access", Icons.Outlined.Shield),
    Settings("Settings", Icons.Outlined.Settings),
}

@OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
private fun MainShell(vm: NetControlViewModel) {
    var tab by rememberSaveable { mutableStateOf(Tab.Dashboard) }
    var scanOpen by rememberSaveable { mutableStateOf(false) }
    var tick by remember { mutableIntStateOf(0) }
    val snackbar = remember { SnackbarHostState() }

    LaunchedEffect(vm.message) {
        val message = vm.message
        if (message != null) {
            snackbar.showSnackbar(message)
            vm.consumeMessage()
        }
    }
    LaunchedEffect(Unit) {
        while (true) {
            delay(6000)
            tick++
            vm.refreshDashboard(silent = true)
            if (tick % 3 == 0) {
                vm.refreshMonitoring()
            }
        }
    }
    LaunchedEffect(tab) {
        when (tab) {
            Tab.Dashboard -> if (vm.dashboard == null) vm.refreshDashboard()
            Tab.Devices -> if (vm.devices.isEmpty()) vm.refreshDevices()
            Tab.Access -> vm.refreshAccess()
            Tab.Settings -> vm.refreshSettings()
        }
    }

    if (scanOpen) {
        ScanScreen(
            dashboard = vm.dashboard,
            running = vm.scanRunning,
            result = vm.scanResult,
            onScan = { iface, methods, nmap ->
                vm.scan(iface, methods, nmap)
            },
            onClose = {
                scanOpen = false
                vm.clearScanResult()
                vm.refreshAll()
            },
        )
        return
    }

    Scaffold(
        containerColor = Base,
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            when (tab) {
                                Tab.Dashboard -> vm.dashboard?.network?.ssid
                                    ?: if (vm.dashboard?.network != null) {
                                        if (vm.dashboard?.network?.kind == "wifi") "Wi-Fi network" else "Wired network"
                                    } else "NetControl"
                                else -> tab.label
                            },
                            style = MaterialTheme.typography.titleMedium,
                            color = Ink,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            StatusDot(vm.dashboard?.network?.online == true, 5)
                            Spacer(Modifier.width(5.dp))
                            Text(
                                vm.dashboard?.network?.let { "${it.cidr} · ${it.iface}" } ?: "no active network",
                                style = MaterialTheme.typography.labelSmall,
                                color = Faint,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                },
                actions = {
                    if (vm.loading) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(17.dp).padding(end = 4.dp),
                            strokeWidth = 2.dp,
                            color = Mint,
                        )
                    }
                    IconButton(onClick = { vm.refreshAll() }) {
                        Icon(Icons.Outlined.Refresh, "Refresh", tint = Muted)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Base),
            )
        },
        bottomBar = {
            NavigationBar(containerColor = Panel, tonalElevation = 0.dp) {
                Tab.entries.forEach { entry ->
                    NavigationBarItem(
                        selected = tab == entry,
                        onClick = { tab = entry },
                        icon = { Icon(entry.icon, entry.label, modifier = Modifier.size(21.dp)) },
                        label = { Text(entry.label, style = MaterialTheme.typography.labelSmall) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = Mint,
                            selectedTextColor = Mint,
                            indicatorColor = Mint.copy(alpha = 0.10f),
                            unselectedIconColor = Faint,
                            unselectedTextColor = Faint,
                        ),
                    )
                }
            }
        },
        floatingActionButton = {
            if (tab == Tab.Dashboard || tab == Tab.Devices) {
                ExtendedFloatingActionButton(
                    onClick = { scanOpen = true },
                    containerColor = Mint,
                    contentColor = Color(0xFF04120D),
                    shape = RoundedCornerShape(16.dp),
                    elevation = FloatingActionButtonDefaults.elevation(defaultElevation = 2.dp),
                ) {
                    Icon(Icons.Outlined.Radar, null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Scan", fontWeight = FontWeight.SemiBold)
                }
            }
        },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when (tab) {
                Tab.Dashboard -> DashboardScreen(
                    dashboard = vm.dashboard,
                    trafficHistory = vm.trafficHistory,
                    devices = vm.devices,
                    onScan = { scanOpen = true },
                    onDevice = { tab = Tab.Devices },
                    onOpenSettings = { tab = Tab.Settings },
                )
                Tab.Devices -> DevicesScreen(
                    devices = vm.devices,
                    enforcementAvailable = vm.dashboard?.enforcementAvailable == true,
                    busy = vm.busy,
                    onScan = { scanOpen = true },
                    onBlock = vm::block,
                    onPause = vm::pause,
                    onUnblock = vm::unblock,
                    onLimit = vm::setLimit,
                    onClearLimit = vm::clearLimit,
                    onTrust = vm::trust,
                    onRename = vm::rename,
                )
                Tab.Access -> AccessScreen(
                    devices = vm.devices,
                    accessRules = vm.accessRules,
                    enforcementAvailable = vm.dashboard?.enforcementAvailable == true,
                    busy = vm.busy,
                    onUnblock = vm::unblock,
                    onClearLimit = vm::clearLimit,
                    onUntrust = { vm.trust(it, false) },
                )
                Tab.Settings -> SettingsScreen(
                    user = vm.user!!,
                    serverUrl = vm.serverUrl,
                    dashboard = vm.dashboard,
                    settings = vm.settings,
                    gateways = vm.gateways,
                    busy = vm.busy,
                    onSave = vm::saveSettings,
                    onTestGateway = vm::testGateway,
                    onActivateGateway = vm::activateGateway,
                    onLogout = vm::logout,
                )
            }
        }
    }
}
