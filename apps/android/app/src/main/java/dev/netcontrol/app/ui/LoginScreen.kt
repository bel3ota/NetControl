package dev.netcontrol.app.ui

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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowForward
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Radar
import androidx.compose.material.icons.outlined.Storage
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun LoginScreen(
    busy: Boolean,
    error: String?,
    onLogin: (server: String, username: String, password: String) -> Unit,
) {
    var server by rememberSaveable { mutableStateOf("http://10.0.2.2:8790/api/v1") }
    var username by rememberSaveable { mutableStateOf("admin") }
    var password by remember { mutableStateOf("") }

    Surface(color = Base, modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(20.dp))
            Box(
                modifier = Modifier
                    .size(86.dp)
                    .clip(CircleShape)
                    .background(
                        Brush.radialGradient(
                            listOf(Mint.copy(alpha = 0.20f), Color.Transparent),
                        ),
                    ),
                contentAlignment = Alignment.Center,
            ) {
                Box(
                    Modifier
                        .size(64.dp)
                        .clip(CircleShape)
                        .background(Panel2),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(Icons.Outlined.Radar, contentDescription = null, tint = Mint, modifier = Modifier.size(34.dp))
                }
            }
            Spacer(Modifier.height(18.dp))
            Text(
                "NETCONTROL",
                style = MaterialTheme.typography.titleLarge,
                letterSpacing = 3.sp,
                color = Ink,
            )
            Text(
                "NETWORK AUTHORITY",
                style = MaterialTheme.typography.labelSmall,
                color = Faint,
                letterSpacing = 3.sp,
                modifier = Modifier.padding(top = 3.dp),
            )
            Spacer(Modifier.height(36.dp))

            Column(Modifier.fillMaxWidth()) {
                Text("MANAGEMENT CONSOLE", style = MaterialTheme.typography.labelMedium, color = Faint)
                Text(
                    "Connect to a NetControl service",
                    style = MaterialTheme.typography.headlineSmall,
                    color = Ink,
                    modifier = Modifier.padding(top = 6.dp),
                )
                Text(
                    "Android cannot enforce access on other devices directly. This client controls an authorized NetControl service on your LAN.",
                    style = MaterialTheme.typography.bodySmall,
                    color = Muted,
                    modifier = Modifier.padding(top = 6.dp),
                )
            }

            Spacer(Modifier.height(22.dp))
            NCard(padding = 16) {
                Column {
                    LoginField(
                        value = server,
                        onValueChange = { server = it },
                        label = "Service URL",
                        leading = { Icon(Icons.Outlined.Storage, null, tint = Faint, modifier = Modifier.size(18.dp)) },
                        keyboardType = KeyboardType.Uri,
                    )
                    Spacer(Modifier.height(12.dp))
                    LoginField(
                        value = username,
                        onValueChange = { username = it },
                        label = "Username",
                    )
                    Spacer(Modifier.height(12.dp))
                    LoginField(
                        value = password,
                        onValueChange = { password = it },
                        label = "Password",
                        leading = { Icon(Icons.Outlined.Lock, null, tint = Faint, modifier = Modifier.size(18.dp)) },
                        password = true,
                    )

                    if (!server.startsWith("https://")) {
                        Row(
                            modifier = Modifier
                                .padding(top = 12.dp)
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .background(Amber.copy(alpha = 0.08f))
                                .padding(10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Icon(Icons.Outlined.WarningAmber, null, tint = Amber, modifier = Modifier.size(15.dp))
                            Spacer(Modifier.width(8.dp))
                            Text(
                                "Cleartext HTTP is for trusted local networks only. Use HTTPS for remote management.",
                                style = MaterialTheme.typography.bodySmall,
                                color = Amber,
                            )
                        }
                    }

                    error?.let {
                        Row(
                            modifier = Modifier
                                .padding(top = 12.dp)
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .background(Rose.copy(alpha = 0.08f))
                                .padding(10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(it, style = MaterialTheme.typography.bodySmall, color = Rose)
                        }
                    }

                    Button(
                        onClick = { onLogin(server, username.trim(), password) },
                        enabled = !busy && username.isNotBlank() && password.isNotBlank(),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 16.dp)
                            .height(48.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Mint, contentColor = Color(0xFF04120D)),
                    ) {
                        if (busy) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(18.dp),
                                strokeWidth = 2.dp,
                                color = Color(0xFF04120D),
                            )
                        } else {
                            Icon(Icons.Outlined.ArrowForward, null, modifier = Modifier.size(17.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Sign in", fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }

            Spacer(Modifier.height(22.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Outlined.Shield, null, tint = Mint.copy(alpha = 0.7f), modifier = Modifier.size(14.dp))
                Spacer(Modifier.width(7.dp))
                Text(
                    "encrypted credential storage · verified enforcement",
                    style = MaterialTheme.typography.labelSmall,
                    color = Faint,
                    textAlign = TextAlign.Center,
                )
            }
            Spacer(Modifier.height(18.dp))
        }
    }
}

@Composable
private fun LoginField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    leading: (@Composable () -> Unit)? = null,
    password: Boolean = false,
    keyboardType: KeyboardType = KeyboardType.Text,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label, style = MaterialTheme.typography.bodySmall) },
        leadingIcon = leading,
        singleLine = true,
        visualTransformation = if (password) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
        keyboardOptions = KeyboardOptions(keyboardType = if (password) KeyboardType.Password else keyboardType),
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = if (password) FontFamily.Default else FontFamily.Monospace),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = Mint.copy(alpha = 0.6f),
            unfocusedBorderColor = Line,
            focusedLabelColor = Mint,
            unfocusedLabelColor = Faint,
            cursorColor = Mint,
            focusedContainerColor = Panel2.copy(alpha = 0.5f),
            unfocusedContainerColor = Panel2.copy(alpha = 0.5f),
        ),
    )
}
