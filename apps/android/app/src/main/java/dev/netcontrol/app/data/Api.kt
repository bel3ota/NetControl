package dev.netcontrol.app.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.URLEncoder
import java.util.concurrent.TimeUnit

class ApiException(
    override val message: String,
    val status: Int = 0,
    val code: String = "",
) : Exception(message)

class NetControlApi(private val store: SecureStore) {
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        explicitNulls = false
    }
    private val media = "application/json; charset=utf-8".toMediaType()
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(180, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

    var server: String? = null
        private set
    var token: String? = null
        private set

    init {
        store.load()?.let { (savedServer, savedToken) ->
            server = savedServer
            token = savedToken
        }
    }

    fun hasSession(): Boolean = server != null && token != null

    fun restore(): Boolean = hasSession()

    fun clearSession() {
        server = null
        token = null
        store.clear()
    }

    suspend fun login(rawServer: String, username: String, password: String): AuthSession {
        val normalized = normalizeServer(rawServer)
        val body = json.encodeToString(LoginRequest.serializer(), LoginRequest(username, password))
        val text = execute(normalized, "/auth/login", "POST", body, authenticated = false)
        val session = json.decodeFromString(AuthSession.serializer(), text)
        server = normalized
        token = session.token
        store.save(normalized, session.token)
        return session
    }

    suspend fun me(): User = get("/auth/me")

    suspend fun logout() {
        runCatching { execute(server!!, "/auth/logout", "POST", null) }
        clearSession()
    }

    suspend fun dashboard(): DashboardSummary = get("/dashboard")

    suspend fun devices(
        query: String? = null,
        online: Boolean? = null,
        blocked: Boolean? = null,
        trusted: Boolean? = null,
        limit: Int = 500,
    ): Paged<Device> {
        val params = buildList {
            query?.takeIf { it.isNotBlank() }?.let { add("query=${encode(it)}") }
            online?.let { add("online=$it") }
            blocked?.let { add("blocked=$it") }
            trusted?.let { add("trusted=$it") }
            add("limit=$limit")
            add("sort=name")
        }
        return get("/devices?${params.joinToString("&")}")
    }

    suspend fun deviceDetail(id: String): DeviceDetail = get("/devices/${enc(id)}")

    suspend fun scan(
        iface: String?,
        methods: List<String>,
        nmap: Boolean,
    ): ScanResult {
        val payload = ScanRequest(iface = iface, methods = methods, nmap = nmap, confirm = true)
        val text = postRaw("/scans", json.encodeToString(ScanRequest.serializer(), payload))
        return json.decodeFromString(ScanResult.serializer(), text)
    }

    suspend fun block(id: String, durationSeconds: Long?, reason: String?): ActionResult =
        post("/devices/${enc(id)}/block", encode(RestrictionRequest.serializer(), RestrictionRequest(
            durationSeconds = durationSeconds,
            until = null,
            reason = reason,
            confirm = true,
        )), ActionResult.serializer())

    suspend fun pause(id: String, durationSeconds: Long): ActionResult =
        post("/devices/${enc(id)}/pause", encode(RestrictionRequest.serializer(), RestrictionRequest(
            durationSeconds = durationSeconds,
            reason = "Paused from Android",
            confirm = true,
        )), ActionResult.serializer())

    suspend fun unblock(id: String): ActionResult =
        post("/devices/${enc(id)}/unblock", """{"confirm":true}""", ActionResult.serializer())

    suspend fun setLimit(id: String, downloadKbps: Long?, uploadKbps: Long?, priority: Int?): ActionResult =
        post("/devices/${enc(id)}/bandwidth", encode(BandwidthRequest.serializer(), BandwidthRequest(
            downloadKbps = downloadKbps,
            uploadKbps = uploadKbps,
            priority = priority,
            confirm = true,
        )), ActionResult.serializer())

    suspend fun clearLimit(id: String): ActionResult =
        executeAsActionResult("/devices/${enc(id)}/bandwidth", "DELETE", """{"confirm":true}""")

    suspend fun trust(id: String, trusted: Boolean): Device {
        val text = postRaw("/devices/${enc(id)}/trust", encode(TrustRequest.serializer(), TrustRequest(trusted)))
        return json.decodeFromString(Device.serializer(), text)
    }

    suspend fun updateDevice(id: String, patch: DevicePatch): Device {
        val text = execute(server!!, "/devices/${enc(id)}", "PATCH", encode(DevicePatch.serializer(), patch))
        return json.decodeFromString(Device.serializer(), text)
    }

    suspend fun accessRules(): List<AccessRule> = get("/access-rules")
    suspend fun bandwidthRules(): List<BandwidthRule> = get("/bandwidth-rules")
    suspend fun monitoringOverview(): Traffic = get("/monitoring/overview")
    suspend fun monitoringHistory(iface: String? = null, minutes: Int = 120): List<MonitoringSample> {
        val ifaceParam = iface?.let { "&interface=${enc(it)}" } ?: ""
        return get("/monitoring/history?minutes=$minutes&limit=1200$ifaceParam")
    }

    suspend fun gateways(): List<GatewayView> = get("/gateways")
    suspend fun gatewayStatus(): GatewayProbe? = get("/gateway/status")
    suspend fun testGateway(id: String): GatewayProbe =
        post("/gateways/${enc(id)}/test", "{}", GatewayProbe.serializer())
    suspend fun activateGateway(id: String) {
        execute(server!!, "/gateways/${enc(id)}/activate", "POST", "{}")
    }

    suspend fun settings(): AppSettings = get("/settings")
    suspend fun saveSettings(settings: AppSettings): AppSettings {
        val text = execute(server!!, "/settings", "PUT", encode(AppSettings.serializer(), settings))
        return json.decodeFromString(AppSettings.serializer(), text)
    }

    private suspend inline fun <reified T> get(path: String): T {
        val text = execute(server ?: throw ApiException("No server configured"), path, "GET", null)
        return json.decodeFromString(text)
    }

    private suspend fun postRaw(path: String, body: String): String =
        execute(server ?: throw ApiException("No server configured"), path, "POST", body)

    private suspend fun <T> post(
        path: String,
        body: String,
        serializer: kotlinx.serialization.DeserializationStrategy<T>,
    ): T {
        val text = execute(server ?: throw ApiException("No server configured"), path, "POST", body)
        return json.decodeFromString(serializer, text)
    }

    private fun <T> encode(
        serializer: kotlinx.serialization.SerializationStrategy<T>,
        value: T,
    ): String = json.encodeToString(serializer, value)

    private suspend fun executeAsActionResult(path: String, method: String, body: String?): ActionResult {
        val text = execute(server ?: throw ApiException("No server configured"), path, method, body)
        return json.decodeFromString(ActionResult.serializer(), text)
    }

    private suspend fun execute(
        base: String,
        path: String,
        method: String,
        body: String?,
        authenticated: Boolean = true,
    ): String = withContext(Dispatchers.IO) {
        val builder = Request.Builder()
            .url("$base$path")
            .header("Accept", "application/json")
            .header("User-Agent", "NetControl-Android/0.1.0")
        if (authenticated) {
            val current = token ?: throw ApiException("Authentication required", 401)
            builder.header("Authorization", "Bearer $current")
        }
        val requestBody = body?.toRequestBody(media)
        builder.method(method, requestBody)
        val response = client.newCall(builder.build()).execute()
        val text = response.body?.string().orEmpty()
        if (!response.isSuccessful) {
            val parsed = runCatching {
                json.decodeFromString(ErrorEnvelope.serializer(), text).error
            }.getOrNull()
            if (response.code == 401) {
                clearSession()
            }
            throw ApiException(
                parsed?.message?.takeIf { it.isNotBlank() }
                    ?: "Request failed (HTTP ${response.code})",
                response.code,
                parsed?.code.orEmpty(),
            )
        }
        text
    }

    companion object {
        fun normalizeServer(input: String): String {
            var value = input.trim().trimEnd('/')
            if (!value.startsWith("http://") && !value.startsWith("https://")) {
                value = "https://$value"
            }
            if (!value.endsWith("/api/v1")) {
                value = "$value/api/v1"
            }
            return value
        }

        private fun enc(value: String): String = URLEncoder.encode(value, "UTF-8")
        private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8")
    }
}
