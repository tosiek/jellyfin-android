package org.jellyfin.mobile.tls

import android.os.Build
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.jellyfin.sdk.api.client.ApiClient
import org.jellyfin.sdk.api.client.extensions.itemsApi
import org.jellyfin.sdk.api.client.extensions.systemApi
import org.jellyfin.sdk.api.client.extensions.userApi
import org.jellyfin.sdk.api.client.util.AuthorizationHeaderBuilder
import org.jellyfin.sdk.api.okhttp.OkHttpFactory
import org.jellyfin.sdk.createJellyfin
import org.jellyfin.sdk.model.ClientInfo
import org.jellyfin.sdk.model.api.AuthenticateUserByName
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.net.URL
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection

/**
 * End-to-end tests against a real Jellyfin server behind an mTLS reverse proxy (tls-test-proxy: Caddy on the host,
 * reachable from the emulator as 10.0.2.2). Skipped unless credentials are passed as instrumentation arguments:
 *
 *   e2eUser, e2ePassword    Jellyfin login (required)
 *   e2eServer               default https://10.0.2.2:8920 (client certificate required)
 *   e2eFiles                default http://10.0.2.2:8930 (serves ca.pem and client-ec.p12 of the proxy)
 *   e2eP12Password          default jellyfin
 */
class JellyfinProxyE2ETests {
    private val arguments = InstrumentationRegistry.getArguments()
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val tls = TlsManager.get(context)

    private val user = arguments.getString("e2eUser")
    private val password = arguments.getString("e2ePassword")
    private val server = arguments.getString("e2eServer") ?: "https://10.0.2.2:8920"
    private val files = arguments.getString("e2eFiles") ?: "http://10.0.2.2:8930"
    private val p12Password = arguments.getString("e2eP12Password") ?: "jellyfin"
    private val endpoint = requireNotNull(TlsEndpoint.fromUrl(server))

    private val jellyfin by lazy {
        createJellyfin {
            this.context = this@JellyfinProxyE2ETests.context
            clientInfo = ClientInfo("Jellyfin TLS E2E", "1.0")
            // The app's TLS configuration, the same way the apps create their SDK instance
            val factory = OkHttpFactory(tls.okHttpClient)
            apiClientFactory = factory
            socketConnectionFactory = factory
        }
    }

    @Before
    fun setUp() {
        assumeTrue("Pass e2eUser and e2ePassword to run the end-to-end tests", user != null && password != null)
        configure(withClientCertificate = true)
    }

    @After
    fun tearDown() {
        if (user != null) tls.setConfig(endpoint, TlsServerConfig())
    }

    @Test
    fun publicSystemInfo() = runBlocking {
        val info = api().systemApi.getPublicSystemInfo().content
        log("server ${info.serverName} ${info.version}")
        assertNotNull(info.id)
    }

    @Test
    fun loginAndAuthenticatedRequests() = runBlocking {
        val api = loggedIn()
        val items = api.itemsApi.getItems(limit = 5, recursive = true).content
        log("items: ${items.totalRecordCount}")
        assertTrue(items.totalRecordCount >= 0)
    }

    @Test
    fun webSocket() = runBlocking {
        val api = loggedIn()
        // Token in the Authorization header like the SDK, newer servers reject the legacy api_key parameter
        val url = "${server.replaceFirst("https", "wss")}/socket"
        val authorization = AuthorizationHeaderBuilder.buildHeader(
            clientName = api.clientInfo.name,
            clientVersion = api.clientInfo.version,
            deviceId = api.deviceInfo.id,
            deviceName = api.deviceInfo.name,
            accessToken = api.accessToken,
        )
        val opened = CountDownLatch(1)
        var failure: Throwable? = null
        val request = Request.Builder().url(url).header("Authorization", authorization).build()
        val socket = tls.okHttpClient.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) = opened.countDown()
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                failure = t
                opened.countDown()
            }
        })
        assertTrue("WebSocket did not open", opened.await(15, TimeUnit.SECONDS))
        socket.close(1000, null)
        assertEquals(null, failure)
    }

    @Test
    fun httpsUrlConnection() {
        // The platform HTTP stack used by ExoPlayer (mobile), media artwork and crash reports
        val connection = URL("$server/System/Info/Public").openConnection() as HttpsURLConnection
        try {
            assertEquals(200, connection.responseCode)
        } finally {
            connection.disconnect()
        }
    }

    @Test
    fun missingClientCertificateIsExplained() = runBlocking {
        configure(withClientCertificate = false)
        val error = runCatching { api().systemApi.getPublicSystemInfo() }.exceptionOrNull()
        assertNotNull("Request without client certificate must fail", error)
        assertEquals(TlsProblem.ClientCertificateRequired, TlsDiagnostics.diagnose(tls, endpoint, error))
    }

    // Helpers

    private fun api(): ApiClient = jellyfin.createApi(baseUrl = server)

    private suspend fun loggedIn(): ApiClient {
        val api = api()
        val result = api.userApi.authenticateUserByName(AuthenticateUserByName(username = user, pw = password)).content
        val token = requireNotNull(result.accessToken) { "Login failed" }
        log("logged in as ${result.user?.name}")
        api.update(accessToken = token)
        return api
    }

    private fun configure(withClientCertificate: Boolean) {
        val ca = CertificateImporter.parseCertificates(download("ca.pem")).certificates.map(tls.store::addCertificate)
        val client = if (withClientCertificate) {
            val key = CertificateImporter.parsePkcs12(download("client-ec.p12"), p12Password.toCharArray()).key
            tls.clientKeyStore.import(key)
        } else {
            ClientCertificate.None
        }
        tls.setConfig(endpoint, TlsServerConfig(ca, client))
    }

    private fun download(file: String): ByteArray =
        tls.okHttpClient.newCall(Request.Builder().url("$files/$file").build()).execute().use { response ->
            check(response.isSuccessful) { "Unable to download $file: HTTP ${response.code}" }
            requireNotNull(response.body).bytes()
        }

    private fun log(message: String) = Log.i("TlsE2E", "API ${Build.VERSION.SDK_INT} | $message")
}
