package org.jellyfin.mobile.tls.ui

import android.app.Activity
import android.app.Instrumentation
import android.content.Intent
import android.net.Uri
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasAction
import androidx.test.platform.app.InstrumentationRegistry
import org.jellyfin.mobile.R
import org.jellyfin.mobile.tls.ClientCertificate
import org.jellyfin.mobile.tls.TlsEndpoint
import org.jellyfin.mobile.tls.TlsManager
import org.jellyfin.mobile.tls.TlsServerConfig
import org.jellyfin.mobile.tls.hasFilePicker
import org.jellyfin.mobile.ui.screens.connect.ServerSelection
import org.jellyfin.mobile.ui.utils.AppTheme
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import java.io.File

/**
 * GUI tests of the "Advanced" certificates section of the connect screen. The connection check runs against a local
 * HTTPS server answering like Jellyfin, see [FakeJellyfinServer].
 */
class ConnectAdvancedTests {
    @get:Rule
    val compose = createAndroidComposeRule<ComponentActivity>()

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val tls = TlsManager.get(context)
    private val dialogs = PromptDialogs(compose)

    private lateinit var fileServer: TestFileServer
    private var server: FakeJellyfinServer? = null
    private val endpoints = mutableListOf<TlsEndpoint>()

    @Volatile
    private var connectedTo: String? = null

    @Before
    fun setUp() {
        fileServer = TestFileServer(::read)
        Intents.init()
        // A connection that fails for a missing client certificate opens the system certificate chooser (Android 10+,
        // CertificateLoader.chooseSystemClient), which would cover the screen under test: answered as cancelled
        intending(hasAction("com.android.keychain.CHOOSER"))
            .respondWith(Instrumentation.ActivityResult(Activity.RESULT_CANCELED, null))
        compose.setContent {
            AppTheme {
                ServerSelection(showExternalConnectionError = false, onConnected = { connectedTo = it })
            }
        }
    }

    @After
    fun tearDown() {
        Intents.release()
        server?.close()
        fileServer.close()
        endpoints.forEach { tls.setConfig(it, TlsServerConfig()) }
    }

    @Test
    fun httpAddressExplainsHttpsOnly() {
        enterAddress("http://jellyfin.example")
        openAdvanced()
        compose.onNodeWithText(string(R.string.tls_https_only), ignoreCase = true).assertIsDisplayed()
        compose.onAllNodesWithText(string(R.string.tls_choose), ignoreCase = true)[0].assertIsNotEnabled()
    }

    @Test
    fun stageCertificatesFromFileAndUrl() {
        enterAddress("https://staging.example:8920")
        openAdvanced()

        // Checkbox unchecked: document picker (TV devices without one: the URL part only)
        if (context.hasFilePicker()) {
            setLoadFromUrl(false)
            stubDocumentPicker("ca/single.pem")
            choose(CA_ROW)
            waitForText("single.pem ${string(R.string.tls_new)}")
        }

        // Checkbox checked: URL, wrong password first
        setLoadFromUrl(true)
        choose(CLIENT_ROW)
        enterUrl("client/ec256-3des.p12")
        enterPassword("wrong")
        dialogs.expect(string(R.string.tls_password_retry, "ec256-3des.p12"))
        enterPassword("jellyfin")
        waitForText("ec256-3des.p12 ${string(R.string.tls_new)}")

        // Nothing is stored before a successful connection
        assertTrue(tls.getConfig(TlsEndpoint.fromUrl("https://staging.example:8920")!!).isEmpty)
    }

    @Test
    fun successfulConnectionKeepsCertificates() {
        val server = FakeJellyfinServer(::read, requireClientCertificate = true).also { server = it }
        val endpoint = TlsEndpoint.fromUrl(server.address)!!.also(endpoints::add)
        enterAddress(server.address)
        openAdvanced()
        setLoadFromUrl(true)
        stageFromUrl(CA_ROW, "ca/single.pem")
        stageFromUrl(CLIENT_ROW, "client/ec256-3des.p12", password = "jellyfin")

        compose.onNodeWithText(string(R.string.connect_button_text), ignoreCase = true).performScrollTo().performClick()

        compose.waitUntil(30_000) { connectedTo != null }
        assertTrue(tls.getConfig(endpoint).clientCertificate is ClientCertificate.Imported)
        assertEquals(1, tls.getConfig(endpoint).caFingerprints.size)
    }

    @Test
    fun failedConnectionRestoresAndExplains() {
        val server = FakeJellyfinServer(::read, requireClientCertificate = true).also { server = it }
        val endpoint = TlsEndpoint.fromUrl(server.address)!!.also(endpoints::add)
        enterAddress(server.address)
        openAdvanced()
        setLoadFromUrl(true)
        // Trusted server but no client certificate
        stageFromUrl(CA_ROW, "ca/single.pem")

        compose.onNodeWithText(string(R.string.connect_button_text), ignoreCase = true).performScrollTo().performClick()

        waitForText("requires a client certificate", substring = true, timeoutMs = 30_000)
        assertTrue(tls.getConfig(endpoint).isEmpty)
        // Selection kept for another try
        waitForText("single.pem ${string(R.string.tls_new)}")
        assertEquals(null, connectedTo)
    }

    // Helpers

    private fun enterAddress(address: String) {
        compose.onNode(hasSetTextAction()).performTextReplacement(address)
    }

    private fun openAdvanced() {
        compose.onNodeWithText(string(R.string.tls_advanced), substring = true, ignoreCase = true).performScrollTo().performClick()
        waitForText(string(R.string.tls_load_from_url))
    }

    private fun setLoadFromUrl(checked: Boolean) {
        val checkBox = compose.onNode(isToggleable())
        val isOn = runCatching { checkBox.assertIsOn() }.isSuccess
        if (isOn != checked) checkBox.performScrollTo().performClick()
        if (checked) checkBox.assertIsOn() else checkBox.assertIsOff()
    }

    private fun choose(row: Int) {
        compose.onAllNodesWithText(string(R.string.tls_choose), ignoreCase = true)[row].performScrollTo().performClick()
    }

    private fun stageFromUrl(row: Int, path: String, password: String? = null) {
        choose(row)
        enterUrl(path)
        password?.let(::enterPassword)
        waitForText("${path.substringAfterLast('/')} ${string(R.string.tls_new)}")
    }

    private fun enterUrl(path: String) = dialogs.enter(fileServer.url(path))

    private fun enterPassword(password: String) = dialogs.enter(password)

    private fun waitForText(text: String, substring: Boolean = false, timeoutMs: Long = 15_000) {
        compose.waitUntil(timeoutMs) {
            compose.onAllNodesWithText(text, substring = substring, ignoreCase = true).fetchSemanticsNodes().isNotEmpty()
        }
    }

    private fun stubDocumentPicker(path: String) {
        val file = File(context.cacheDir, path.substringAfterLast('/')).apply { writeBytes(read(path)) }
        intending(hasAction(Intent.ACTION_OPEN_DOCUMENT))
            .respondWith(Instrumentation.ActivityResult(Activity.RESULT_OK, Intent().setData(Uri.fromFile(file))))
    }

    private fun string(id: Int, vararg args: Any) = context.getString(id, *args)

    private fun read(path: String) = instrumentation.context.assets.open("tls/$path").use { it.readBytes() }

    private companion object {
        const val CA_ROW = 0
        const val CLIENT_ROW = 1
    }
}
