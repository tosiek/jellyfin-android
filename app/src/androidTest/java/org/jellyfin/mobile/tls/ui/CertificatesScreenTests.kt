package org.jellyfin.mobile.tls.ui

import android.app.Activity
import android.app.Instrumentation
import android.content.Intent
import android.net.Uri
import android.view.KeyEvent
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isFocused
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasAction
import androidx.test.platform.app.InstrumentationRegistry
import org.jellyfin.mobile.R
import org.jellyfin.mobile.tls.CertificatesScreen
import org.jellyfin.mobile.tls.ClientCertificate
import org.jellyfin.mobile.tls.Pkcs12Algorithms
import org.jellyfin.mobile.tls.TlsEndpoint
import org.jellyfin.mobile.tls.TlsManager
import org.jellyfin.mobile.tls.TlsServerConfig
import org.jellyfin.mobile.tls.hasFilePicker
import org.jellyfin.mobile.ui.utils.AppTheme
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import java.io.File
import kotlin.random.Random

/**
 * GUI tests of the certificates screen. Separate from the TLS device matrix (TlsDeviceTests), run with
 * tls-test-matrix/run-gui.sh. No server is needed, files are served by a local HTTP server or returned by a stubbed
 * document picker.
 */
class CertificatesScreenTests {
    @get:Rule
    val compose = createAndroidComposeRule<ComponentActivity>()

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val tls = TlsManager.get(context)
    private val dialogs = PromptDialogs(compose)

    // Unique endpoint per test, no configuration is shared between tests
    private val endpoint = TlsEndpoint.fromUrl("https://localhost:${Random.nextInt(20_000, 60_000)}")!!

    private lateinit var fileServer: TestFileServer

    @Before
    fun setUp() {
        fileServer = TestFileServer(::read)
        Intents.init()
    }

    @After
    fun tearDown() {
        Intents.release()
        fileServer.close()
        tls.setConfig(endpoint, TlsServerConfig())
    }

    @Test
    fun showsEndpoint() {
        launch()
        compose.onNodeWithText(string(R.string.tls_certificates_title, endpoint.display), ignoreCase = true).assertIsDisplayed()
        dialogs.waitForText(string(R.string.tls_ca_none))
        dialogs.waitForText(string(R.string.tls_client_none))
    }

    @Test
    fun importCaFromUrl() {
        launch()
        importFromUrl("ca/single.pem", client = false)
        dialogs.expect("Fixture Root CA")
        dialogs.click(string(R.string.tls_trust))

        dialogs.waitForText("CN=Fixture Root CA", substring = true)
        assertEquals(1, tls.store.getCertificates(endpoint).size)
    }

    @Test
    fun importClientCertificateFromUrl() {
        launch()
        importFromUrl("client/ec256-3des.p12", client = true)
        dialogs.enter("jellyfin")
        dialogs.expect("client-ec256")
        dialogs.click(string(R.string.tls_use))
        skipContainedCas()

        dialogs.waitForText("CN=client-ec256", substring = true)
        assertTrue(tls.getConfig(endpoint).clientCertificate is ClientCertificate.Imported)
    }

    @Test
    fun wrongPassword() {
        launch()
        importFromUrl("client/ec256-3des.p12", client = true)
        dialogs.enter("wrong")
        // Asked again, the title says why
        dialogs.expect(string(R.string.tls_password_retry, "ec256-3des.p12"))
        dialogs.click(string(android.R.string.cancel))
        assertEquals(ClientCertificate.None, tls.getConfig(endpoint).clientCertificate)
    }

    @Test
    fun unsupportedKeyType() {
        launch()
        importFromUrl("client/ed25519-3des.p12", client = true)
        dialogs.enter("jellyfin")
        expectMessage("RSA (2048 bits or more) and EC (P-256, P-384)")
    }

    @Test
    fun openSsl3DefaultEncryption() {
        launch()
        importFromUrl("client/ec256-aes.p12", client = true)
        dialogs.enter("jellyfin")
        if (Pkcs12Algorithms.supportsModernEncryption()) {
            dialogs.click(string(R.string.tls_use))
            skipContainedCas()
            dialogs.waitForText("CN=client-ec256", substring = true)
        } else {
            // Explains why and what the device supports
            expectMessage("3DES (SHA-1)")
        }
    }

    @Test
    fun importCaWithDocumentPicker() {
        // Without a file picker (TV devices) the button opens the URL dialog, importFromUrl covers it
        assumeTrue(context.hasFilePicker())
        stubDocumentPicker("ca/bundle.pem")
        launch()
        compose.onNodeWithText(string(R.string.tls_ca_import), ignoreCase = true).performScrollTo().performClick()
        dialogs.click(string(R.string.tls_trust))

        dialogs.waitForText("CN=Fixture Intermediate CA", substring = true)
        assertEquals(2, tls.store.getCertificates(endpoint).size)
    }

    @Test
    fun removeCaAndClientCertificate() {
        launch()
        importFromUrl("ca/single.pem", client = false)
        dialogs.click(string(R.string.tls_trust))
        importFromUrl("client/rsa2048-3des.p12", client = true)
        dialogs.enter("jellyfin")
        dialogs.click(string(R.string.tls_use))
        skipContainedCas()
        // The client certificate entry shows the subject once the certificate is loaded
        dialogs.waitForText("CN=client-rsa2048", substring = true)

        compose.onNodeWithText("CN=Fixture Root CA", substring = true).performScrollTo().performClick()
        dialogs.click(string(R.string.tls_remove))
        dialogs.waitForText(string(R.string.tls_ca_none))
        compose.onNodeWithText("CN=client-rsa2048", substring = true).performScrollTo().performClick()
        dialogs.click(string(R.string.tls_remove))

        dialogs.waitForText(string(R.string.tls_client_none))
        assertTrue(tls.getConfig(endpoint).isEmpty)
    }

    @Test
    fun dpadNavigation() {
        stubDocumentPicker("ca/single.pem")
        launch()
        dialogs.waitForText(string(R.string.tls_ca_none))
        val importButton = hasText(string(R.string.tls_ca_import), ignoreCase = true) and isFocused()
        var found = false
        // Key events of a remote, through the window. Search downwards first, then upwards like a user would
        for (key in listOf(KeyEvent.KEYCODE_DPAD_DOWN, KeyEvent.KEYCODE_DPAD_UP)) {
            repeat(MAX_DPAD_STEPS) {
                if (found) return@repeat
                instrumentation.sendKeyDownUpSync(key)
                compose.waitForIdle()
                found = compose.onAllNodes(importButton).fetchSemanticsNodes().isNotEmpty()
            }
        }
        assertTrue("Import button not reachable with the D-pad", found)

        instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_DPAD_CENTER)
        if (context.hasFilePicker()) {
            dialogs.expect(string(R.string.tls_trust))
        } else {
            // No file picker (TV devices): the URL dialog
            dialogs.expect(string(R.string.tls_import_url_hint))
        }
    }

    // Helpers

    private fun launch() {
        compose.setContent {
            AppTheme {
                CertificatesScreen(endpoint = endpoint, onBackPressed = {})
            }
        }
    }

    private fun importFromUrl(path: String, client: Boolean) {
        compose.onNodeWithText(string(R.string.tls_import_from_url), ignoreCase = true).performScrollTo().performClick()
        dialogs.click(string(if (client) R.string.tls_client_import else R.string.tls_ca_import))
        dialogs.enter(fileServer.url(path))
    }

    /**
     * A client .p12 with its CA: the app offers to trust that CA too, not needed here.
     */
    private fun skipContainedCas() = dialogs.click(string(R.string.tls_contained_ca_skip))

    private fun expectMessage(text: String) {
        dialogs.expect(text)
        dialogs.click(string(android.R.string.ok))
    }

    private fun stubDocumentPicker(path: String) {
        val file = File(context.cacheDir, "picked-${path.replace('/', '-')}").apply { writeBytes(read(path)) }
        intending(hasAction(Intent.ACTION_OPEN_DOCUMENT))
            .respondWith(Instrumentation.ActivityResult(Activity.RESULT_OK, Intent().setData(Uri.fromFile(file))))
    }

    private fun string(id: Int, vararg args: Any) = context.getString(id, *args)

    // Fixtures are packaged as assets of the test APK
    private fun read(path: String) = instrumentation.context.assets.open("tls/$path").use { it.readBytes() }

    private companion object {
        const val MAX_DPAD_STEPS = 15
    }
}
