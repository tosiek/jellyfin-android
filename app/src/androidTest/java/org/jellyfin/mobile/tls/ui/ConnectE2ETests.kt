package org.jellyfin.mobile.tls.ui

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.platform.app.InstrumentationRegistry
import org.jellyfin.mobile.R
import org.jellyfin.mobile.tls.ClientCertificate
import org.jellyfin.mobile.tls.TlsEndpoint
import org.jellyfin.mobile.tls.TlsManager
import org.jellyfin.mobile.tls.TlsServerConfig
import org.jellyfin.mobile.ui.screens.connect.ServerSelection
import org.jellyfin.mobile.ui.utils.AppTheme
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * UI end-to-end test of the connect screen against a real Jellyfin server behind the mTLS proxy (tls-test-proxy).
 * Skipped unless e2eUser and e2ePassword are passed, see JellyfinProxyE2ETests for all arguments.
 */
class ConnectE2ETests {
    @get:Rule
    val compose = createAndroidComposeRule<ComponentActivity>()

    private val arguments = InstrumentationRegistry.getArguments()
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val tls = TlsManager.get(context)
    private val dialogs = PromptDialogs(compose)

    private val server = arguments.getString("e2eServer") ?: "https://10.0.2.2:8920"
    private val files = arguments.getString("e2eFiles") ?: "http://10.0.2.2:8930"
    private val p12Password = arguments.getString("e2eP12Password") ?: "jellyfin"
    private val endpoint = requireNotNull(TlsEndpoint.fromUrl(server))

    @Volatile
    private var connectedTo: String? = null

    @Before
    fun setUp() {
        assumeTrue("Pass e2eUser and e2ePassword to run the end-to-end tests", arguments.getString("e2eUser") != null)
        tls.setConfig(endpoint, TlsServerConfig())
        compose.setContent {
            AppTheme { ServerSelection(showExternalConnectionError = false, onConnected = { connectedTo = it }) }
        }
    }

    @After
    fun tearDown() {
        tls.setConfig(endpoint, TlsServerConfig())
    }

    @Test
    fun connectWithCertificatesFromUrl() {
        compose.onNode(hasSetTextAction()).performTextReplacement(server)
        compose.onNodeWithText(string(R.string.tls_advanced), substring = true, ignoreCase = true).performScrollTo().performClick()
        waitForText(string(R.string.tls_load_from_url))
        val checkBox = compose.onNode(isToggleable())
        if (runCatching { checkBox.assertIsOn() }.isFailure) checkBox.performScrollTo().performClick()

        stageFromUrl(0, "ca.pem")
        stageFromUrl(1, "client-ec.p12", p12Password)

        compose.onNodeWithText(string(R.string.connect_button_text), ignoreCase = true).performScrollTo().performClick()

        compose.waitUntil(60_000) { connectedTo != null }
        assertTrue(tls.getConfig(endpoint).clientCertificate is ClientCertificate.Imported)
        assertEquals(1, tls.getConfig(endpoint).caFingerprints.size)
    }

    private fun stageFromUrl(row: Int, file: String, password: String? = null) {
        compose.onAllNodesWithText(string(R.string.tls_choose), ignoreCase = true)[row].performScrollTo().performClick()
        dialogs.enter("$files/$file")
        password?.let(dialogs::enter)
        waitForText("$file ${string(R.string.tls_new)}")
    }

    private fun waitForText(text: String) {
        compose.waitUntil(20_000) { compose.onAllNodesWithText(text, ignoreCase = true).fetchSemanticsNodes().isNotEmpty() }
    }

    private fun string(id: Int, vararg args: Any) = context.getString(id, *args)

}
