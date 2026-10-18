package org.jellyfin.mobile.tls.ui

import android.app.Activity
import android.os.Build
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.webkit.WebSettings
import android.webkit.WebView
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import androidx.webkit.WebViewCompat
import kotlinx.coroutines.runBlocking
import okhttp3.Request
import org.jellyfin.mobile.MainActivity
import org.jellyfin.mobile.app.ApiClientController
import org.jellyfin.mobile.tls.CertificateImporter
import org.jellyfin.mobile.tls.TlsEndpoint
import org.jellyfin.mobile.tls.TlsManager
import org.jellyfin.mobile.tls.TlsServerConfig
import org.jellyfin.mobile.utils.Constants
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.koin.core.context.GlobalContext
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * UI end-to-end test of the web UI login in the WebView against a real Jellyfin server behind the mTLS proxy
 * (tls-test-proxy): the WebView has to present the client certificate and accept the server certificate of the
 * imported CA. Skipped unless e2eUser and e2ePassword are passed, see JellyfinProxyE2ETests for all arguments.
 */
class WebViewLoginE2ETests {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val arguments = InstrumentationRegistry.getArguments()
    private val context = instrumentation.targetContext
    private val tls = TlsManager.get(context)

    private val user = arguments.getString("e2eUser")
    private val password = arguments.getString("e2ePassword")
    private val server = arguments.getString("e2eServer") ?: "https://10.0.2.2:8920"
    private val files = arguments.getString("e2eFiles") ?: "http://10.0.2.2:8930"
    private val p12Password = arguments.getString("e2eP12Password") ?: "jellyfin"
    private val endpoint = requireNotNull(TlsEndpoint.fromUrl(server))
    private var scenario: ActivityScenario<MainActivity>? = null

    @Before
    fun setUp() {
        assumeTrue("Pass e2eUser and e2ePassword to run the end-to-end tests", user != null && password != null)
        // The app shows an "outdated WebView" screen below its minimum version (old emulator images)
        val webViewMajor = """Chrome/(\d+)\.""".toRegex().find(WebSettings.getDefaultUserAgent(context))?.groupValues?.get(1)?.toInt() ?: 0
        assumeTrue(
            "WebView $webViewMajor is older than the minimum ${Constants.MINIMUM_WEB_VIEW_VERSION} of the app",
            webViewMajor >= Constants.MINIMUM_WEB_VIEW_VERSION,
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            runCatching {
                instrumentation.uiAutomation.grantRuntimePermission(context.packageName, "android.permission.POST_NOTIFICATIONS")
            }
        }

        // Certificates of the proxy and the server, like after a successful connect
        val ca = CertificateImporter.parseCertificates(download("ca.pem")).certificates.map(tls.store::addCertificate)
        val key = CertificateImporter.parsePkcs12(download("client-ec.p12"), p12Password.toCharArray()).key
        tls.setConfig(endpoint, TlsServerConfig(ca, tls.clientKeyStore.import(key)))
        runBlocking { GlobalContext.get().get<ApiClientController>().setupServer(server) }
    }

    @After
    fun tearDown() {
        scenario?.close()
        if (user != null) tls.setConfig(endpoint, TlsServerConfig())
    }

    @Test
    fun loginInWebView() {
        scenario = ActivityScenario.launch(MainActivity::class.java)
        val chrome = WebSettings.getDefaultUserAgent(context).substringAfter("Chrome/").substringBefore(' ')
        log("WebView ${webViewVersion()}, user agent $chrome")

        // Log in with the manual login form of jellyfin-web
        val deadline = System.currentTimeMillis() + 120_000
        var state = ""
        while (state != "submitted") {
            check(System.currentTimeMillis() < deadline) { "Login form not ready, last state: $state, page: ${evaluate("location.href")}" }
            state = evaluate(loginScript()) ?: "no webview"
            if (state != "submitted") Thread.sleep(1_000)
        }
        log("login submitted on ${evaluate("location.href")}")

        // The app reads the credentials of the web UI and stores the user
        val controller = GlobalContext.get().get<ApiClientController>()
        val loginDeadline = System.currentTimeMillis() + 60_000
        var stored = runBlocking { controller.loadSavedUser() }
        while (stored == null && System.currentTimeMillis() < loginDeadline) {
            Thread.sleep(1_000)
            stored = runBlocking { controller.loadSavedUser() }
        }
        log("logged in, page ${evaluate("location.href")}")
        assertNotNull("User not stored after the web login", stored)
    }

    // Helpers

    private fun loginScript() = """
        (function() {
            var name = document.querySelector('#txtManualName');
            var pw = document.querySelector('#txtManualPassword');
            if (!name || !pw) return 'loading';
            if (name.offsetParent === null) {
                var manual = document.querySelector('.btnManual');
                if (manual) { manual.click(); return 'manual'; }
                return 'hidden';
            }
            name.value = ${JSONObject.quote(user)};
            name.dispatchEvent(new Event('input', { bubbles: true }));
            pw.value = ${JSONObject.quote(password)};
            pw.dispatchEvent(new Event('input', { bubbles: true }));
            var form = name.closest('form');
            var button = form && form.querySelector('button[type=submit]');
            if (button) { button.click(); return 'submitted'; }
            return 'no form';
        })()
    """.trimIndent()

    /**
     * Evaluate JavaScript in the WebView of the app, returns the result as string or null without WebView.
     */
    private fun evaluate(script: String): String? {
        var result: String? = null
        val done = CountDownLatch(1)
        // onActivity must not be called from the main thread, take the activity first
        var activity: Activity? = null
        scenario?.onActivity { activity = it }
        instrumentation.runOnMainSync {
            val webView = activity?.let { find(it.window.decorView) }
            if (webView == null) done.countDown()
            else webView.evaluateJavascript(script) { value ->
                result = runCatching { JSONObject("{\"v\":$value}").optString("v") }.getOrNull() ?: value
                done.countDown()
            }
        }
        done.await(10, TimeUnit.SECONDS)
        return result
    }

    private fun find(view: View): WebView? = when (view) {
        is WebView -> view
        is ViewGroup -> (0 until view.childCount).firstNotNullOfOrNull { find(view.getChildAt(it)) }
        else -> null
    }

    // Package actually loaded by the app, like the version check of WebViewFragment (an installed package may be unused,
    // e.g. com.google.android.webview on Android 6 or when another provider is selected)
    private fun webViewVersion(): String = runCatching {
        WebViewCompat.getCurrentWebViewPackage(context)?.let { "${it.packageName} ${it.versionName}" } ?: "?"
    }.getOrDefault("?")

    private fun download(file: String): ByteArray =
        tls.okHttpClient.newCall(Request.Builder().url("$files/$file").build()).execute().use { response ->
            check(response.isSuccessful) { "Unable to download $file: HTTP ${response.code}" }
            requireNotNull(response.body).bytes()
        }

    private fun log(message: String) = Log.i("TlsE2E", "API ${Build.VERSION.SDK_INT} | $message")
}
