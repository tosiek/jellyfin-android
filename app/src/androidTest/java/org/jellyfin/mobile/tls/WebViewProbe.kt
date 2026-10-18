package org.jellyfin.mobile.tls

import android.os.Bundle
import android.webkit.WebSettings
import androidx.test.platform.app.InstrumentationRegistry
import androidx.webkit.WebViewCompat
import org.junit.Test

/**
 * Reports the WebView the app actually loads, used by tls-test-matrix/run-matrix.sh and not part of a test suite.
 * An installed WebView may be unused (Android 6 always loads com.android.webview, Android 7+ the selected provider),
 * the instrumentation status contains webviewPackage, webviewVersion and the Chrome version of the user agent.
 */
class WebViewProbe {
    @Test
    fun currentWebView() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val status = Bundle()
        instrumentation.runOnMainSync {
            // Loads the WebView provider, before Android 8 the package is only known once it is loaded
            val userAgent = WebSettings.getDefaultUserAgent(context)
            val webView = WebViewCompat.getCurrentWebViewPackage(context)
            status.putString("webviewPackage", webView?.packageName.orEmpty())
            status.putString("webviewVersion", webView?.versionName.orEmpty())
            status.putString("webviewUserAgent", userAgent.substringAfter("Chrome/", "").substringBefore(' '))
        }
        instrumentation.sendStatus(0, status)
    }
}
