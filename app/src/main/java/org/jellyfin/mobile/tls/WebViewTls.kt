package org.jellyfin.mobile.tls

import android.net.http.SslCertificate
import android.net.http.SslError
import android.os.Build
import android.webkit.ClientCertRequest
import android.webkit.SslErrorHandler
import android.webkit.WebView
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.Request
import timber.log.Timber
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Client certificates and imported CA certificates for the WebView, which only knows the system store. Problems are
 * reported to [TlsManager.reportProblem] when `report` is true.
 */
class WebViewTls(private val coroutineScope: CoroutineScope) {
    fun onClientCertRequest(view: WebView, request: ClientCertRequest, report: Boolean) {
        val tls = TlsManager.get(view.context)
        val endpoint = TlsEndpoint.of(request.host, request.port)
        val certificate = endpoint?.let { tls.getConfig(it).clientCertificate } ?: ClientCertificate.None
        if (certificate == ClientCertificate.None) {
            Timber.w("Client certificate requested by %s, none configured", endpoint)
            request.ignore()
            if (endpoint != null && report) tls.reportProblem(endpoint, TlsProblem.ClientCertificateRequired)
            return
        }

        // Loading keys may block (KeyChain), the request can be answered from any thread
        coroutineScope.launch(Dispatchers.IO) {
            val key = tls.clientKeyStore.load(certificate)
            if (key != null) {
                request.proceed(key.privateKey, key.chain)
            } else {
                request.ignore()
                if (endpoint != null && report) tls.reportProblem(endpoint, TlsProblem.ClientCertificateUnavailable)
            }
        }
    }

    /**
     * Proceed only when the only problem is an untrusted issuer and the app validated the exact same server certificate
     * against the imported CA certificates.
     */
    @Suppress("ComplexCondition")
    fun onSslError(view: WebView, handler: SslErrorHandler, error: SslError, report: Boolean) {
        val tls = TlsManager.get(view.context)
        val endpoint = TlsEndpoint.fromUrl(error.url)
        val onlyUntrusted = error.hasError(SslError.SSL_UNTRUSTED) && OTHER_SSL_ERRORS.none(error::hasError)
        val leaf = error.certificate?.toX509Certificate()
        if (!onlyUntrusted || endpoint == null || leaf == null || tls.store.getCertificates(endpoint).isEmpty()) {
            handler.cancel()
            if (onlyUntrusted && endpoint != null && report) {
                tls.reportProblem(endpoint, TlsProblem.Untrusted(leaf?.issuerX500Principal?.name))
            }
            return
        }

        coroutineScope.launch {
            val validatedLeaf = withContext(Dispatchers.IO) {
                tls.trustManager.getValidatedLeaf(endpoint) ?: run {
                    runCatching {
                        val url = "https://${endpoint.display}/"
                        tls.okHttpClient.newCall(Request.Builder().url(url).head().build()).execute().close()
                    }.onFailure { Timber.w(it, "Validating the server certificate of %s failed", endpoint.display) }
                    tls.trustManager.getValidatedLeaf(endpoint)
                }
            }

            if (validatedLeaf == leaf.sha256()) {
                handler.proceed()
            } else {
                Timber.w(
                    "WebView certificate of %s not validated by the app (%s)",
                    endpoint.display,
                    validatedLeaf ?: "none"
                )
                handler.cancel()
                if (report) tls.reportProblem(endpoint, TlsProblem.Untrusted(leaf.issuerX500Principal?.name))
            }
        }
    }

    private fun SslCertificate.toX509Certificate(): X509Certificate? = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q -> x509Certificate
        else -> SslCertificate.saveState(this).getByteArray("x509-certificate")?.let { bytes ->
            runCatching {
                CertificateFactory.getInstance("X.509").generateCertificate(bytes.inputStream()) as X509Certificate
            }.getOrNull()
        }
    }

    private companion object {
        val OTHER_SSL_ERRORS = listOf(
            SslError.SSL_NOTYETVALID,
            SslError.SSL_EXPIRED,
            SslError.SSL_IDMISMATCH,
            SslError.SSL_DATE_INVALID,
            SslError.SSL_INVALID,
        )
    }
}
