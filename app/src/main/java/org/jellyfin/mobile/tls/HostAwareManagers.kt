package org.jellyfin.mobile.tls

import android.annotation.SuppressLint
import timber.log.Timber
import java.net.Socket
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509KeyManager
import javax.net.ssl.X509TrustManager

// Only interfaces available on every supported API level are used here. X509ExtendedTrustManager and
// SSLSocket.getHandshakeSession require API 24, so the endpoint is bound when the socket is created instead
// (see TlsManager), giving every endpoint its own trust and key manager.

data class TrustFailure(
    val chain: List<X509Certificate>,
    val error: CertificateException,
)

/**
 * Trusts the platform (system + user CA store via network security config) first, then the CA certificates imported
 * for the endpoint. Records validation results per endpoint for diagnostics and the WebView.
 * The checks are done by the platform trust managers, this class only chooses which of them to use.
 */
@SuppressLint("CustomX509TrustManager")
class HostAwareTrustManager(
    private val store: TlsStore,
) : X509TrustManager {
    private val platform: X509TrustManager = createTrustManager(null)
    private val endpointTrustManagers = ConcurrentHashMap<String, X509TrustManager>()
    private val failures = ConcurrentHashMap<String, TrustFailure>()
    private val validatedLeafs = ConcurrentHashMap<String, String>()

    fun getLastFailure(endpoint: TlsEndpoint): TrustFailure? = failures[endpoint.key]

    /**
     * SHA-256 of the last server certificate that passed validation for the endpoint.
     */
    fun getValidatedLeaf(endpoint: TlsEndpoint): String? = validatedLeafs[endpoint.key]

    fun clearCache() {
        endpointTrustManagers.clear()
        failures.clear()
        validatedLeafs.clear()
    }

    @SuppressLint("CustomX509TrustManager")
    fun forEndpoint(endpoint: TlsEndpoint): X509TrustManager = object : X509TrustManager {
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) =
            checkServer(chain, authType, endpoint)

        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
            platform.checkClientTrusted(chain, authType)

        override fun getAcceptedIssuers(): Array<X509Certificate> =
            (platform.acceptedIssuers.asList() + store.getCertificates(endpoint)).distinct().toTypedArray()
    }

    // Without endpoint (sockets created without host) only the platform is trusted
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = checkServer(
        chain,
        authType,
        null
    )

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
        platform.checkClientTrusted(chain, authType)

    // Used by OkHttp to clean certificate chains, include all imported CAs
    override fun getAcceptedIssuers(): Array<X509Certificate> =
        (platform.acceptedIssuers.asList() + store.getAllCertificates()).distinct().toTypedArray()

    private fun checkServer(chain: Array<X509Certificate>, authType: String, endpoint: TlsEndpoint?) {
        try {
            platform.checkServerTrusted(chain, authType)
        } catch (platformError: CertificateException) {
            val custom = endpoint?.let(::getEndpointTrustManager)
            if (custom == null) {
                endpoint?.let { failures[it.key] = TrustFailure(chain.toList(), platformError) }
                throw platformError
            }

            try {
                custom.checkServerTrusted(chain, authType)
            } catch (customError: CertificateException) {
                failures[endpoint.key] = TrustFailure(chain.toList(), customError)
                throw customError
            }
        }

        endpoint?.let {
            failures.remove(it.key)
            chain.firstOrNull()?.let { leaf -> validatedLeafs[it.key] = leaf.sha256() }
        }
    }

    private fun getEndpointTrustManager(endpoint: TlsEndpoint): X509TrustManager? {
        val certificates = store.getCertificates(endpoint)
        if (certificates.isEmpty()) return null
        return endpointTrustManagers.getOrPut(endpoint.key) {
            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null)
                certificates.forEachIndexed { index, certificate -> setCertificateEntry("ca$index", certificate) }
            }
            createTrustManager(keyStore)
        }
    }

    private companion object {
        fun createTrustManager(keyStore: KeyStore?): X509TrustManager {
            val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            factory.init(keyStore)
            return factory.trustManagers.filterIsInstance<X509TrustManager>().first()
        }
    }
}

data class ClientCertificateRequest(
    val issuers: List<Principal>,
    val configured: Boolean,
)

/**
 * Provides the client certificate configured for an endpoint and records client certificate requests for
 * diagnostics.
 */
class HostAwareKeyManager(
    private val store: TlsStore,
    private val clientKeyStore: ClientKeyStore,
) {
    private val requests = ConcurrentHashMap<String, ClientCertificateRequest>()

    /**
     * The last client certificate request by the server of the endpoint, null if the server never asked for one.
     */
    fun getLastRequest(endpoint: TlsEndpoint): ClientCertificateRequest? = requests[endpoint.key]

    fun clearCache() = requests.clear()

    fun forEndpoint(endpoint: TlsEndpoint): X509KeyManager = object : X509KeyManager {
        private fun getKey(alias: String?): ClientKey? =
            if (alias == endpoint.key) clientKeyStore.load(store.get(endpoint).clientCertificate) else null

        override fun chooseClientAlias(
            keyType: Array<out String>?,
            issuers: Array<out Principal>?,
            socket: Socket?,
        ): String? {
            val certificate = store.get(endpoint).clientCertificate
            val available = certificate != ClientCertificate.None && clientKeyStore.load(certificate) != null
            requests[endpoint.key] = ClientCertificateRequest(issuers?.toList().orEmpty(), available)
            if (certificate != ClientCertificate.None && !available) {
                Timber.w("Client certificate for $endpoint is unavailable")
            }
            return if (available) endpoint.key else null
        }

        override fun getCertificateChain(alias: String?): Array<X509Certificate>? = getKey(alias)?.chain
        override fun getPrivateKey(alias: String?): PrivateKey? = getKey(alias)?.privateKey

        // Server side is not used
        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null
        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null
        override fun chooseServerAlias(
            keyType: String?,
            issuers: Array<out Principal>?,
            socket: Socket?
        ): String? = null
    }
}
