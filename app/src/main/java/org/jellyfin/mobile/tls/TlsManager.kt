package org.jellyfin.mobile.tls

import android.content.Context
import android.os.Looper
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Response
import java.io.IOException
import java.net.ConnectException
import java.net.InetAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import kotlin.concurrent.thread

/**
 * Process wide TLS configuration supporting custom CA certificates and client certificates (mTLS) per endpoint.
 *
 * Usable before dependency injection is set up. All connections should use [sslSocketFactory] with [trustManager],
 * OkHttp clients should be derived from [okHttpClient].
 */
class TlsManager private constructor(context: Context) {
    val store = TlsStore(context)
    val clientKeyStore = ClientKeyStore(context)
    val trustManager = HostAwareTrustManager(store)
    val keyManager = HostAwareKeyManager(store, clientKeyStore)

    // One SSLContext per endpoint, created when a socket for the endpoint is created. This binds the trust and key
    // manager to the endpoint without APIs that are missing on older Android versions. Replaced on configuration
    // changes to drop all cached TLS sessions (sessions can not be invalidated on all Android versions).
    private val endpointContexts = ConcurrentHashMap<String, SSLContext>()

    @Volatile
    private var defaultContext: SSLContext = createSslContext(null)

    private fun createSslContext(endpoint: TlsEndpoint?): SSLContext = SSLContext.getInstance("TLS").apply {
        if (endpoint == null) {
            init(null, arrayOf(trustManager), null)
        } else {
            init(arrayOf(keyManager.forEndpoint(endpoint)), arrayOf(trustManager.forEndpoint(endpoint)), null)
        }
    }

    private fun getSocketFactory(host: String?, port: Int): SSLSocketFactory {
        val endpoint = TlsEndpoint.of(host, port) ?: return defaultContext.socketFactory
        return endpointContexts.getOrPut(endpoint.key) { createSslContext(endpoint) }.socketFactory
    }

    /**
     * Stable socket factory using the TLS configuration of the endpoint of each socket.
     */
    val sslSocketFactory: SSLSocketFactory = EndpointSslSocketFactory(
        ::getSocketFactory
    ) { defaultContext.socketFactory }

    val okHttpClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .sslSocketFactory(sslSocketFactory, trustManager)
            .addInterceptor(::reportProblems)
            .build()
    }

    private val problemListeners = CopyOnWriteArrayList<(TlsEndpoint, TlsProblem) -> Unit>()

    /**
     * Called on the thread of the request for every request of a client derived from [okHttpClient] that fails with a TLS
     * problem, e.g. to explain empty screens after a certificate was removed.
     */
    fun addProblemListener(listener: (TlsEndpoint, TlsProblem) -> Unit) {
        problemListeners += listener
    }

    fun removeProblemListener(listener: (TlsEndpoint, TlsProblem) -> Unit) {
        problemListeners -= listener
    }

    /**
     * Reports a TLS problem found outside of [okHttpClient], e.g. by the WebView, to the problem listeners.
     */
    fun reportProblem(endpoint: TlsEndpoint, problem: TlsProblem) {
        problemListeners.forEach { it(endpoint, problem) }
    }

    private fun reportProblems(chain: Interceptor.Chain): Response = try {
        chain.proceed(chain.request())
    } catch (err: IOException) {
        // No handshake without a connection: the state recorded by an earlier handshake would be taken for the cause. A
        // missing client certificate ends in "Broken pipe", not an SSLException.
        val connected = generateSequence<Throwable>(err) { it.cause }.none {
            it is ConnectException || it is NoRouteToHostException ||
                it is UnknownHostException || it is SocketTimeoutException
        }
        val url = chain.request().url
        if (connected && url.isHttps && problemListeners.isNotEmpty()) {
            val endpoint = TlsEndpoint.of(url.host, url.port)
            val problem = TlsDiagnostics.diagnose(this, endpoint, err)
            if (endpoint != null && problem != null) reportProblem(endpoint, problem)
        }
        throw err
    }

    private val changeListeners = CopyOnWriteArrayList<() -> Unit>()

    /**
     * Increased on every configuration change, for state that has to be reset later (e.g. the SSL decisions of a WebView).
     */
    @Volatile
    var configVersion = 0
        private set

    fun addChangeListener(listener: () -> Unit) {
        changeListeners += listener
    }

    fun getConfig(endpoint: TlsEndpoint): TlsServerConfig = store.get(endpoint)

    fun setConfig(endpoint: TlsEndpoint, config: TlsServerConfig) {
        val previous = store.get(endpoint).clientCertificate
        store.set(endpoint, config)
        val stillUsed = store.endpoints.any { store.get(it).clientCertificate == previous }
        if (previous != config.clientCertificate && !stillUsed) {
            clientKeyStore.delete(previous)
        }
        onConfigChanged()
    }

    /**
     * Drop all cached state so the next connection uses the current configuration.
     */
    fun onConfigChanged() {
        configVersion++
        clientKeyStore.clearCache()
        trustManager.clearCache()
        keyManager.clearCache()

        // Do not reuse connections or resume sessions negotiated with the old configuration
        endpointContexts.clear()
        defaultContext = createSslContext(null)
        // Closing TLS connections sends close_notify over the network, not allowed on the main thread (crashed with
        // NetworkOnMainThreadException on API 23 - 26 when called from the UI). Wait for it, otherwise the next request
        // could still reuse a connection of the old configuration.
        if (Looper.myLooper() == Looper.getMainLooper()) {
            thread(name = "tls-evict-connections") { okHttpClient.connectionPool.evictAll() }.join(EVICT_TIMEOUT_MS)
        } else {
            okHttpClient.connectionPool.evictAll()
        }

        changeListeners.forEach { it() }
    }

    companion object {
        private const val EVICT_TIMEOUT_MS = 1_000L

        @Volatile
        private var instance: TlsManager? = null

        fun get(context: Context): TlsManager = instance ?: synchronized(this) {
            instance ?: TlsManager(context.applicationContext ?: context).also { instance = it }
        }

        /**
         * Initialize and use the TLS configuration as default for [HttpsURLConnection]. Must be called before any
         * connection is created.
         */
        fun install(context: Context): TlsManager = get(context).also {
            HttpsURLConnection.setDefaultSSLSocketFactory(it.sslSocketFactory)
        }
    }
}

/**
 * Socket factory that selects the [SSLSocketFactory] by the host and port of the connection. Sockets created without a
 * host use [default], which only trusts the platform and presents no client certificate.
 */
private class EndpointSslSocketFactory(
    private val forEndpoint: (host: String?, port: Int) -> SSLSocketFactory,
    private val default: () -> SSLSocketFactory,
) : SSLSocketFactory() {
    override fun getDefaultCipherSuites(): Array<String> = default().defaultCipherSuites
    override fun getSupportedCipherSuites(): Array<String> = default().supportedCipherSuites
    override fun createSocket(): Socket = default().createSocket()

    // Used by OkHttp and HttpsURLConnection, host is the literal host of the URL
    override fun createSocket(socket: Socket?, host: String?, port: Int, autoClose: Boolean): Socket =
        forEndpoint(host, port).createSocket(socket, host, port, autoClose)

    override fun createSocket(host: String?, port: Int): Socket = forEndpoint(host, port).createSocket(host, port)
    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
        forEndpoint(host, port).createSocket(host, port, localHost, localPort)

    override fun createSocket(host: InetAddress?, port: Int): Socket =
        forEndpoint(host?.hostAddress, port).createSocket(host, port)

    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
        forEndpoint(address?.hostAddress, port).createSocket(address, port, localAddress, localPort)
}
