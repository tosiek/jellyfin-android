package org.jellyfin.mobile.tls.ui

import android.util.Log
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlin.concurrent.thread

/**
 * HTTPS server answering like a Jellyfin server for the connection check of the connect screen. Uses the server
 * certificate of the test fixtures (issued by ca/single.pem) and requires a client certificate issued by
 * server/client-ca.pem when [requireClientCertificate] is set.
 */
class FakeJellyfinServer(
    read: (String) -> ByteArray,
    requireClientCertificate: Boolean,
) : AutoCloseable {
    private val socket: SSLServerSocket

    init {
        val keyStore = KeyStore.getInstance("PKCS12").apply { load(ByteArrayInputStream(read("server/server.p12")), PASSWORD) }
        val keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            .apply { init(keyStore, PASSWORD) }.keyManagers
        val clientCa = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(read("server/client-ca.pem"))) as X509Certificate
        val trustStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("client-ca", clientCa)
        }
        val trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(trustStore) }.trustManagers
        val context = SSLContext.getInstance("TLS").apply { init(keyManagers, trustManagers, null) }
        socket = (context.serverSocketFactory.createServerSocket(0) as SSLServerSocket).apply {
            needClientAuth = requireClientCertificate
        }

        thread(isDaemon = true) {
            while (!socket.isClosed) {
                val client = runCatching { socket.accept() as SSLSocket }.getOrNull() ?: break
                thread(isDaemon = true) { handle(client) }
            }
        }
    }

    val address get() = "https://localhost:${socket.localPort}"

    private fun handle(client: SSLSocket) = runCatching {
        client.use {
            it.soTimeout = 10_000
            val reader = it.inputStream.bufferedReader()
            val path = reader.readLine()?.split(' ')?.getOrNull(1).orEmpty()
            while (reader.readLine()?.isNotEmpty() == true) Unit
            Log.i("FakeJellyfin", "GET $path")

            val body = when {
                path.startsWith("/System/Info/Public", ignoreCase = true) -> """{"LocalAddress":"$address","ServerName":"Fake",""" +
                    """"Version":"99.0.0","ProductName":"Jellyfin Server","OperatingSystem":"","Id":"$SERVER_ID",""" +
                    """"StartupWizardCompleted":true}"""

                path.startsWith("/Users/Public", ignoreCase = true) -> "[]"
                path.startsWith("/Branding/Configuration", ignoreCase = true) -> """{"SplashscreenEnabled":false}"""
                path.startsWith("/QuickConnect/Enabled", ignoreCase = true) -> "false"
                else -> null
            }
            val status = if (body != null) "200 OK" else "404 Not Found"
            val bytes = (body ?: "").toByteArray()
            it.outputStream.write(
                ("HTTP/1.1 $status\r\nContent-Type: application/json\r\nContent-Length: ${bytes.size}\r\nConnection: close\r\n\r\n")
                    .toByteArray() + bytes
            )
            it.outputStream.flush()
        }
    }

    override fun close() = socket.close()

    private companion object {
        val PASSWORD = "jellyfin".toCharArray()
        const val SERVER_ID = "0123456789abcdef0123456789abcdef"
    }
}
