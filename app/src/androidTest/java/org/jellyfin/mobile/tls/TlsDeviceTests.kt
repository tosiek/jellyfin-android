package org.jellyfin.mobile.tls

import android.os.Build
import android.os.StrictMode
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.TlsVersion
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.security.KeyStore
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.KeyManager
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread

/**
 * Device tests for the tls package. Run on every API level of the support matrix, the output of [pkcs12Matrix]
 * (logcat tag "TlsSupport") is the compatibility table of PKCS#12 files per Android version.
 */
class TlsDeviceTests {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val tls = TlsManager.get(context)
    private val servers = mutableListOf<TestServer>()
    private val endpoints = mutableListOf<TlsEndpoint>()

    private val tlsVersions = buildList {
        add(TlsVersion.TLS_1_2)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) add(TlsVersion.TLS_1_3)
    }

    @After
    fun tearDown() {
        servers.forEach { it.close() }
        endpoints.forEach { tls.setConfig(it, TlsServerConfig()) }
    }

    // Import

    @Test
    fun caFormats() {
        mapOf(
            "ca/single.pem" to 1, "ca/bundle.pem" to 2, "ca/crlf.pem" to 1, "ca/bom.pem" to 1, "ca/with-text.pem" to 1,
            "ca/single.der" to 1, "ca/single.cer" to 1, "ca/bundle.p7b" to 2, "ca/bundle-der.p7b" to 2,
            "ca/extra-bag-attributes.pem" to 1, "ca/extra-bundle-comments.pem" to 2,
        ).forEach { (file, count) ->
            assertEquals(file, count, CertificateImporter.parseCertificates(read(file)).certificates.size)
        }
        listOf("ca/garbage.bin", "ca/empty.pem", "ca/private-key-only.pem").forEach { file ->
            assertEquals(file, ImportError.UnrecognizedFormat, importError { CertificateImporter.parseCertificates(read(file)) })
        }
        assertTrue(importError { CertificateImporter.parseCertificates(read("ca/expired.pem")) } is ImportError.Expired)
    }

    @Test
    fun pkcs12Matrix() {
        val unexpected = mutableListOf<String>()
        val files = KEY_TYPES.flatMap { key -> ENCRYPTIONS.map { "client/$key-$it.p12" } }

        for (file in files) {
            var cause: String? = null
            val outcome = try {
                val parsed = CertificateImporter.parsePkcs12(read(file), PASSWORD.toCharArray())
                val stored = tls.clientKeyStore.import(parsed.key)
                val loaded = requireNotNull(tls.clientKeyStore.load(stored))
                assertTrue(KeySelfTest.run(loaded.privateKey, loaded.chain.first()))
                tls.clientKeyStore.delete(stored)
                "ok:${stored.storage}"
            } catch (err: ImportException) {
                cause = generateSequence(err.cause) { it.cause }.joinToString(" <- ") { "${it.javaClass.simpleName}: ${it.message}" }
                "error:${err.error.javaClass.simpleName}"
            } catch (_: ClientKeyStore.KeyUnusableException) {
                "error:KeyUnusable"
            }

            Log.i("TlsSupport", "API ${Build.VERSION.SDK_INT} | $file | $outcome")
            if (cause != null) Log.i("TlsSupport", "  cause: $cause")
            if (!isExpected(file, outcome)) unexpected += "$file -> $outcome"
        }

        // Extra fixtures (jellyfin-desktop test cases): file to allowed outcomes, Android versions may differ
        val readableOrUnsupported = setOf("ok:KEYSTORE", "ok:ENCRYPTED_FILE", "error:UnsupportedEncryption")
        val extras = mapOf(
            "client/extra-rsa8192-3des.p12" to setOf("ok:KEYSTORE", "ok:ENCRYPTED_FILE"),
            "client/extra-brainpool256-3des.p12" to setOf("error:UnsupportedKeyType", "error:UnreadableKey"),
            "client/extra-dsa2048-3des.p12" to setOf("error:UnsupportedKeyType", "error:UnreadableKey"),
            "client/extra-mldsa65-3des.p12" to setOf("error:UnsupportedKeyType", "error:UnreadableKey"),
            "client/extra-ec256-aes128.p12" to readableOrUnsupported,
            "client/extra-ec256-mac-sha512.p12" to readableOrUnsupported,
            "client/extra-ec256-mac-sha384.p12" to readableOrUnsupported,
            "client/extra-ec256-pbes1-md5.p12" to readableOrUnsupported,
            "client/extra-utf8-subject-3des.p12" to setOf("ok:KEYSTORE", "ok:ENCRYPTED_FILE"),
            "client/extra-no-cn-3des.p12" to setOf("ok:KEYSTORE", "ok:ENCRYPTED_FILE"),
            "client/extra-expired-client-3des.p12" to setOf("error:Expired"),
        )
        val passwords = mapOf("client/extra-ec256-utf8-password.p12" to "Pässwörd!123_üöä€")
        val passwordOutcomes = readableOrUnsupported + "error:WrongOrUnsupportedPassword"
        for (file in extras.keys + passwords.keys) {
            var cause: String? = null
            val outcome = try {
                val parsed = CertificateImporter.parsePkcs12(read(file), (passwords[file] ?: PASSWORD).toCharArray())
                val stored = tls.clientKeyStore.import(parsed.key)
                tls.clientKeyStore.delete(stored)
                "ok:${stored.storage}"
            } catch (err: ImportException) {
                cause = generateSequence(err.cause) { it.cause }.joinToString(" <- ") { "${it.javaClass.simpleName}: ${it.message}" }
                "error:${err.error.javaClass.simpleName}"
            } catch (_: ClientKeyStore.KeyUnusableException) {
                "error:KeyUnusable"
            }
            Log.i("TlsSupport", "API ${Build.VERSION.SDK_INT} | $file | $outcome")
            if (cause != null) Log.i("TlsSupport", "  cause: $cause")
            val allowed = extras[file] ?: passwordOutcomes
            if (outcome !in allowed) unexpected += "$file -> $outcome"
        }

        assertTrue("Unexpected outcomes on API ${Build.VERSION.SDK_INT}:\n${unexpected.joinToString("\n")}", unexpected.isEmpty())
    }

    private fun isExpected(file: String, outcome: String): Boolean {
        val key = file.substringAfter('/').substringBefore('-')
        val encryption = file.substringAfterLast('-').removeSuffix(".p12")
        return when {
            // Ed25519 is either recognized as unsupported or can not be decoded at all (encrypted key, API < 33)
            // P-521 does not work for client authentication over TLS 1.3 on Android, rejected at import
            key == "ec521" -> outcome == "error:UnsupportedKeyType" || outcome == "error:UnsupportedEncryption"
            key == "ed25519" -> outcome == "error:UnsupportedKeyType" || outcome == "error:UnreadableKey" ||
                outcome == "error:UnsupportedEncryption"
            // Unencrypted key bags are ignored by the platform PKCS#12 reader on some versions
            encryption == "nopbe" -> outcome.startsWith("ok:") || outcome == "error:UnsupportedEncryption"
            // Encryption support differs per Android version, it must be either readable or reported as unsupported
            encryption == "aes" || encryption == "legacy" -> outcome.startsWith("ok:") || outcome == "error:UnsupportedEncryption"
            else -> outcome.startsWith("ok:")
        }
    }

    @Test
    fun pkcs12Variants() {
        assertNotNull(CertificateImporter.parsePkcs12(read("client/rsa2048-empty-password.p12"), CharArray(0)))
        val unicode = runCatching {
            CertificateImporter.parsePkcs12(read("client/rsa2048-unicode-password.p12"), UNICODE_PASSWORD.toCharArray())
        }
        assertTrue(
            "unicode: ${unicode.exceptionOrNull()}",
            unicode.isSuccess || (unicode.exceptionOrNull() as? ImportException)?.error is ImportError.UnsupportedEncryption,
        )
        assertEquals(
            ImportError.WrongPassword,
            importError { CertificateImporter.parsePkcs12(read("client/ec256-3des.p12"), "x".toCharArray()) },
        )
        // cert-only.p12 uses the OpenSSL 3 default encryption, which is not readable on every Android version
        val certOnly = importError { CertificateImporter.parsePkcs12(read("client/cert-only.p12"), PASSWORD.toCharArray()) }
        assertTrue("cert-only: $certOnly", certOnly == ImportError.NoPrivateKey || certOnly is ImportError.UnsupportedEncryption)
        assertEquals(
            ImportError.NotPkcs12,
            importError { CertificateImporter.parsePkcs12(read("client/pem-key-and-cert.pem"), PASSWORD.toCharArray()) },
        )
        assertEquals(2, CertificateImporter.getPkcs12KeyAliases(read("client/two-keys.p12"), PASSWORD.toCharArray()).size)
    }

    // Handshakes

    @Suppress("NestedBlockDepth")
    @Test
    fun mutualTlsAllKeyTypesAndVersions() {
        val failures = mutableListOf<String>()
        for (key in listOf("rsa2048", "rsa4096", "ec256", "ec384")) {
            val server = startServer()
            val endpoint = configure(server, key)
            val storage = (tls.getConfig(endpoint).clientCertificate as ClientCertificate.Imported).storage
            val requests = tlsVersions.map { version -> "$version" to { requestOkHttp(server, version) } } +
                ("HttpsURLConnection" to { requestUrlConnection(server) })
            for ((name, request) in requests) {
                val result = runCatching(request)
                val outcome = result.getOrNull()?.let { if (it == "client-$key") "ok" else "wrong client $it" }
                    ?: generateSequence(result.exceptionOrNull()) { it.cause }
                        .joinToString(" <- ") { "${it.javaClass.simpleName}: ${it.message}" }
                Log.i("TlsSupport", "API ${Build.VERSION.SDK_INT} | handshake $key ($storage) $name | $outcome")
                if (outcome != "ok") failures += "$key ($storage) $name: $outcome"
            }
            tls.setConfig(endpoint, TlsServerConfig())
        }
        assertTrue("Failed handshakes on API ${Build.VERSION.SDK_INT}:\n${failures.joinToString("\n")}", failures.isEmpty())
    }

    @Test
    fun eachPortUsesItsOwnConfiguration() {
        val first = startServer()
        val second = startServer()
        configure(first, "ec256")
        configure(second, "rsa2048")
        assertEquals("client-ec256", requestOkHttp(first))
        assertEquals("client-rsa2048", requestOkHttp(second))
    }

    @Test
    fun configurationChangeAppliesToNextRequest() {
        val server = startServer()
        val endpoint = configure(server, "ec256")
        assertEquals("client-ec256", requestOkHttp(server))
        configure(server, "rsa2048")
        assertEquals("client-rsa2048", requestOkHttp(server))
        tls.setConfig(endpoint, tls.getConfig(endpoint).copy(clientCertificate = ClientCertificate.None))
        assertEquals(TlsProblem.ClientCertificateRequired, failure(server, endpoint))
    }

    @Test
    fun configurationChangeClosesPooledConnections() {
        val server = startServer(keepAlive = true)
        configure(server, "ec256")
        assertEquals("client-ec256", requestOkHttp(server))
        assertEquals("client-ec256", requestOkHttp(server))
        // The second request reused the pooled connection
        assertEquals(1, server.connections)

        // The very next request must not reuse the connection of the old configuration: evicted before the
        // configuration change returns, not in the background
        configure(server, "rsa2048")
        assertEquals(0, tls.okHttpClient.connectionPool.connectionCount())
        assertEquals("client-rsa2048", requestOkHttp(server))
        assertEquals(2, server.connections)
    }

    @Test
    fun configurationChangeOnMainThreadWithPooledConnection() {
        val server = startServer(keepAlive = true)
        configure(server, "ec256")
        assertEquals("client-ec256", requestOkHttp(server))
        assertTrue(tls.okHttpClient.connectionPool.connectionCount() > 0)

        // Changes from the UI run on the main thread, closing the pooled TLS connection there crashed on API 23 - 26
        var error: Throwable? = null
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            val policy = StrictMode.getThreadPolicy()
            StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.Builder().detectNetwork().penaltyDeathOnNetwork().build())
            error = runCatching { tls.onConfigChanged() }.exceptionOrNull()
            StrictMode.setThreadPolicy(policy)
        }
        assertEquals(null, error)
        assertEquals(0, tls.okHttpClient.connectionPool.connectionCount())
        assertEquals("client-ec256", requestOkHttp(server))
        assertEquals(2, server.connections)
    }

    @Test
    fun missingClientCertificate() {
        val server = startServer()
        val endpoint = configure(server, null)
        assertEquals(TlsProblem.ClientCertificateRequired, failure(server, endpoint))
    }

    @Test
    fun untrustedServer() {
        val server = startServer()
        val endpoint = endpointOf(server)
        tls.setConfig(endpoint, TlsServerConfig(caFingerprints = listOf(tls.store.addCertificate(certificate("ca/other.pem")))))
        assertTrue(failure(server, endpoint) is TlsProblem.Untrusted)
    }

    @Test
    fun expiredServer() {
        val server = startServer("server/server-expired.p12")
        val endpoint = configure(server, "ec256")
        assertTrue(failure(server, endpoint) is TlsProblem.Expired)
    }

    @Test
    fun wrongHostServer() {
        val server = startServer("server/server-wrong-host.p12")
        val endpoint = configure(server, "ec256")
        assertEquals(TlsProblem.HostnameMismatch, failure(server, endpoint))
    }

    @Test
    fun hostLiteralsAreSeparate() {
        val server = startServer()
        configure(server, "ec256")
        // Configured for localhost only, 127.0.0.1 is a different endpoint and must not get the CA
        val result = runCatching { requestOkHttp(server, host = "127.0.0.1") }
        assertTrue(result.isFailure)
    }

    // Capabilities offered by the TLS stack

    /**
     * Records the ClientHello of the app's TLS stack (OkHttp: API, WebSocket, images, ExoPlayer on TV;
     * HttpsURLConnection: ExoPlayer on mobile, media artwork, crash reports) and logs the offered TLS versions,
     * key exchange groups, cipher suites and signature algorithms for the compatibility matrix.
     */
    @Test
    fun clientHelloCapabilities() {
        val clients = listOf<Pair<String, (String) -> Unit>>(
            "OkHttp" to { url ->
                tls.okHttpClient.newBuilder().callTimeout(5, TimeUnit.SECONDS).build()
                    .newCall(Request.Builder().url(url).build()).execute().close()
            },
            "HttpsURLConnection" to { url ->
                (URL(url).openConnection() as HttpsURLConnection).apply {
                    connectTimeout = 5_000
                    readTimeout = 5_000
                }.inputStream.close()
            },
        )

        for ((client, request) in clients) {
            val hello = ClientHello.parse(captureClientHello { port -> runCatching { request("https://localhost:$port/") } })
            for ((field, values) in hello.fields()) {
                Log.i("TlsSupport", "API ${Build.VERSION.SDK_INT} | clienthello $client $field | ${values.joinToString(", ")}")
            }
            assertTrue("$client offers no key exchange group", hello.groups.isNotEmpty())
            assertTrue("$client offers no cipher suite", hello.cipherSuites.isNotEmpty())
        }
    }

    /**
     * Post-quantum algorithms of the platform providers (ML-KEM, ML-DSA, SLH-DSA), for the compatibility matrix.
     */
    @Test
    fun postQuantumAlgorithms() {
        val pattern = Regex("ML-?KEM|ML-?DSA|SLH-?DSA|KYBER|DILITHIUM|SPHINCS", RegexOption.IGNORE_CASE)
        val found = Security.getProviders().flatMap { provider ->
            provider.services.filter { pattern.containsMatchIn(it.algorithm) }.map { "${provider.name} ${it.type} ${it.algorithm}" }
        }.distinct().sorted()
        Log.i("TlsSupport", "API ${Build.VERSION.SDK_INT} | pqc algorithms | ${found.joinToString(", ").ifEmpty { "none" }}")
    }

    /**
     * Whether the TLS stack offers X25519MLKEM768 when asked for it with SSLParameters.setNamedGroups (Java 20 API).
     * clientHelloCapabilities shows what the app gets without asking.
     */
    @Test
    fun postQuantumKeyExchangeOptIn() {
        val setNamedGroups = setNamedGroups
        val outcome = if (setNamedGroups == null) {
            "SSLParameters.setNamedGroups missing"
        } else {
            var error: Throwable? = null
            val hello = runCatching {
                ClientHello.parse(
                    captureClientHello { port ->
                        error = runCatching {
                            (tls.sslSocketFactory.createSocket("localhost", port) as SSLSocket).use { socket ->
                                socket.soTimeout = 5_000
                                socket.sslParameters = socket.sslParameters.also {
                                    setNamedGroups.invoke(it, arrayOf("X25519MLKEM768", "x25519"))
                                }
                                socket.startHandshake()
                            }
                        }.exceptionOrNull()
                    },
                )
            }.getOrNull()
            hello?.fields()?.first { it.first == "groups" }?.second?.joinToString(", ", prefix = "groups ")
                ?: "no ClientHello (${error?.javaClass?.simpleName}: ${error?.message})"
        }
        Log.i("TlsSupport", "API ${Build.VERSION.SDK_INT} | pqc opt-in X25519MLKEM768 | $outcome")
    }

    /**
     * The sockets of the app offer X25519MLKEM768 first from Android 17, with a key share (no extra round trip), and
     * keep the classic groups and the server name.
     */
    @Test
    fun postQuantumOfferedByApp() {
        val hello = ClientHello.parse(
            captureClientHello { port ->
                runCatching {
                    // Like OkHttp: TLS layered over a connected socket, the host of the URL for the server name
                    (tls.sslSocketFactory.createSocket(Socket("localhost", port), "jellyfin.example", port, true) as SSLSocket).use {
                        it.soTimeout = 5_000
                        it.startHandshake()
                    }
                }
            },
        )
        val fields = hello.fields().toMap()
        val outcome = "groups ${fields["groups"]}, key shares ${fields["keyshares"]}, server name ${hello.serverName}"
        Log.i("TlsSupport", "API ${Build.VERSION.SDK_INT} | pqc app sockets | $outcome")
        if (setNamedGroups != null) {
            assertEquals(listOf("X25519MLKEM768", "x25519", "secp256r1", "secp384r1"), fields["groups"])
            assertTrue(outcome, "X25519MLKEM768" in fields.getValue("keyshares"))
            assertEquals("jellyfin.example", hello.serverName)
        } else {
            assertTrue(outcome, "X25519MLKEM768" !in fields.getValue("groups"))
        }
    }

    /**
     * A handshake with a server that only accepts X25519MLKEM768 succeeds only when the hybrid post-quantum key
     * exchange is negotiated. Without asking for it (what the app does now) the same client must fail.
     */
    @Test
    fun postQuantumHandshake() {
        if (setNamedGroups == null) {
            Log.i("TlsSupport", "API ${Build.VERSION.SDK_INT} | pqc handshake | SSLParameters.setNamedGroups missing")
            return
        }
        val postQuantum = handshakeWithGroups(arrayOf("X25519MLKEM768"), arrayOf("X25519MLKEM768", "x25519"))
        val default = handshakeWithGroups(arrayOf("X25519MLKEM768"), null)
        Log.i("TlsSupport", "API ${Build.VERSION.SDK_INT} | pqc handshake X25519MLKEM768 | ${postQuantum.describe()}")
        Log.i("TlsSupport", "API ${Build.VERSION.SDK_INT} | pqc handshake default groups | ${default.describe()}")
        assertTrue("X25519MLKEM768 handshake: ${postQuantum.describe()}", postQuantum.isSuccess)
        assertTrue("Default groups against an X25519MLKEM768-only server: ${default.describe()}", default.isFailure)
    }

    /**
     * Every post-quantum group alone: accepted by setNamedGroups, offered in the ClientHello, and a handshake with a
     * server that only accepts that group. For the compatibility matrix, not an assertion.
     */
    @Test
    fun postQuantumGroups() {
        val setNamedGroups = setNamedGroups ?: return
        // The groups the TLS stack reports itself (SSLParameters.getNamedGroups): the defaults of a new socket
        val getNamedGroups = SSLParameters::class.java.getMethod("getNamedGroups")
        (tls.sslSocketFactory.createSocket() as SSLSocket).use { socket ->
            val groups = (getNamedGroups.invoke(socket.sslParameters) as Array<*>?)?.joinToString(", ") ?: "null"
            Log.i("TlsSupport", "API ${Build.VERSION.SDK_INT} | pqc named groups default | $groups")
        }
        val candidates = listOf("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM768", "MLKEM1024",
            "X25519Kyber768Draft00")
        for (group in candidates) {
            var error: Throwable? = null
            val hello = runCatching {
                ClientHello.parse(
                    captureClientHello { port ->
                        error = runCatching {
                            (tls.sslSocketFactory.createSocket("localhost", port) as SSLSocket).use { socket ->
                                socket.soTimeout = 5_000
                                socket.sslParameters = socket.sslParameters.also { setNamedGroups.invoke(it, arrayOf(group)) }
                                socket.startHandshake()
                            }
                        }.exceptionOrNull()
                    },
                )
            }.getOrNull()
            val offered = hello?.fields()?.first { it.first == "groups" }?.second?.joinToString(", ")
            val outcome = if (offered == null) {
                "not accepted (${error?.javaClass?.simpleName}: ${error?.message})"
            } else {
                "offered: $offered, handshake: ${handshakeWithGroups(arrayOf(group), arrayOf(group)).describe()}"
            }
            Log.i("TlsSupport", "API ${Build.VERSION.SDK_INT} | pqc group $group | $outcome")
        }
    }

    /**
     * Handshake with a server of another TLS implementation, e.g. OpenSSL 3.5 `s_server -www -groups X25519MLKEM768`
     * on the host. Instrumentation arguments pqcHost, pqcPort and pqcGroups (comma separated), skipped without them,
     * pqcCaUrl for a server CA other than server/root.pem (e.g. ca.pem of the test proxy), pqcClientUrl (comma separated,
     * one handshake each) and pqcClientPassword (default jellyfin) for client certificates (e.g. client-ec.p12 and
     * client-rsa.p12 of the test proxy, mTLS port 8920).
     * Logs the lines of the OpenSSL status page that name the negotiated group.
     */
    @Suppress("CyclomaticComplexMethod")
    @Test
    fun postQuantumExternalServer() {
        val args = InstrumentationRegistry.getArguments()
        val host = args.getString("pqcHost")
        val port = args.getString("pqcPort")?.toIntOrNull()
        val method = setNamedGroups
        assumeTrue(host != null && port != null && method != null)
        val groups = args.getString("pqcGroups")?.split(",")?.toTypedArray()
        val ca = args.getString("pqcCaUrl")?.let { url -> URL(url).readBytes() }
        val password = (args.getString("pqcClientPassword") ?: "jellyfin").toCharArray()
        val clients = args.getString("pqcClientUrl")?.split(",") ?: listOf(null)
        val failures = clients.mapNotNull { url ->
            val result = runCatching {
                val keyStore = url?.let {
                    KeyStore.getInstance("PKCS12").apply { load(ByteArrayInputStream(URL(it).readBytes()), password) }
                }
                val keyManagers = keyStore?.let {
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(it, password) }.keyManagers
                }
                val keyType = keyStore?.let { it.getCertificate(it.aliases().nextElement()).publicKey.algorithm } ?: "no client key"
                (rootTrustingContext(ca, keyManagers).socketFactory.createSocket(host, port!!) as SSLSocket).use { socket ->
                    socket.soTimeout = 10_000
                    if (groups != null) socket.sslParameters = socket.sslParameters.also { method!!.invoke(it, groups) }
                    socket.startHandshake()
                    socket.outputStream.write("GET / HTTP/1.0\r\n\r\n".toByteArray())
                    socket.outputStream.flush()
                    val page = socket.inputStream.bufferedReader().readText()
                    val negotiated = page.lines().filter { it.contains("group", ignoreCase = true) }.joinToString(" / ")
                    "$keyType, ${socket.session.protocol} ${socket.session.cipherSuite}, server: $negotiated"
                }
            }
            val name = url?.substringAfterLast('/') ?: "no client key"
            val offered = groups?.joinToString(",") ?: "default"
            Log.i("TlsSupport", "API ${Build.VERSION.SDK_INT} | pqc external $host:$port $offered $name | ${result.describe()}")
            result.exceptionOrNull()?.let { "$name: ${result.describe()}" }
        }
        assertTrue(failures.joinToString("; "), failures.isEmpty())
    }

    private fun rootTrustingContext(ca: ByteArray? = null, keyManagers: Array<KeyManager>? = null): SSLContext {
        val trust = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            val root = ca?.let { CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(it)) }
            setCertificateEntry("root", root ?: certificate("server/root.pem"))
        }
        val trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trust) }.trustManagers
        return SSLContext.getInstance("TLS").apply { init(keyManagers, trustManagers, null) }
    }

    // SSLParameters.setNamedGroups (Java 20 API), missing before Android 17
    private val setNamedGroups = runCatching {
        SSLParameters::class.java.getMethod("setNamedGroups", Array<String>::class.java)
    }.getOrNull()

    private fun Result<String>.describe() = fold({ "ok $it" }, { "failed ${it.javaClass.simpleName}: ${it.message}" })

    /**
     * TLS handshake on this device between a server that only accepts [serverGroups] and a client offering
     * [clientGroups] (null: the defaults). The result is the negotiated protocol and cipher suite.
     */
    private fun handshakeWithGroups(serverGroups: Array<String>, clientGroups: Array<String>?): Result<String> {
        val method = requireNotNull(setNamedGroups)
        val keyStore = KeyStore.getInstance("PKCS12").apply {
            load(ByteArrayInputStream(read("server/server.p12")), PASSWORD.toCharArray())
        }
        val keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            .apply { init(keyStore, PASSWORD.toCharArray()) }.keyManagers
        val serverContext = SSLContext.getInstance("TLS").apply { init(keyManagers, null, null) }
        val clientContext = rootTrustingContext()

        return (serverContext.serverSocketFactory.createServerSocket(0) as SSLServerSocket).use { server ->
            // Set on the accepted socket, Conscrypt does not pass the groups of the server socket on
            val accepting = thread(isDaemon = true) {
                runCatching {
                    (server.accept() as SSLSocket).use { socket ->
                        socket.soTimeout = 5_000
                        socket.sslParameters = socket.sslParameters.also { method.invoke(it, serverGroups) }
                        socket.startHandshake()
                    }
                }
            }
            runCatching {
                (clientContext.socketFactory.createSocket("localhost", server.localPort) as SSLSocket).use { socket ->
                    socket.soTimeout = 5_000
                    if (clientGroups != null) socket.sslParameters = socket.sslParameters.also { method.invoke(it, clientGroups) }
                    socket.startHandshake()
                    "${socket.session.protocol} ${socket.session.cipherSuite}"
                }
            }.also { accepting.join(5_000) }
        }
    }

    private fun captureClientHello(connect: (port: Int) -> Unit): ByteArray = ServerSocket(0).use { server ->
        var captured: ByteArray? = null
        val reader = thread(isDaemon = true) {
            runCatching {
                server.accept().use { socket ->
                    val input = DataInputStream(socket.getInputStream())
                    val header = ByteArray(5).also(input::readFully) // TLS record: type, version, length
                    check(header[0] == 0x16.toByte()) { "Not a TLS handshake record" }
                    val length = ((header[3].toInt() and 0xff) shl 8) or (header[4].toInt() and 0xff)
                    captured = ByteArray(length).also(input::readFully)
                }
            }
        }
        connect(server.localPort)
        reader.join(10_000)
        requireNotNull(captured) { "No ClientHello received" }
    }

    // Helpers

    private fun endpointOf(server: TestServer) = TlsEndpoint.of("localhost", server.port)!!.also { endpoints += it }

    private fun configure(server: TestServer, clientKey: String?): TlsEndpoint {
        val endpoint = endpointOf(server)
        val ca = tls.store.addCertificate(certificate("server/root.pem"))
        val client = clientKey?.let {
            val parsed = CertificateImporter.parsePkcs12(read("client/$it-3des.p12"), PASSWORD.toCharArray())
            tls.clientKeyStore.import(parsed.key)
        } ?: ClientCertificate.None
        tls.setConfig(endpoint, TlsServerConfig(listOf(ca), client))
        return endpoint
    }

    private fun requestOkHttp(server: TestServer, version: TlsVersion? = null, host: String = "localhost"): String {
        val client = tls.okHttpClient.newBuilder()
            .apply {
                if (version != null) {
                    connectionSpecs(listOf(ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS).tlsVersions(version).build()))
                }
            }
            .callTimeout(10, TimeUnit.SECONDS)
            .build()
        return client.newCall(Request.Builder().url("https://$host:${server.port}/").build()).execute().use { response ->
            assertEquals(200, response.code)
            requireNotNull(response.body).string()
        }
    }

    private fun requestUrlConnection(server: TestServer): String {
        // Uses the default socket factory installed by TlsManager.install
        val connection = URL("https://localhost:${server.port}/").openConnection() as HttpsURLConnection
        return try {
            assertEquals(200, connection.responseCode)
            connection.inputStream.bufferedReader().readText()
        } finally {
            connection.disconnect()
        }
    }

    private fun failure(server: TestServer, endpoint: TlsEndpoint): TlsProblem? {
        val error = runCatching { requestOkHttp(server) }.exceptionOrNull()
        if (error == null) fail("Request should fail")
        return TlsDiagnostics.diagnose(tls, endpoint, error)
    }

    private fun startServer(keyStoreFile: String = "server/server.p12", keepAlive: Boolean = false) = TestServer(
        keyStore = KeyStore.getInstance("PKCS12").apply { load(ByteArrayInputStream(read(keyStoreFile)), PASSWORD.toCharArray()) },
        clientCa = certificate("server/client-ca.pem"),
        keepAlive = keepAlive,
    ).also { servers += it }

    // Fixtures are packaged as assets of the test APK
    private fun read(path: String) =
        InstrumentationRegistry.getInstrumentation().context.assets.open("tls/$path").use { it.readBytes() }

    private fun certificate(path: String) =
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(read(path))) as X509Certificate

    private fun importError(block: () -> Unit): ImportError? = try {
        block()
        null
    } catch (err: ImportException) {
        err.error
    }

    /**
     * Minimal HTTPS server requiring a client certificate. Responds with the CN of the client certificate. With
     * [keepAlive] connections stay open for further requests, so OkHttp pools them.
     */
    private class TestServer(keyStore: KeyStore, clientCa: X509Certificate, private val keepAlive: Boolean) : AutoCloseable {
        private val socket: SSLServerSocket
        private val accepted = AtomicInteger()
        private val verifiedClient = ThreadLocal<X509Certificate?>()
        private val sessionClients = ConcurrentHashMap<String, X509Certificate>()

        init {
            val keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
                .apply { init(keyStore, PASSWORD.toCharArray()) }.keyManagers
            val trustStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null)
                setCertificateEntry("client-ca", clientCa)
            }
            val platform = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                .apply { init(trustStore) }.trustManagers.filterIsInstance<X509TrustManager>().first()
            // Record the client leaf certificate during verification: on API 23 (OpenSSL based Conscrypt) the server
            // side SSLSession.getPeerCertificates() does not contain the client leaf certificate.
            val recording = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                    platform.checkClientTrusted(chain, authType)
                    verifiedClient.set(chain.first())
                }

                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) =
                    platform.checkServerTrusted(chain, authType)

                override fun getAcceptedIssuers(): Array<X509Certificate> = platform.acceptedIssuers
            }
            val context = SSLContext.getInstance("TLS").apply { init(keyManagers, arrayOf(recording), null) }
            socket = (context.serverSocketFactory.createServerSocket(0) as SSLServerSocket).apply { needClientAuth = true }

            thread(isDaemon = true) {
                while (!socket.isClosed) {
                    val client = runCatching { socket.accept() as SSLSocket }.getOrNull() ?: break
                    thread(isDaemon = true) { handle(client) }
                }
            }
        }

        val port get() = socket.localPort

        // Number of accepted TLS connections
        val connections get() = accepted.get()

        private fun handle(client: SSLSocket) = runCatching {
            client.use {
                accepted.incrementAndGet()
                it.soTimeout = 10_000
                val reader = it.inputStream.bufferedReader()
                var body: String? = null
                // Request line, then headers until the empty line
                while (reader.readLine() != null) {
                    while (reader.readLine()?.isNotEmpty() == true) Unit
                    if (body == null) {
                        // The handshake runs on this thread, resumed sessions skip verification
                        val sessionId = it.session.id.joinToString("") { byte -> "%02x".format(byte) }
                        verifiedClient.get()?.let { verified -> sessionClients[sessionId] = verified }
                        verifiedClient.remove()
                        val certificate = sessionClients[sessionId] ?: it.session.peerCertificates.first() as X509Certificate
                        body = certificate.subjectX500Principal.name.substringAfter("CN=").substringBefore(',')
                    }
                    val connection = if (keepAlive) "keep-alive" else "close"
                    val response = "HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: $connection\r\n\r\n$body"
                    it.outputStream.write(response.toByteArray())
                    it.outputStream.flush()
                    if (!keepAlive) break
                }
            }
        }

        override fun close() = socket.close()
    }

    private companion object {
        const val PASSWORD = "jellyfin"
        const val UNICODE_PASSWORD = "zażółć-ü"
        val KEY_TYPES = listOf("rsa2048", "rsa4096", "rsa1024", "ec256", "ec384", "ec521", "ed25519")
        val ENCRYPTIONS = listOf("aes", "legacy", "3des", "nopbe")
    }
}

/**
 * Minimal ClientHello parser for the capabilities of the TLS stack.
 */
private class ClientHello(
    val cipherSuites: List<Int>,
    val groups: List<Int>,
    val signatureAlgorithms: List<Int>,
    val versions: List<Int>,
    val keyShares: List<Int>,
    val serverName: String?,
) {
    fun fields() = listOf(
        "versions" to versions.map { VERSIONS[it] ?: hex(it) },
        "groups" to groups.filterNot(::isGrease).map { GROUPS[it] ?: hex(it) },
        "keyshares" to keyShares.filterNot(::isGrease).map { GROUPS[it] ?: hex(it) },
        "ciphers" to cipherSuites.filterNot(::isGrease).map { CIPHERS[it] ?: hex(it) },
        "sigalgs" to signatureAlgorithms.filterNot(::isGrease).map { SIGNATURE_ALGORITHMS[it] ?: hex(it) },
    )

    companion object {
        @Suppress("NestedBlockDepth")
        fun parse(handshake: ByteArray): ClientHello {
            val buffer = java.nio.ByteBuffer.wrap(handshake)
            fun u8() = buffer.get().toInt() and 0xff
            fun u16() = buffer.short.toInt() and 0xffff
            fun skip(count: Int) = buffer.position(buffer.position() + count)
            fun u16List(bytes: Int) = List(bytes / 2) { u16() }

            check(u8() == 1) { "Not a ClientHello" }
            skip(3) // length
            val legacyVersion = u16()
            skip(32) // random
            skip(u8()) // session id
            val cipherSuites = u16List(u16())
            skip(u8()) // compression methods

            var groups = emptyList<Int>()
            var signatureAlgorithms = emptyList<Int>()
            var versions = listOf(legacyVersion)
            val keyShares = mutableListOf<Int>()
            var serverName: String? = null
            if (buffer.remaining() >= 2) {
                val end = u16() + buffer.position()
                while (buffer.position() + 4 <= end) {
                    val type = u16()
                    val length = u16()
                    val next = buffer.position() + length
                    when (type) {
                        0 -> {
                            skip(3) // list length, name type (host name)
                            serverName = String(ByteArray(u16()).also { buffer.get(it) })
                        }
                        10 -> groups = u16List(u16())
                        13 -> signatureAlgorithms = u16List(u16())
                        43 -> versions = u16List(u8())
                        51 -> {
                            val sharesEnd = u16() + buffer.position()
                            while (buffer.position() < sharesEnd) {
                                keyShares += u16()
                                skip(u16())
                            }
                        }
                    }
                    buffer.position(next)
                }
            }
            return ClientHello(cipherSuites, groups, signatureAlgorithms, versions.filterNot(::isGrease), keyShares, serverName)
        }

        private fun isGrease(value: Int) = value and 0x0f0f == 0x0a0a
        private fun hex(value: Int) = "0x%04x".format(value)

        val VERSIONS = mapOf(0x0304 to "TLS 1.3", 0x0303 to "TLS 1.2", 0x0302 to "TLS 1.1", 0x0301 to "TLS 1.0")

        val GROUPS = mapOf(
            0x0017 to "secp256r1", 0x0018 to "secp384r1", 0x0019 to "secp521r1", 0x001d to "x25519", 0x001e to "x448",
            0x0100 to "ffdhe2048", 0x0101 to "ffdhe3072",
            0x11ec to "X25519MLKEM768", 0x11eb to "SecP256r1MLKEM768", 0x11ed to "SecP384r1MLKEM1024",
            0x0201 to "MLKEM768", 0x0202 to "MLKEM1024", 0x6399 to "X25519Kyber768Draft00",
        )

        val CIPHERS = mapOf(
            0x1301 to "TLS_AES_128_GCM_SHA256", 0x1302 to "TLS_AES_256_GCM_SHA384", 0x1303 to "TLS_CHACHA20_POLY1305_SHA256",
            0xc02b to "ECDHE_ECDSA_AES_128_GCM", 0xc02c to "ECDHE_ECDSA_AES_256_GCM", 0xcca9 to "ECDHE_ECDSA_CHACHA20_POLY1305",
            0xc02f to "ECDHE_RSA_AES_128_GCM", 0xc030 to "ECDHE_RSA_AES_256_GCM", 0xcca8 to "ECDHE_RSA_CHACHA20_POLY1305",
            0xc009 to "ECDHE_ECDSA_AES_128_CBC", 0xc00a to "ECDHE_ECDSA_AES_256_CBC",
            0xc013 to "ECDHE_RSA_AES_128_CBC", 0xc014 to "ECDHE_RSA_AES_256_CBC",
            0xcc13 to "ECDHE_RSA_CHACHA20_POLY1305_OLD", 0xcc14 to "ECDHE_ECDSA_CHACHA20_POLY1305_OLD",
            0x009c to "RSA_AES_128_GCM", 0x009d to "RSA_AES_256_GCM", 0x002f to "RSA_AES_128_CBC", 0x0035 to "RSA_AES_256_CBC",
            0x000a to "RSA_3DES_EDE_CBC", 0x00ff to "EMPTY_RENEGOTIATION_INFO", 0x5600 to "FALLBACK_SCSV",
        )

        val SIGNATURE_ALGORITHMS = mapOf(
            0x0403 to "ecdsa_secp256r1_sha256", 0x0503 to "ecdsa_secp384r1_sha384", 0x0603 to "ecdsa_secp521r1_sha512",
            0x0804 to "rsa_pss_rsae_sha256", 0x0805 to "rsa_pss_rsae_sha384", 0x0806 to "rsa_pss_rsae_sha512",
            0x0809 to "rsa_pss_pss_sha256", 0x080a to "rsa_pss_pss_sha384", 0x080b to "rsa_pss_pss_sha512",
            0x0401 to "rsa_pkcs1_sha256", 0x0501 to "rsa_pkcs1_sha384", 0x0601 to "rsa_pkcs1_sha512",
            0x0201 to "rsa_pkcs1_sha1", 0x0203 to "ecdsa_sha1", 0x0807 to "ed25519", 0x0808 to "ed448",
            0x0904 to "mldsa44", 0x0905 to "mldsa65", 0x0906 to "mldsa87",
        )
    }
}
