package org.jellyfin.mobile.tls

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.mockk.every
import io.mockk.mockk
import org.jellyfin.mobile.tls.TlsFixtures.PASSWORD
import org.jellyfin.mobile.tls.TlsFixtures.read
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

private fun loadChain(file: String): Array<X509Certificate> {
    val keyStore = KeyStore.getInstance("PKCS12")
    keyStore.load(ByteArrayInputStream(read(file)), PASSWORD.toCharArray())
    return keyStore.getCertificateChain("server").map { it as X509Certificate }.toTypedArray()
}

private fun loadCertificate(file: String) =
    CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(read(file))) as X509Certificate

private fun endpoint(key: String) = requireNotNull(TlsEndpoint.fromKey(key))

private val localhost = endpoint("localhost_8920")

class HostAwareManagersTests : FunSpec({
    val root = loadCertificate("ca/single.pem")
    val other = loadCertificate("ca/other.pem")
    val serverChain = loadChain("server/server.p12")
    val expiredChain = loadChain("server/server-expired.p12")

    fun trustManager(vararg configs: Pair<String, X509Certificate>): HostAwareTrustManager {
        val store = mockk<TlsStore> {
            every { getCertificates(any()) } answers {
                val endpoint = firstArg<TlsEndpoint>()
                configs.filter { it.first == endpoint.key }.map { it.second }
            }
            every { getAllCertificates() } returns configs.map { it.second }
        }
        return HostAwareTrustManager(store)
    }

    context("trust") {
        test("untrusted server without configuration fails and records the failure") {
            val tm = trustManager()
            shouldThrow<CertificateException> { tm.forEndpoint(localhost).checkServerTrusted(serverChain, "RSA") }
            tm.getLastFailure(localhost).shouldNotBeNull()
        }

        test("imported CA of the endpoint is trusted") {
            val tm = trustManager("localhost_8920" to root)
            tm.forEndpoint(localhost).checkServerTrusted(serverChain, "RSA")
            tm.getLastFailure(localhost).shouldBeNull()
            tm.getValidatedLeaf(localhost) shouldBe serverChain.first().sha256()
        }

        test("CA of another port is not applied") {
            val tm = trustManager("localhost_443" to root)
            shouldThrow<CertificateException> { tm.forEndpoint(localhost).checkServerTrusted(serverChain, "RSA") }
        }

        test("CA of another host literal is not applied") {
            val tm = trustManager("127.0.0.1_8920" to root)
            shouldThrow<CertificateException> { tm.forEndpoint(localhost).checkServerTrusted(serverChain, "RSA") }
        }

        test("unrelated CA is rejected") {
            val tm = trustManager("localhost_8920" to other)
            shouldThrow<CertificateException> { tm.forEndpoint(localhost).checkServerTrusted(serverChain, "RSA") }
        }

        test("expired server certificate is diagnosed as expired") {
            val tm = trustManager("localhost_8920" to root)
            shouldThrow<CertificateException> { tm.forEndpoint(localhost).checkServerTrusted(expiredChain, "RSA") }
            val keyManager = HostAwareKeyManager(mockk(), mockk())
            TlsDiagnostics.diagnose(tm, keyManager, { false }, localhost, null)
                .shouldBeInstanceOf<TlsProblem.Expired>()
        }

        test("untrusted server is diagnosed with its issuer") {
            val tm = trustManager()
            runCatching { tm.forEndpoint(localhost).checkServerTrusted(serverChain, "RSA") }
            val problem = TlsDiagnostics.diagnose(tm, HostAwareKeyManager(mockk(), mockk()), { false }, localhost, null)
            val issuer = problem.shouldBeInstanceOf<TlsProblem.Untrusted>().issuer
            issuer!!.contains("Fixture Intermediate CA") shouldBe true
        }

        test("accepted issuers include imported CAs") {
            trustManager("localhost_8920" to root).acceptedIssuers.toList() shouldContain root
            trustManager("localhost_8920" to root).forEndpoint(localhost).acceptedIssuers.toList() shouldContain root
        }

        test("without endpoint only the platform is trusted") {
            val trustManager = trustManager("localhost_8920" to root)
            shouldThrow<CertificateException> { trustManager.checkServerTrusted(serverChain, "RSA") }
        }
    }

    context("client certificate") {
        val clientKey = CertificateImporter.parsePkcs12(read("client/ec256-3des.p12"), PASSWORD.toCharArray()).key
        val imported = ClientCertificate.Imported("alias", ClientCertificate.Imported.Storage.KEYSTORE)

        fun keyManager(config: Map<String, ClientCertificate>, available: Boolean = true): HostAwareKeyManager {
            val store = mockk<TlsStore>()
            every { store.get(any()) } answers {
                TlsServerConfig(clientCertificate = config[firstArg<TlsEndpoint>().key] ?: ClientCertificate.None)
            }
            val clientKeyStore = mockk<ClientKeyStore> {
                every { load(ClientCertificate.None) } returns null
                every { load(imported) } returns if (available) clientKey else null
            }
            return HostAwareKeyManager(store, clientKeyStore)
        }

        test("configured endpoint presents its key") {
            val km = keyManager(mapOf("localhost_8920" to imported))
            val alias = km.forEndpoint(localhost).chooseClientAlias(arrayOf("EC"), null, null)
            alias shouldBe "localhost_8920"
            val endpointKeyManager = km.forEndpoint(localhost)
            endpointKeyManager.getPrivateKey(alias) shouldBe clientKey.privateKey
            endpointKeyManager.getCertificateChain(alias)!!.first() shouldBe clientKey.chain.first()
            // The alias of another endpoint never resolves
            km.forEndpoint(endpoint("localhost_443")).getPrivateKey(alias).shouldBeNull()
        }

        test("other port or host literal presents nothing") {
            val km = keyManager(mapOf("localhost_8920" to imported))
            km.forEndpoint(endpoint("localhost_443")).chooseClientAlias(arrayOf("EC"), null, null).shouldBeNull()
            km.forEndpoint(endpoint("127.0.0.1_8920")).chooseClientAlias(arrayOf("EC"), null, null).shouldBeNull()
        }

        test("request without configuration is diagnosed as required") {
            val km = keyManager(emptyMap())
            km.forEndpoint(localhost).chooseClientAlias(arrayOf("EC"), null, null).shouldBeNull()
            TlsDiagnostics.diagnose(trustManager(), km, { false }, localhost, null) shouldBe
                TlsProblem.ClientCertificateRequired
        }

        test("unavailable key is diagnosed as unavailable") {
            val km = keyManager(mapOf("localhost_8920" to imported), available = false)
            km.forEndpoint(localhost).chooseClientAlias(arrayOf("EC"), null, null).shouldBeNull()
            TlsDiagnostics.diagnose(trustManager(), km, { true }, localhost, null) shouldBe
                TlsProblem.ClientCertificateUnavailable
        }

        test("rejected certificate is diagnosed from the alert") {
            val km = keyManager(mapOf("localhost_8920" to imported))
            km.forEndpoint(localhost).chooseClientAlias(arrayOf("EC"), null, null)
            val error = javax.net.ssl.SSLHandshakeException("Received fatal alert: bad_certificate")
            TlsDiagnostics.diagnose(trustManager(), km, { true }, localhost, error) shouldBe
                TlsProblem.ClientCertificateRejected
        }
    }
})
