package org.jellyfin.mobile.tls

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.jellyfin.mobile.tls.TlsFixtures.PASSWORD
import org.jellyfin.mobile.tls.TlsFixtures.read

class CertificateDraftTests : FunSpec({
    val endpoint = requireNotNull(TlsEndpoint.fromKey("jf.example.com_8920"))
    val ca = CertificateImporter.parseCertificates(read("ca/single.pem")).certificates
    val clientKey = CertificateImporter.parsePkcs12(read("client/ec256-3des.p12"), PASSWORD.toCharArray()).key
    val oldClient = ClientCertificate.Imported("old", ClientCertificate.Imported.Storage.KEYSTORE)
    val newClient = ClientCertificate.Imported("new", ClientCertificate.Imported.Storage.KEYSTORE)

    fun tls(
        initial: TlsServerConfig,
        otherEndpointUsesOld: Boolean = false,
    ): Triple<TlsManager, MutableMap<String, TlsServerConfig>, ClientKeyStore> {
        val configs = mutableMapOf(endpoint.key to initial)
        if (otherEndpointUsesOld) configs["other_443"] = TlsServerConfig(clientCertificate = oldClient)
        val store = mockk<TlsStore>(relaxed = true)
        val config = slot<TlsServerConfig>()
        val key = slot<TlsEndpoint>()
        every { store.get(any()) } answers { configs[firstArg<TlsEndpoint>().key] ?: TlsServerConfig() }
        every { store.set(capture(key), capture(config)) } answers { configs[key.captured.key] = config.captured }
        every { store.endpoints } answers { configs.keys.mapNotNull(TlsEndpoint::fromKey) }
        every { store.getCertificates(any()) } returns emptyList()
        every { store.addCertificate(any()) } answers { firstArg<java.security.cert.X509Certificate>().sha256() }
        val clientKeyStore = mockk<ClientKeyStore>(relaxed = true)
        every { clientKeyStore.import(any()) } returns newClient
        val tls = mockk<TlsManager>(relaxed = true)
        every { tls.store } returns store
        every { tls.clientKeyStore } returns clientKeyStore
        every { tls.getConfig(any()) } answers { store.get(firstArg()) }
        return Triple(tls, configs, clientKeyStore)
    }

    test("CA certificates of a client file are staged with the staged CA, then known") {
        val (tls) = tls(TlsServerConfig())
        val draft = CertificateDraft(tls)
        val contained = CertificateImporter
            .parsePkcs12(read("client/rsa2048-empty-password.p12"), CharArray(0))
            .caCertificates
        draft.untrustedCas(endpoint, contained) shouldBe contained
        draft.stageCa(StagedCa("ca.pem", ca))
        draft.stageContainedCas(endpoint, "client.p12", contained)
        draft.stagedCa?.certificates shouldBe ca + contained
        draft.caLabel(endpoint)?.name shouldBe "ca.pem, client.p12"
        draft.untrustedCas(endpoint, contained) shouldBe emptyList()
    }

    test("CA certificates of a client file keep the trusted ones") {
        val (tls) = tls(TlsServerConfig())
        every { tls.store.getCertificates(endpoint) } returns ca
        val draft = CertificateDraft(tls)
        val contained = CertificateImporter
            .parsePkcs12(read("client/rsa2048-empty-password.p12"), CharArray(0))
            .caCertificates
        draft.untrustedCas(endpoint, ca) shouldBe emptyList()
        draft.stageContainedCas(endpoint, "client.p12", contained)
        draft.stagedCa?.certificates shouldBe ca + contained
        draft.caLabel(endpoint)?.name shouldBe "client.p12"
    }

    test("the staged or configured client certificate is the current one") {
        val (tls, _, clientKeyStore) = tls(TlsServerConfig(clientCertificate = oldClient))
        val other = CertificateImporter.parsePkcs12(read("client/rsa2048-empty-password.p12"), CharArray(0)).key
        every { clientKeyStore.load(oldClient) } returns clientKey
        val draft = CertificateDraft(tls)
        draft.isCurrentClient(endpoint, clientKey.chain.first()) shouldBe true
        draft.isCurrentClient(endpoint, other.chain.first()) shouldBe false
        draft.stageClient(StagedClient("other.p12", other))
        draft.isCurrentClient(endpoint, other.chain.first()) shouldBe true
        draft.isCurrentClient(endpoint, clientKey.chain.first()) shouldBe false
    }

    test("no changes apply nothing") {
        val (tls, _, keys) = tls(TlsServerConfig())
        CertificateDraft(tls).apply(endpoint).shouldBeNull()
    }

    test("a client key that can not be loaded anymore is labeled unavailable") {
        val system = ClientCertificate.System("client-ec")
        val (tls, configs, keys) = tls(TlsServerConfig(clientCertificate = system))
        every { keys.load(any()) } returns null
        CertificateDraft(tls).clientLabel(endpoint) shouldBe
            CertificateLabel("client-ec", isNew = false, unavailable = true)

        // Imported keys only have an internal alias, the screen names them generically
        configs[endpoint.key] = TlsServerConfig(clientCertificate = oldClient)
        CertificateDraft(tls).clientLabel(endpoint) shouldBe CertificateLabel(null, isNew = false, unavailable = true)
    }

    test("staged certificates are applied for the check") {
        val (tls, configs, keys) = tls(TlsServerConfig(clientCertificate = oldClient))
        val draft = CertificateDraft(tls)
        draft.stageCa(StagedCa("ca.pem", ca))
        draft.stageClient(StagedClient("client.p12", clientKey))
        draft.caLabel(endpoint) shouldBe CertificateLabel("ca.pem", isNew = true)

        draft.apply(endpoint)
        configs[endpoint.key] shouldBe TlsServerConfig(ca.map { it.sha256() }, newClient)
        verify { tls.onConfigChanged() }
    }

    test("failed check restores the previous configuration and keeps the selection") {
        val previous = TlsServerConfig(clientCertificate = oldClient)
        val (tls, configs, keys) = tls(previous)
        val draft = CertificateDraft(tls)
        draft.stageClient(StagedClient("client.p12", clientKey))

        draft.revert(draft.apply(endpoint)!!)
        configs[endpoint.key] shouldBe previous
        verify { keys.delete(newClient) }
        verify(exactly = 0) { keys.delete(oldClient) }
        draft.hasChanges shouldBe true
    }

    test("successful check keeps the configuration and deletes the replaced key") {
        val (tls, configs, keys) = tls(TlsServerConfig(clientCertificate = oldClient))
        val draft = CertificateDraft(tls)
        draft.stageClient(StagedClient("client.p12", clientKey))

        draft.commit(draft.apply(endpoint)!!)
        configs[endpoint.key]!!.clientCertificate shouldBe newClient
        verify { keys.delete(oldClient) }
        draft.hasChanges shouldBe false
    }

    test("replaced key used by another server is kept") {
        val (tls, _, keys) = tls(TlsServerConfig(clientCertificate = oldClient), otherEndpointUsesOld = true)
        val draft = CertificateDraft(tls)
        draft.stageClient(StagedClient("client.p12", clientKey))

        draft.commit(draft.apply(endpoint)!!)
        verify(exactly = 0) { keys.delete(oldClient) }
    }

    test("removing certificates") {
        val (tls, configs, keys) = tls(TlsServerConfig(listOf("abc"), oldClient))
        val draft = CertificateDraft(tls)
        draft.removeCa()
        draft.removeClient()
        draft.caLabel(endpoint).shouldBeNull()

        draft.commit(draft.apply(endpoint)!!)
        configs[endpoint.key] shouldBe TlsServerConfig()
        verify { keys.delete(oldClient) }
    }

    test("common name is used as label") {
        ca.first().commonName() shouldBe "Fixture Root CA"
    }
})
