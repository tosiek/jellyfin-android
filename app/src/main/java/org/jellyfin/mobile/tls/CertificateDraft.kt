package org.jellyfin.mobile.tls

import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

data class StagedCa(val name: String, val certificates: List<X509Certificate>)

/**
 * A client key loaded from a file or URL, imported into the app on apply, or a key from the system store
 * ([systemAlias]), which is only referenced.
 */
data class StagedClient(
    val name: String,
    val key: ClientKey,
    val systemAlias: String? = null,
    /** CA certificates contained in the file, see [CertificateDraft.untrustedCas]. */
    val caCertificates: List<X509Certificate> = emptyList(),
)

/**
 * Certificates selected on the connect screen. They are only applied for the connection check and kept when the check
 * succeeds, otherwise the previous configuration of the endpoint is restored.
 */
class CertificateDraft(private val tls: TlsManager) {
    var stagedCa: StagedCa? = null
        private set
    var stagedClient: StagedClient? = null
        private set
    private var removeCa = false
    private var removeClient = false

    val hasChanges get() = stagedCa != null || stagedClient != null || removeCa || removeClient

    fun stageCa(ca: StagedCa) {
        stagedCa = ca
        removeCa = false
    }

    fun stageClient(client: StagedClient) {
        stagedClient = client
        removeClient = false
    }

    fun removeCa() {
        stagedCa = null
        removeCa = true
    }

    fun removeClient() {
        stagedClient = null
        removeClient = true
    }

    /**
     * The certificates of [certificates] that are neither staged nor trusted for [endpoint] as CA certificates.
     */
    fun untrustedCas(endpoint: TlsEndpoint?, certificates: List<X509Certificate>): List<X509Certificate> {
        val known = currentCas(endpoint).map { it.sha256() }.toSet()
        return certificates.filter { it.sha256() !in known }
    }

    /**
     * Adds CA certificates contained in the client certificate file [fileName] to the CA certificates of [endpoint]
     * (the staged ones or the trusted ones, which stay trusted). The CA row shows the file like one picked there.
     */
    fun stageContainedCas(endpoint: TlsEndpoint?, fileName: String, certificates: List<X509Certificate>) {
        stageCa(StagedCa(stagedCa?.let { "${it.name}, $fileName" } ?: fileName, currentCas(endpoint) + certificates))
    }

    /**
     * Whether [certificate] is the staged client certificate or the configured one of [endpoint]. Must not be called
     * on the main thread (KeyChain access).
     */
    fun isCurrentClient(endpoint: TlsEndpoint?, certificate: X509Certificate): Boolean {
        val fingerprint = certificate.sha256()
        stagedClient?.let { return it.key.chain.first().sha256() == fingerprint }
        if (removeClient || endpoint == null) return false
        val configured = tls.getConfig(endpoint).clientCertificate
        if (configured == ClientCertificate.None) return false
        return tls.clientKeyStore.load(configured)?.chain?.firstOrNull()?.sha256() == fingerprint
    }

    private fun currentCas(endpoint: TlsEndpoint?): List<X509Certificate> = stagedCa?.certificates ?: when {
        removeCa || endpoint == null -> emptyList()
        else -> tls.store.getCertificates(endpoint)
    }

    fun caLabel(endpoint: TlsEndpoint?): CertificateLabel? {
        stagedCa?.let { return CertificateLabel(it.name, isNew = true) }
        if (removeCa || endpoint == null) return null
        val certificates = tls.store.getCertificates(endpoint)
        if (certificates.isEmpty()) return null
        val name = certificates.first().commonName() + if (certificates.size > 1) " +${certificates.size - 1}" else ""
        return CertificateLabel(name, isNew = false)
    }

    /**
     * Must not be called on the main thread (KeyChain access).
     */
    fun clientLabel(endpoint: TlsEndpoint?): CertificateLabel? {
        stagedClient?.let { return CertificateLabel(it.name, isNew = true) }
        if (removeClient || endpoint == null) return null
        val certificate = tls.getConfig(endpoint).clientCertificate
        if (certificate == ClientCertificate.None) return null
        tls.clientKeyStore.load(certificate)?.chain?.firstOrNull()?.commonName()?.let {
            return CertificateLabel(it, isNew = false)
        }
        // The key is gone (removed from the system store, app data restored elsewhere): the alias of a system key is
        // the name the user chose, an imported key only has an internal alias
        return CertificateLabel((certificate as? ClientCertificate.System)?.alias, isNew = false, unavailable = true)
    }

    /**
     * Apply the staged changes to [endpoint] for a connection check. Must not be called on the main thread.
     * Returns null when there are no changes.
     */
    fun apply(endpoint: TlsEndpoint): Applied? {
        if (!hasChanges) return null
        val previous = tls.getConfig(endpoint)

        val caFingerprints = when {
            stagedCa != null -> stagedCa!!.certificates.map(tls.store::addCertificate)
            removeCa -> emptyList()
            else -> previous.caFingerprints
        }

        val staged = stagedClient
        var imported: ClientCertificate.Imported? = null
        val clientCertificate = when {
            staged?.systemAlias != null -> ClientCertificate.System(staged.systemAlias)
            staged != null -> try {
                tls.clientKeyStore.import(staged.key).also { imported = it }
            } catch (err: ClientKeyStore.KeyUnusableException) {
                throw ImportException(ImportError.KeyUnusable, err)
            }

            removeClient -> ClientCertificate.None
            else -> previous.clientCertificate
        }

        // Store directly, TlsManager.setConfig would delete the previous key which is needed for a revert
        tls.store.set(endpoint, TlsServerConfig(caFingerprints, clientCertificate))
        tls.onConfigChanged()
        return Applied(endpoint, previous, imported)
    }

    /**
     * The connection check failed, restore the previous configuration. The staged certificates stay selected.
     */
    fun revert(applied: Applied) {
        tls.store.set(applied.endpoint, applied.previous)
        applied.imported?.let(tls.clientKeyStore::delete)
        tls.onConfigChanged()
    }

    /**
     * The connection check succeeded, keep the configuration and clear the draft.
     */
    fun commit(applied: Applied) {
        val previous = applied.previous.clientCertificate
        val current = tls.getConfig(applied.endpoint).clientCertificate
        val stillUsed = tls.store.endpoints.any { tls.store.get(it).clientCertificate == previous }
        if (previous != current && !stillUsed) tls.clientKeyStore.delete(previous)
        stagedCa = null
        stagedClient = null
        removeCa = false
        removeClient = false
    }

    class Applied internal constructor(
        val endpoint: TlsEndpoint,
        val previous: TlsServerConfig,
        val imported: ClientCertificate.Imported?,
    )
}

/**
 * Label of a certificate in the connect screen. [name] is null for an unavailable imported key, [unavailable] when the
 * configured key can not be loaded anymore.
 */
data class CertificateLabel(val name: String?, val isNew: Boolean, val unavailable: Boolean = false)

fun X509Certificate.commonName(): String = subjectX500Principal.getName(X500Principal.RFC2253)
    .split(',')
    .firstOrNull { it.trim().startsWith("CN=", ignoreCase = true) }
    ?.substringAfter('=')
    ?: subjectX500Principal.name
