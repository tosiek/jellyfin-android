package org.jellyfin.mobile.tls

import android.app.Activity
import android.content.Context
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.jellyfin.mobile.R
import java.security.cert.X509Certificate
import java.text.DateFormat

/**
 * The CA certificates and the client certificate of [endpoint] on the certificates screen. Changes are saved right
 * away, after the user confirmed them in [prompts].
 */
@Stable
// Characters of the SHA-256 fingerprint shown in a list entry
private const val FINGERPRINT_PREFIX_LENGTH = 16

@Suppress("TooManyFunctions")
class CertificatesScreenModel(private val context: Context, val endpoint: TlsEndpoint) {
    private val tls = TlsManager.get(context)
    val prompts = PromptState()
    private val loader = CertificateLoader(context, prompts)

    /**
     * [certificate] is null when there is no client certificate or its key is no longer available.
     */
    data class Client(val config: ClientCertificate, val certificate: X509Certificate?)

    var cas by mutableStateOf(emptyList<X509Certificate>())
        private set

    /**
     * Null while it is loaded.
     */
    var client by mutableStateOf<Client?>(null)
        private set

    var clientRequested by mutableStateOf(false)
        private set

    val systemStoreAvailable = context.hasKeyChainChooser()

    suspend fun refresh() {
        cas = tls.store.getCertificates(endpoint)
        clientRequested = tls.keyManager.getLastRequest(endpoint) != null
        val config = tls.getConfig(endpoint).clientCertificate
        val certificate = if (config == ClientCertificate.None) {
            null
        } else {
            withContext(Dispatchers.IO) { tls.clientKeyStore.load(config)?.chain?.firstOrNull() }
        }
        client = Client(config, certificate)
    }

    suspend fun import(kind: CertificateKind, source: CertificateSource) = when (kind) {
        CertificateKind.CA -> importCa(source)
        CertificateKind.CLIENT -> importClient(source)
    }

    /**
     * Asks for the URL, and for the kind of certificate when [kind] is null.
     */
    suspend fun importFromUrl(kind: CertificateKind? = null) {
        val chosen = kind ?: prompts.choose(
            context.getString(R.string.tls_import_from_url),
            listOf(context.getString(R.string.tls_ca_import), context.getString(R.string.tls_client_import)),
        )?.let(CertificateKind.entries::get) ?: return
        val url = prompts.url() ?: return
        import(chosen, CertificateSource.Url(url))
    }

    private suspend fun importCa(source: CertificateSource) {
        val loaded = loader.loadCa(source) ?: return
        val confirmed = prompts.confirm(
            Confirmation(
                title = context.getString(R.string.tls_ca_import),
                message = loaded.ca.certificates.joinToString("\n\n", transform = ::details),
                confirm = context.getString(R.string.tls_trust),
                dismiss = context.getString(android.R.string.cancel),
            ),
        )
        if (!confirmed) return
        trust(loaded.ca.certificates)
        val current = client?.certificate?.sha256()
        val contained = loader.offerContainedClient(loaded) { it.sha256() == current } ?: return
        useClient(contained)
    }

    private suspend fun importClient(source: CertificateSource) {
        val staged = loader.loadClient(source) ?: return
        val confirmed = prompts.confirm(
            Confirmation(
                title = context.getString(R.string.tls_client_import),
                message = details(staged.key.chain.first()),
                confirm = context.getString(R.string.tls_use),
                dismiss = context.getString(android.R.string.cancel),
            ),
        )
        if (confirmed) useClient(staged)
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun useClient(staged: StagedClient) {
        val certificate = try {
            withContext(Dispatchers.IO) { tls.clientKeyStore.import(staged.key) }
        } catch (_: ClientKeyStore.KeyUnusableException) {
            prompts.message(TlsMessages.describe(context, ImportError.KeyUnusable))
            return
        } catch (err: ImportException) {
            prompts.message(TlsMessages.describe(context, err.error))
            return
        } catch (err: Exception) {
            prompts.message(err.message ?: err.javaClass.simpleName)
            return
        }
        tls.setConfig(endpoint, tls.getConfig(endpoint).copy(clientCertificate = certificate))
        refresh()
        val trusted = cas.map { it.sha256() }.toSet()
        val contained = staged.caCertificates.filter { it.sha256() !in trusted }
        if (loader.offerContainedCas(endpoint, contained)) trust(contained)
    }

    suspend fun chooseSystem(activity: Activity) {
        val staged = loader.chooseSystemClient(activity, endpoint) ?: return
        val alias = staged.systemAlias ?: return
        tls.setConfig(endpoint, tls.getConfig(endpoint).copy(clientCertificate = ClientCertificate.System(alias)))
        refresh()
    }

    suspend fun removeCa(certificate: X509Certificate) {
        val confirmed = prompts.confirm(
            Confirmation(
                title = certificate.subjectX500Principal.name,
                message = details(certificate) + "\n\n" +
                    context.getString(R.string.tls_ca_remove_confirm, endpoint.display),
                confirm = context.getString(R.string.tls_remove),
                dismiss = context.getString(android.R.string.cancel),
                destructive = true,
            ),
        )
        if (!confirmed) return
        val config = tls.getConfig(endpoint)
        tls.setConfig(endpoint, config.copy(caFingerprints = config.caFingerprints - certificate.sha256()))
        refresh()
    }

    suspend fun removeClient(client: Client) {
        val question = context.getString(R.string.tls_client_remove_confirm, endpoint.display)
        val confirmed = prompts.confirm(
            Confirmation(
                title = client.certificate?.subjectX500Principal?.name
                    ?: context.getString(R.string.tls_client_section),
                message = client.certificate?.let { details(it) + "\n\n" + question } ?: question,
                confirm = context.getString(R.string.tls_remove),
                dismiss = context.getString(android.R.string.cancel),
                destructive = true,
            ),
        )
        if (!confirmed) return
        tls.setConfig(endpoint, tls.getConfig(endpoint).copy(clientCertificate = ClientCertificate.None))
        refresh()
    }

    private fun trust(certificates: List<X509Certificate>) {
        val config = tls.getConfig(endpoint)
        val fingerprints = certificates.map(tls.store::addCertificate)
        tls.setConfig(endpoint, config.copy(caFingerprints = (config.caFingerprints + fingerprints).distinct()))
        cas = tls.store.getCertificates(endpoint)
    }

    fun caText(certificate: X509Certificate): String = itemText(certificate.subjectX500Principal.name, certificate)

    fun clientText(client: Client): String {
        val certificate = client.certificate
        return when {
            client.config == ClientCertificate.None -> context.getString(R.string.tls_client_none)
            certificate == null -> describe(client.config, null) + " " + context.getString(R.string.tls_unavailable)
            else -> itemText(describe(client.config, certificate.subjectX500Principal.name), certificate)
        }
    }

    // Without subject (the key is gone): the alias of a system key, an imported key has only an internal alias
    private fun describe(config: ClientCertificate, subject: String?) = when (config) {
        ClientCertificate.None -> context.getString(R.string.tls_client_none)
        is ClientCertificate.System -> context.getString(R.string.tls_client_system, subject ?: config.alias)
        is ClientCertificate.Imported -> {
            val name = subject ?: context.getString(R.string.tls_client_imported_key)
            when (config.storage) {
                ClientCertificate.Imported.Storage.KEYSTORE -> context.getString(R.string.tls_client_imported, name)
                ClientCertificate.Imported.Storage.ENCRYPTED_FILE -> context.getString(
                    R.string.tls_client_imported_fallback,
                    name
                )
            }
        }
    }

    private fun itemText(name: String, certificate: X509Certificate) = context.getString(
        R.string.tls_ca_item,
        name,
        DateFormat.getDateInstance().format(certificate.notAfter),
        certificate.sha256().take(FINGERPRINT_PREFIX_LENGTH),
    )

    private fun details(certificate: X509Certificate): String {
        val format = DateFormat.getDateInstance()
        return context.getString(
            R.string.tls_certificate_details,
            certificate.subjectX500Principal.name,
            certificate.issuerX500Principal.name,
            format.format(certificate.notBefore),
            format.format(certificate.notAfter),
            certificate.sha256().chunked(2).joinToString(":"),
        )
    }
}
