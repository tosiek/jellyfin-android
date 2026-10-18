package org.jellyfin.mobile.tls

import android.app.Activity
import android.net.Uri
import androidx.activity.result.ActivityResultLauncher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Certificates selected for the entered server address in the "Advanced" section of the connect screen. The selection
 * is used for the connection check and only kept when it succeeds. [onChanged] is called after every change.
 */
class ServerCertificates(
    private val activity: Activity,
    private val scope: CoroutineScope,
    private val prompts: CertificatePrompts,
    private val endpointOf: () -> TlsEndpoint?,
    private val onChanged: () -> Unit,
) {
    private val tls = TlsManager.get(activity)
    private val draft = CertificateDraft(tls)
    private val loader = CertificateLoader(activity, prompts)
    private var applied: CertificateDraft.Applied? = null
    private var picking = CertificateKind.CA

    /**
     * Endpoint of the entered address, null for http.
     */
    val endpoint: TlsEndpoint? get() = endpointOf()

    val systemStoreAvailable = activity.hasKeyChainChooser()

    fun caLabel(): CertificateLabel? = draft.caLabel(endpoint)

    suspend fun clientLabel(): CertificateLabel? = withContext(Dispatchers.IO) { draft.clientLabel(endpoint) }

    /**
     * Choose a certificate file with [picker], or with a URL when [fromUrl] or no file picker can be started. Returns
     * true when a URL is asked for.
     */
    fun choose(kind: CertificateKind, fromUrl: Boolean, picker: ActivityResultLauncher<FilePicker>): Boolean {
        picking = kind
        if (!fromUrl && activity.launchFilePicker(picker)) return false
        scope.launch {
            val url = prompts.url() ?: return@launch
            load(kind, CertificateSource.Url(url))
        }
        return true
    }

    fun onFilePicked(uri: Uri?) {
        if (uri != null) scope.launch { load(picking, CertificateSource.File(uri)) }
    }

    fun chooseSystem(onChosen: () -> Unit = {}) {
        val endpoint = endpoint ?: return
        scope.launch {
            draft.stageClient(loader.chooseSystemClient(activity, endpoint) ?: return@launch)
            onChanged()
            onChosen()
        }
    }

    fun remove(kind: CertificateKind) {
        if (kind == CertificateKind.CA) draft.removeCa() else draft.removeClient()
        onChanged()
    }

    /**
     * Use the selection for the connection check. Returns the error when it can not be used.
     */
    suspend fun apply(): String? {
        val endpoint = endpoint ?: return null
        if (applied != null) return null
        applied = try {
            withContext(Dispatchers.IO) { draft.apply(endpoint) }
        } catch (err: ImportException) {
            return TlsMessages.describe(activity, err.error)
        }
        return null
    }

    fun onConnected() {
        applied?.let(draft::commit)
        applied = null
    }

    /**
     * Restore the previous certificates after a failed connection check, the selection is kept for another try.
     * Returns true when the server asked for a client certificate and none was configured.
     */
    fun onFailed(): Boolean {
        // Read before the revert, which clears the recorded requests
        val request = endpoint?.let(tls.keyManager::getLastRequest)
        applied?.let(draft::revert)
        applied = null
        onChanged()
        return request?.configured == false
    }

    private suspend fun load(kind: CertificateKind, source: CertificateSource) {
        when (kind) {
            CertificateKind.CA -> {
                val loaded = loader.loadCa(source) ?: return
                draft.stageCa(loaded.ca)
                onChanged()
                val client = loader.offerContainedClient(loaded) { draft.isCurrentClient(endpoint, it) } ?: return
                draft.stageClient(client)
                onChanged()
            }
            CertificateKind.CLIENT -> {
                val client = loader.loadClient(source) ?: return
                draft.stageClient(client)
                onChanged()
                val endpoint = endpoint ?: return
                val cas = draft.untrustedCas(endpoint, client.caCertificates)
                if (loader.offerContainedCas(endpoint, cas)) {
                    draft.stageContainedCas(endpoint, client.name, cas)
                    onChanged()
                }
            }
        }
    }
}
