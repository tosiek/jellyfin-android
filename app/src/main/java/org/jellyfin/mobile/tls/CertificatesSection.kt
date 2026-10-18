@file:Suppress("MatchingDeclarationName")

package org.jellyfin.mobile.tls

import android.content.Context
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.ActivityResultLauncher
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.material.Checkbox
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.jellyfin.mobile.R
import java.util.concurrent.TimeUnit

/**
 * State of the "Advanced" section of the connect screen, see [ServerCertificates].
 */
@Stable
class CertificatesSectionState internal constructor(
    context: Context,
    scope: CoroutineScope,
    endpointOf: () -> TlsEndpoint?,
) {
    var version by mutableIntStateOf(0)
        private set
    var expanded by mutableStateOf(false)
    var loadFromUrl by mutableStateOf(!context.hasFilePicker())
    internal lateinit var picker: ActivityResultLauncher<FilePicker>

    val prompts = PromptState()
    val certificates =
        ServerCertificates(requireNotNull(context.findActivity()), scope, prompts, endpointOf) { version++ }

    // Not when the store can not hold keys: Android would only ask to set a lock screen
    private val offerSystemStore = certificates.systemStoreAvailable && context.canHoldSystemKeys()

    suspend fun apply(): String? = certificates.apply()

    fun onConnected() = certificates.onConnected()

    /**
     * After a failed connection check. When the server asked for a client certificate and none is configured, the
     * system store is offered like a browser does and [retry] checks again with the chosen one.
     */
    fun onFailed(retry: () -> Unit) {
        val clientRequired = certificates.onFailed()
        if (certificates.endpoint != null) expanded = true
        if (clientRequired && offerSystemStore) certificates.chooseSystem(retry)
    }
}

@Composable
fun rememberCertificatesSectionState(endpointOf: () -> TlsEndpoint?): CertificatesSectionState {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val state = remember { CertificatesSectionState(context, scope, endpointOf) }
    state.picker = rememberLauncherForActivityResult(PickFile(), state.certificates::onFilePicked)
    return state
}

/**
 * TLS reason why [address] can not be reached, null when the connection works or fails for another reason. The WebView
 * does not report why it failed, a request with the TLS configuration of the app records it.
 */
suspend fun describeTlsProblem(context: Context, address: String): String? = withContext(Dispatchers.IO) {
    val client = TlsManager.get(context).okHttpClient.newBuilder()
        .callTimeout(TLS_CHECK_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .build()
    val error = runCatching {
        val request = Request.Builder().url("${address.trimEnd('/')}/System/Info/Public").build()
        client.newCall(request).execute().close()
    }.exceptionOrNull() ?: return@withContext null
    TlsMessages.describe(context, address, error)
}

private const val TLS_CHECK_TIMEOUT_SECONDS = 10L

@Composable
fun CertificatesSection(state: CertificatesSectionState) {
    val certificates = state.certificates
    val endpoint = certificates.endpoint
    val httpsAvailable = endpoint != null
    val ca = remember(endpoint, state.version) { certificates.caLabel() }
    val client by produceState<CertificateLabel?>(null, endpoint, state.version) { value = certificates.clientLabel() }
    val onChoose: (CertificateKind) -> Unit = { kind ->
        if (certificates.choose(kind, state.loadFromUrl, state.picker)) state.loadFromUrl = true
    }

    CertificatePromptDialogs(state.prompts)

    Column {
        TextButton(onClick = { state.expanded = !state.expanded }) {
            Text(text = stringResource(R.string.tls_advanced) + if (state.expanded) " ▲" else " ▼")
        }
        AnimatedVisibility(visible = state.expanded) {
            Column(modifier = Modifier.padding(horizontal = 8.dp)) {
                if (!httpsAvailable) {
                    Text(text = stringResource(R.string.tls_https_only), style = MaterialTheme.typography.body2)
                }
                Row(
                    modifier = Modifier.clickable(enabled = httpsAvailable) { state.loadFromUrl = !state.loadFromUrl },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(
                        checked = state.loadFromUrl,
                        onCheckedChange = { state.loadFromUrl = it },
                        enabled = httpsAvailable
                    )
                    Text(text = stringResource(R.string.tls_load_from_url))
                }
                CertificateRow(
                    R.string.tls_ca_certificate,
                    ca,
                    httpsAvailable,
                    CertificateKind.CA,
                    onChoose,
                    certificates::remove
                )
                CertificateRow(
                    R.string.tls_client_certificate,
                    client,
                    httpsAvailable,
                    CertificateKind.CLIENT,
                    onChoose,
                    certificates::remove,
                    onChooseSystem = { certificates.chooseSystem() }.takeIf { certificates.systemStoreAvailable },
                )
            }
        }
    }
}

@Suppress("LongParameterList")
@Composable
private fun CertificateRow(
    title: Int,
    label: CertificateLabel?,
    enabled: Boolean,
    kind: CertificateKind,
    onChoose: (CertificateKind) -> Unit,
    onRemove: (CertificateKind) -> Unit,
    onChooseSystem: (() -> Unit)? = null,
) {
    Column(modifier = Modifier.padding(top = 8.dp)) {
        Text(text = stringResource(title), style = MaterialTheme.typography.subtitle1)
        Text(
            text = when {
                label == null -> stringResource(R.string.tls_none)
                label.isNew -> "${label.name} ${stringResource(R.string.tls_new)}"
                label.unavailable -> "${label.name ?: stringResource(R.string.tls_client_imported_key)} " +
                    stringResource(R.string.tls_unavailable)
                else -> label.name.orEmpty()
            },
            style = MaterialTheme.typography.body2,
        )
        Row {
            TextButton(onClick = { onChoose(kind) }, enabled = enabled) {
                Text(text = stringResource(R.string.tls_choose))
            }
            if (label != null) {
                TextButton(onClick = { onRemove(kind) }) {
                    Text(text = stringResource(R.string.tls_remove))
                }
            }
        }
        // Own line, does not fit next to the other buttons on narrow screens
        if (onChooseSystem != null) {
            TextButton(onClick = onChooseSystem, enabled = enabled) {
                Text(text = stringResource(R.string.tls_client_choose_system))
            }
        }
    }
}
