package org.jellyfin.mobile.tls

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.Icon
import androidx.compose.material.IconButton
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Scaffold
import androidx.compose.material.Text
import androidx.compose.material.TextButton
import androidx.compose.material.TopAppBar
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.os.bundleOf
import kotlinx.coroutines.launch
import org.jellyfin.mobile.R
import org.jellyfin.mobile.ui.ComposeFragment

class CertificatesFragment : ComposeFragment() {
    @Composable
    override fun Content() {
        val endpoint = remember { requireNotNull(TlsEndpoint.fromUrl(requireArguments().getString(ARG_ADDRESS))) }
        CertificatesScreen(
            endpoint = endpoint,
            onBackPressed = {
                isAdded && !parentFragmentManager.isStateSaved && parentFragmentManager.popBackStackImmediate()
            },
        )
    }

    companion object {
        private const val ARG_ADDRESS = "address"

        fun arguments(address: String) = bundleOf(ARG_ADDRESS to address)
    }
}

/**
 * The CA certificates and the client certificate of [endpoint].
 */
@Suppress("LongMethod")
@Composable
fun CertificatesScreen(endpoint: TlsEndpoint, onBackPressed: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val model = remember(endpoint) { CertificatesScreenModel(context, endpoint) }
    var picking by remember { mutableStateOf(CertificateKind.CA) }
    val picker = rememberLauncherForActivityResult(PickFile()) { uri ->
        if (uri != null) scope.launch { model.import(picking, CertificateSource.File(uri)) }
    }
    val import = { kind: CertificateKind ->
        picking = kind
        if (!context.launchFilePicker(picker)) scope.launch { model.importFromUrl(kind) }
    }

    LaunchedEffect(model) { model.refresh() }
    CertificatePromptDialogs(model.prompts)

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(text = stringResource(R.string.tls_certificates_title, endpoint.display)) },
                navigationIcon = {
                    IconButton(onClick = onBackPressed) {
                        Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = null)
                    }
                },
            )
        },
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
        ) {
            SectionTitle(stringResource(R.string.tls_ca_section))
            Text(
                text = stringResource(R.string.tls_ca_system_info, endpoint.display),
                style = MaterialTheme.typography.body2
            )
            if (model.cas.isEmpty()) {
                Text(
                    text = stringResource(R.string.tls_ca_none),
                    modifier = Modifier.padding(top = 8.dp)
                )
            }
            model.cas.forEach { certificate ->
                CertificateItem(model.caText(certificate)) { scope.launch { model.removeCa(certificate) } }
            }
            TextButton(onClick = { import(CertificateKind.CA) }) {
                Text(text = stringResource(R.string.tls_ca_import))
            }

            SectionTitle(stringResource(R.string.tls_client_section))
            if (model.clientRequested) {
                Text(
                    text = stringResource(R.string.tls_client_requested),
                    style = MaterialTheme.typography.body2
                )
            }
            model.client?.let { client ->
                if (client.config == ClientCertificate.None) {
                    Text(text = model.clientText(client), modifier = Modifier.padding(top = 8.dp))
                } else {
                    CertificateItem(model.clientText(client)) { scope.launch { model.removeClient(client) } }
                }
            }
            TextButton(onClick = { import(CertificateKind.CLIENT) }) {
                Text(text = stringResource(R.string.tls_client_import))
            }
            if (model.systemStoreAvailable) {
                TextButton(onClick = { context.findActivity()?.let { scope.launch { model.chooseSystem(it) } } }) {
                    Text(text = stringResource(R.string.tls_client_choose_system))
                }
            }

            TextButton(onClick = { scope.launch { model.importFromUrl() } }, modifier = Modifier.padding(top = 16.dp)) {
                Text(text = stringResource(R.string.tls_import_from_url))
            }
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(text = text, style = MaterialTheme.typography.h6, modifier = Modifier.padding(top = 24.dp, bottom = 8.dp))
}

@Composable
private fun CertificateItem(text: String, onClick: () -> Unit) {
    Text(
        text = text,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 12.dp),
    )
}
