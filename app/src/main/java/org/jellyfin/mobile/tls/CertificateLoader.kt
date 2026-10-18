package org.jellyfin.mobile.tls

import android.app.Activity
import android.app.KeyguardManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import android.security.KeyChain
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContract
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.jellyfin.mobile.R
import java.io.InputStream
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal
import kotlin.coroutines.resume

enum class CertificateKind { CA, CLIENT }

sealed interface CertificateSource {
    data class File(val uri: Uri) : CertificateSource
    data class Url(val url: String) : CertificateSource
}

/**
 * CA certificates read by [CertificateLoader.loadCa]. A .p12 / .pfx file can also contain client certificates, see
 * [CertificateLoader.offerContainedClient].
 */
class LoadedCa internal constructor(
    val ca: StagedCa,
    internal val pkcs12: Pkcs12File?,
)

internal class Pkcs12File(val name: String, val data: ByteArray, val password: CharArray, val keyAliases: List<String>)

/**
 * Reads CA and client certificates from a file or URL: validates them and asks for the password and which key to use
 * with [prompts]. Returns null when the user cancels or the file can not be used, the reason was shown already.
 */
class CertificateLoader(
    private val context: Context,
    private val prompts: CertificatePrompts,
) {
    private val tls = TlsManager.get(context)

    suspend fun loadCa(source: CertificateSource): LoadedCa? {
        val (name, data) = read(source) ?: return null
        val parsed = try {
            withContext(Dispatchers.IO) { CertificateImporter.parseCertificates(data) }
        } catch (err: ImportException) {
            if (err.error == ImportError.UnrecognizedFormat && CertificateImporter.mayBePkcs12(data)) {
                return loadPkcs12Cas(name, data)
            }
            prompts.message(TlsMessages.describe(context, err.error))
            return null
        }
        if (!confirmWarnings(parsed.warnings)) return null
        return LoadedCa(StagedCa(name, parsed.certificates), pkcs12 = null)
    }

    private suspend fun loadPkcs12Cas(name: String, data: ByteArray): LoadedCa? {
        var retry = false
        while (true) {
            val password = askPassword(name, retry) ?: return null
            try {
                val parsed = withContext(Dispatchers.IO) { CertificateImporter.parsePkcs12Cas(data, password) }
                return LoadedCa(
                    StagedCa(name, parsed.certificates),
                    Pkcs12File(name, data, password, parsed.keyAliases)
                )
            } catch (err: ImportException) {
                if (err.error != ImportError.WrongPassword) {
                    prompts.message(TlsMessages.describe(context, err.error))
                    return null
                }
                retry = true
            }
        }
    }

    /**
     * The client certificates in the file of [loaded] that are not [isCurrent]: asks whether to use one.
     */
    suspend fun offerContainedClient(loaded: LoadedCa, isCurrent: (X509Certificate) -> Boolean): StagedClient? {
        val file = loaded.pkcs12?.takeIf { it.keyAliases.isNotEmpty() } ?: return null
        val clients = withContext(Dispatchers.IO) {
            file.keyAliases
                .mapNotNull { alias ->
                    runCatching { CertificateImporter.parsePkcs12(file.data, file.password, alias) }.getOrNull()
                }
                .filterNot { isCurrent(it.key.chain.first()) }
        }
        val subjects = clients.map { it.key.chain.first().subjectX500Principal.name }
        val title = context.getString(R.string.tls_contained_client_title)
        val chosen = when (clients.size) {
            0 -> return null
            1 -> clients.single().takeIf {
                prompts.confirm(
                    Confirmation(
                        title = title,
                        message = context.getString(R.string.tls_contained_client_message, subjects.single()),
                        confirm = context.getString(R.string.tls_use),
                        dismiss = context.getString(R.string.tls_contained_client_skip),
                    ),
                )
            }
            else -> prompts.choose(title, subjects)?.let(clients::get)
        } ?: return null
        if (!confirmWarnings(chosen.warnings)) return null
        return StagedClient(file.name, chosen.key, caCertificates = chosen.caCertificates)
    }

    @Suppress("ReturnCount")
    suspend fun loadClient(source: CertificateSource): StagedClient? {
        val (name, data) = read(source) ?: return null
        // A PEM file is rejected before its password is asked
        try {
            CertificateImporter.checkPkcs12Format(data)
        } catch (err: ImportException) {
            prompts.message(TlsMessages.describe(context, err.error))
            return null
        }

        var retry = false
        while (true) {
            val password = askPassword(name, retry) ?: return null
            val aliases = try {
                withContext(Dispatchers.IO) { CertificateImporter.getPkcs12KeyAliases(data, password) }
            } catch (err: ImportException) {
                if (err.error != ImportError.WrongPassword) {
                    prompts.message(TlsMessages.describe(context, err.error))
                    return null
                }
                retry = true
                continue
            }
            val alias = if (aliases.size > 1) {
                aliases[prompts.choose(context.getString(R.string.tls_choose_key), aliases) ?: return null]
            } else {
                aliases.firstOrNull()
            }
            val parsed = try {
                withContext(Dispatchers.IO) { CertificateImporter.parsePkcs12(data, password, alias) }
            } catch (err: ImportException) {
                prompts.message(TlsMessages.describe(context, err.error))
                return null
            }
            if (!confirmWarnings(parsed.warnings)) return null
            return StagedClient(name, parsed.key, caCertificates = parsed.caCertificates)
        }
    }

    /**
     * Choose a key of the system credential store with the KeyChain dialog, which also grants the app access to it.
     */
    suspend fun chooseSystemClient(activity: Activity, endpoint: TlsEndpoint): StagedClient? {
        val issuers = tls.keyManager.getLastRequest(endpoint)?.issuers
            ?.mapNotNull { runCatching { X500Principal(it.name) }.getOrNull() }
            ?.toTypedArray()
        val current = (tls.getConfig(endpoint).clientCertificate as? ClientCertificate.System)?.alias

        val alias = suspendCancellableCoroutine<String?> { continuation ->
            try {
                KeyChain.choosePrivateKeyAlias(
                    activity,
                    { alias -> continuation.resume(alias) },
                    arrayOf("RSA", "EC"),
                    issuers,
                    endpoint.host,
                    endpoint.port,
                    current,
                )
            } catch (_: ActivityNotFoundException) {
                // Only offered when the chooser exists, see hasKeyChainChooser
                continuation.resume(null)
            }
        } ?: return null

        val key = try {
            withContext(Dispatchers.IO) {
                val key = tls.clientKeyStore.loadChosen(ClientCertificate.System(alias))
                if (!KeySelfTest.run(key.privateKey, key.chain.first())) throw ImportException(ImportError.KeyUnusable)
                key
            }
        } catch (err: ImportException) {
            prompts.message(TlsMessages.describe(context, err.error))
            return null
        }
        return StagedClient(key.chain.first().commonName(), key, systemAlias = alias)
    }

    /**
     * A client certificate file often contains the CA that issued it. Trusting it helps only when that CA also issued
     * the server certificate (one CA for both): asks whether to trust [certificates] for [endpoint].
     */
    suspend fun offerContainedCas(endpoint: TlsEndpoint, certificates: List<X509Certificate>): Boolean {
        if (certificates.isEmpty()) return false
        return prompts.confirm(
            Confirmation(
                title = context.getString(R.string.tls_contained_ca_title),
                message = context.resources.getQuantityString(
                    R.plurals.tls_contained_ca_message,
                    certificates.size,
                    certificates.joinToString("\n") { it.subjectX500Principal.name },
                    endpoint.display,
                ),
                confirm = context.getString(R.string.tls_trust),
                dismiss = context.getString(R.string.tls_contained_ca_skip),
            ),
        )
    }

    private suspend fun askPassword(name: String, retry: Boolean): CharArray? =
        prompts.password(context.getString(if (retry) R.string.tls_password_retry else R.string.tls_password_for, name))

    private suspend fun confirmWarnings(warnings: List<ImportWarning>): Boolean {
        if (warnings.isEmpty()) return true
        return prompts.confirm(
            Confirmation(
                title = context.getString(R.string.tls_warnings),
                message = warnings.joinToString("\n\n") { TlsMessages.describe(context, it) },
                confirm = context.getString(R.string.tls_use),
                dismiss = context.getString(android.R.string.cancel),
            ),
        )
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun read(source: CertificateSource): Pair<String, ByteArray>? = try {
        withContext(Dispatchers.IO) {
            when (source) {
                is CertificateSource.File -> {
                    val name = displayName(source.uri)
                    val data = requireNotNull(
                        context.contentResolver.openInputStream(source.uri)
                    ) { "Unable to open $name" }
                        .use { it.readLimited() }
                    name to data
                }

                is CertificateSource.Url -> {
                    tls.okHttpClient.newCall(Request.Builder().url(source.url).build()).execute().use { response ->
                        if (!response.isSuccessful) error("HTTP ${response.code}")
                        val url = response.request.url
                        val name = url.pathSegments.lastOrNull { it.isNotEmpty() } ?: url.host
                        name to requireNotNull(response.body) { "Empty response" }.byteStream().readLimited()
                    }
                }
            }
        }
    } catch (err: ImportException) {
        prompts.message(TlsMessages.describe(context, err.error))
        null
    } catch (err: Exception) {
        val message = err.message ?: err.javaClass.simpleName
        prompts.message(
            if (source is CertificateSource.Url) {
                context.getString(R.string.tls_import_download_failed, message)
            } else {
                context.getString(R.string.tls_import_read_failed, message)
            },
        )
        null
    }

    private fun displayName(uri: Uri): String = runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        }
    }.getOrNull() ?: uri.lastPathSegment?.substringAfterLast('/') ?: uri.toString()

    private fun InputStream.readLimited(): ByteArray {
        val bytes = readBytes()
        if (bytes.size > MAX_FILE_SIZE) throw ImportException(ImportError.UnrecognizedFormat)
        return bytes
    }

    private companion object {
        const val MAX_FILE_SIZE = 1024 * 1024
    }
}

/**
 * A way to pick a certificate file: [action] [Intent.ACTION_OPEN_DOCUMENT] (the system document picker) or
 * [Intent.ACTION_GET_CONTENT] (e.g. a file manager on a TV device), sent to [packageName] when only one app handles it.
 */
data class FilePicker(val action: String, val packageName: String?)

/**
 * The ways to pick a certificate file, best first: the document picker, then another app returning content. Empty
 * when there is none, many TV devices have none: load from a URL then. Android TV images have a stub for both
 * (com.android.tv.frameworkpackagestubs on Google TV 14, com.google.android.tv.frameworkpackagestubs on Android TV 11),
 * it finishes without a result: not a picker, and not offered in the app chooser (the intent goes to the only other
 * app directly). The photo picker of the media provider handles GET_CONTENT for every type since Android 13 (on Android
 * TV 14 the only handler besides the stub), it shows photos and videos only: not a picker for certificate files.
 */
fun Context.filePickers(): List<FilePicker> = FILE_PICKER_ACTIONS.mapNotNull { action ->
    val packages = packageManager.queryIntentActivities(filePickerIntent(action), PackageManager.MATCH_DEFAULT_ONLY)
        .map { it.activityInfo }
        .filterNot { it.packageName.endsWith(TV_FRAMEWORK_STUBS) || PHOTO_PICKER in it.name }
        .map { it.packageName }
        .distinct()
    if (packages.isEmpty()) null else FilePicker(action, packages.singleOrNull())
}

fun Context.hasFilePicker(): Boolean = filePickers().isNotEmpty()

/**
 * Starts the first file picker of [filePickers] that can be started. False when there is none: load from a URL.
 */
fun Context.launchFilePicker(launcher: ActivityResultLauncher<FilePicker>): Boolean = filePickers().any { picker ->
    try {
        launcher.launch(picker)
        true
    } catch (_: ActivityNotFoundException) {
        false
    }
}

/**
 * Picks a file with a [FilePicker], the result is its content URI.
 */
class PickFile : ActivityResultContract<FilePicker, Uri?>() {
    override fun createIntent(context: Context, input: FilePicker): Intent =
        filePickerIntent(input.action).apply { input.packageName?.let(::setPackage) }

    override fun parseResult(resultCode: Int, intent: Intent?): Uri? = intent?.data?.takeIf {
        resultCode == Activity.RESULT_OK
    }
}

private fun filePickerIntent(action: String) = Intent(action).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")

private const val TV_FRAMEWORK_STUBS = ".tv.frameworkpackagestubs"
private const val PHOTO_PICKER = ".photopicker."
private val FILE_PICKER_ACTIONS = listOf(Intent.ACTION_OPEN_DOCUMENT, Intent.ACTION_GET_CONTENT)

/**
 * Whether the KeyChain certificate chooser exists, it is missing on some TV devices.
 */
fun Context.hasKeyChainChooser(): Boolean = Intent("com.android.keychain.CHOOSER")
    .setPackage("com.android.keychain")
    .resolveActivity(packageManager) != null

/**
 * Whether the system credential store can hold a key. Before Android 10 it needs a secure lock screen, without one the
 * KeyChain chooser only asks to set a lock screen (seen on API 23 - 26), there is nothing to choose.
 */
fun Context.canHoldSystemKeys(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q ||
    getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true

fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}
