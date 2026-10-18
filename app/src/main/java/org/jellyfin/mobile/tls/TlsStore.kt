package org.jellyfin.mobile.tls

import android.content.Context
import androidx.core.content.edit
import org.json.JSONArray
import org.json.JSONObject
import timber.log.Timber
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap

/**
 * Where the client certificate of an endpoint comes from. There is no fallback between sources.
 */
sealed interface ClientCertificate {
    data object None : ClientCertificate

    /** A key installed in the Android system credential store (KeyChain), granted to this app. */
    data class System(val alias: String) : ClientCertificate

    /** A key imported from a PKCS#12 file into the app. */
    data class Imported(val alias: String, val storage: Storage) : ClientCertificate {
        enum class Storage {
            KEYSTORE,

            /** Stored encrypted with an AndroidKeyStore key, used when the KeyStore rejects the key. */
            ENCRYPTED_FILE,
        }
    }
}

data class TlsServerConfig(
    val caFingerprints: List<String> = emptyList(),
    val clientCertificate: ClientCertificate = ClientCertificate.None,
) {
    val isEmpty get() = caFingerprints.isEmpty() && clientCertificate == ClientCertificate.None
}

/**
 * Persists the per-endpoint TLS configuration. CA certificates are stored as DER files named by their SHA-256.
 */
class TlsStore(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
    private val caDirectory = File(context.filesDir, "tls/ca")
    private val configCache = ConcurrentHashMap<String, TlsServerConfig>()
    private val caCache = ConcurrentHashMap<String, X509Certificate>()

    val endpoints: List<TlsEndpoint>
        get() = preferences.all.keys.mapNotNull(TlsEndpoint::fromKey)

    fun get(endpoint: TlsEndpoint): TlsServerConfig = configCache.getOrPut(endpoint.key) {
        preferences.getString(endpoint.key, null)?.let(::decode) ?: TlsServerConfig()
    }

    fun set(endpoint: TlsEndpoint, config: TlsServerConfig) {
        configCache[endpoint.key] = config
        preferences.edit {
            if (config.isEmpty) {
                remove(endpoint.key)
            } else {
                putString(endpoint.key, encode(config))
            }
        }
        removeUnusedCertificates()
    }

    fun getCertificates(endpoint: TlsEndpoint): List<X509Certificate> = get(
        endpoint
    ).caFingerprints.mapNotNull(::getCertificate)

    fun getAllCertificates(): List<X509Certificate> = endpoints
        .flatMap { get(it).caFingerprints }
        .distinct()
        .mapNotNull(::getCertificate)

    fun addCertificate(certificate: X509Certificate): String {
        val fingerprint = certificate.sha256()
        caDirectory.mkdirs()
        File(caDirectory, "$fingerprint.der").writeBytes(certificate.encoded)
        caCache[fingerprint] = certificate
        return fingerprint
    }

    private fun getCertificate(fingerprint: String): X509Certificate? = caCache[fingerprint] ?: runCatching {
        File(caDirectory, "$fingerprint.der").inputStream().use { input ->
            CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
        }
    }.onFailure {
        Timber.w(it, "Unable to read stored CA certificate $fingerprint")
    }.getOrNull()?.also { caCache[fingerprint] = it }

    private fun removeUnusedCertificates() {
        val used = endpoints.flatMap { get(it).caFingerprints }.toSet()
        caDirectory.listFiles()?.forEach { file ->
            val fingerprint = file.name.removeSuffix(".der")
            if (fingerprint !in used) {
                file.delete()
                caCache.remove(fingerprint)
            }
        }
    }

    private fun encode(config: TlsServerConfig) = JSONObject().apply {
        put("ca", JSONArray(config.caFingerprints))
        when (val client = config.clientCertificate) {
            ClientCertificate.None -> Unit
            is ClientCertificate.System -> put("client", JSONObject().put("type", "system").put("alias", client.alias))
            is ClientCertificate.Imported -> put(
                "client",
                JSONObject().put("type", "imported").put("alias", client.alias).put("storage", client.storage.name)
            )
        }
    }.toString()

    private fun decode(value: String): TlsServerConfig? = runCatching {
        val json = JSONObject(value)
        val ca = json.optJSONArray("ca")?.let { array -> List(array.length()) { array.getString(it) } }.orEmpty()
        val client = json.optJSONObject("client")?.let { client ->
            when (client.getString("type")) {
                "system" -> ClientCertificate.System(client.getString("alias"))
                "imported" -> ClientCertificate.Imported(
                    client.getString("alias"),
                    ClientCertificate.Imported.Storage.valueOf(client.getString("storage")),
                )

                else -> null
            }
        } ?: ClientCertificate.None
        TlsServerConfig(ca, client)
    }.onFailure {
        Timber.w(it, "Unable to decode TLS configuration")
    }.getOrNull()

    companion object {
        private const val PREFERENCES_NAME = "tls_servers"
    }
}

fun X509Certificate.sha256(): String = MessageDigest.getInstance("SHA-256")
    .digest(encoded)
    .joinToString("") { "%02x".format(it) }
