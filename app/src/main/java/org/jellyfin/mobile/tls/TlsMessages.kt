package org.jellyfin.mobile.tls

import android.content.Context
import org.jellyfin.mobile.R
import org.jellyfin.sdk.discovery.RecommendedServerIssue
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.text.DateFormat
import java.util.Date
import javax.net.ssl.SSLPeerUnverifiedException

sealed interface TlsProblem {
    data class Untrusted(val issuer: String?) : TlsProblem
    data class Expired(val date: Date) : TlsProblem
    data class NotYetValid(val date: Date) : TlsProblem
    data object HostnameMismatch : TlsProblem
    data object ClientCertificateRequired : TlsProblem
    data object ClientCertificateUnavailable : TlsProblem
    data object ClientCertificateRejected : TlsProblem
}

object TlsDiagnostics {
    private val rejectedAlerts = listOf(
        "certificate_required", "certificate required", "bad_certificate", "bad certificate",
        "unknown_ca", "unknown ca", "certificate_unknown", "certificate unknown",
        "access_denied", "access denied", "certificate_revoked", "certificate_expired",
    )

    /**
     * Determine the TLS problem of a failed connection to [endpoint] using the state recorded during the handshake and
     * the [error] of the connection. Returns null when the failure is not TLS related.
     */
    fun diagnose(tls: TlsManager, endpoint: TlsEndpoint?, error: Throwable?): TlsProblem? = diagnose(
        trustManager = tls.trustManager,
        keyManager = tls.keyManager,
        hasClientCertificate = { tls.getConfig(it).clientCertificate != ClientCertificate.None },
        endpoint = endpoint,
        error = error,
    )

    @Suppress("NestedBlockDepth")
    internal fun diagnose(
        trustManager: HostAwareTrustManager,
        keyManager: HostAwareKeyManager,
        hasClientCertificate: (TlsEndpoint) -> Boolean,
        endpoint: TlsEndpoint?,
        error: Throwable?,
    ): TlsProblem? {
        val causes = generateSequence(error) { it.cause }.toList()

        if (endpoint != null) {
            trustManager.getLastFailure(endpoint)?.let { failure ->
                val leaf = failure.chain.firstOrNull()
                val failureCauses = generateSequence<Throwable>(failure.error) { it.cause }.toList()
                return when {
                    failureCauses.any { it is CertificateExpiredException } -> TlsProblem.Expired(
                        expiredDate(failure.chain)
                    )
                    failureCauses.any { it is CertificateNotYetValidException } -> TlsProblem.NotYetValid(
                        leaf?.notBefore ?: Date()
                    )
                    else -> TlsProblem.Untrusted(leaf?.issuerX500Principal?.name)
                }
            }

            keyManager.getLastRequest(endpoint)?.let { request ->
                if (!request.configured) {
                    return if (hasClientCertificate(
                            endpoint
                        )
                    ) {
                        TlsProblem.ClientCertificateUnavailable
                    } else {
                        TlsProblem.ClientCertificateRequired
                    }
                }
                val messages = causes.mapNotNull { it.message?.lowercase() }
                if (messages.any { message ->
                        rejectedAlerts.any {
                            message.contains(
                                it
                            )
                        }
                    }
                ) {
                    return TlsProblem.ClientCertificateRejected
                }
            }
        }

        val unverified = causes.any {
            it is SSLPeerUnverifiedException || it.message?.contains("not verified", ignoreCase = true) == true
        }
        if (unverified) {
            return TlsProblem.HostnameMismatch
        }

        return null
    }

    private fun expiredDate(chain: List<X509Certificate>): Date {
        val now = Date()
        return chain.firstOrNull { it.notAfter.before(now) }?.notAfter ?: now
    }
}

object TlsMessages {
    fun describe(context: Context, endpoint: TlsEndpoint, problem: TlsProblem): String {
        val dateFormat = DateFormat.getDateInstance(DateFormat.MEDIUM)
        return when (problem) {
            is TlsProblem.Untrusted -> context.getString(
                R.string.tls_problem_untrusted,
                problem.issuer ?: "?",
                endpoint.display,
            )

            is TlsProblem.Expired -> context.getString(R.string.tls_problem_expired, dateFormat.format(problem.date))
            is TlsProblem.NotYetValid -> context.getString(
                R.string.tls_problem_not_yet_valid,
                dateFormat.format(problem.date)
            )
            TlsProblem.HostnameMismatch -> context.getString(R.string.tls_problem_hostname, endpoint.display)
            TlsProblem.ClientCertificateRequired -> context.getString(
                R.string.tls_problem_client_required,
                endpoint.display
            )
            TlsProblem.ClientCertificateUnavailable -> context.getString(
                R.string.tls_problem_client_unavailable,
                endpoint.display
            )
            TlsProblem.ClientCertificateRejected -> context.getString(
                R.string.tls_problem_client_rejected,
                endpoint.display
            )
        }
    }

    /**
     * Describe a failed connection to [address], null when the failure is not TLS related.
     */
    fun describe(context: Context, address: String, error: Throwable?): String? {
        val endpoint = TlsEndpoint.fromUrl(address) ?: return null
        val problem = TlsDiagnostics.diagnose(TlsManager.get(context), endpoint, error) ?: return null
        return describe(context, endpoint, problem)
    }

    /**
     * Describe the TLS problem in the issues of a server address candidate, null when there is none.
     */
    fun describe(context: Context, address: String, issues: Collection<RecommendedServerIssue>): String? {
        val error = issues.firstNotNullOfOrNull { issue ->
            when (issue) {
                is RecommendedServerIssue.SecureConnectionFailed -> issue.sslException
                is RecommendedServerIssue.MissingSystemInfo ->
                    issue.throwable ?: IllegalStateException("No system info")
                else -> null
            }
        } ?: return null
        return describe(context, address, error)
    }

    @Suppress("CyclomaticComplexMethod")
    fun describe(context: Context, error: ImportError): String = when (error) {
        ImportError.UnrecognizedFormat -> context.getString(R.string.tls_import_unrecognized)
        ImportError.NotPkcs12 -> context.getString(R.string.tls_import_not_pkcs12)
        ImportError.WrongPassword -> context.getString(R.string.tls_import_wrong_password)
        ImportError.WrongOrUnsupportedPassword -> context.getString(R.string.tls_import_wrong_or_unsupported_password)
        is ImportError.UnsupportedEncryption -> context.getString(
            R.string.tls_import_unsupported_encryption,
            Pkcs12Algorithms.androidVersion,
            error.detected.joinToString().ifEmpty { "?" },
            error.supported.joinToString().ifEmpty { "-" },
        )

        ImportError.NoPrivateKey -> context.getString(R.string.tls_import_no_private_key)
        ImportError.NoCaCertificate -> context.getString(R.string.tls_import_no_ca)
        is ImportError.UnsupportedKeyType -> context.getString(R.string.tls_import_unsupported_key, error.keyType)
        ImportError.UnreadableKey -> context.getString(
            R.string.tls_import_unreadable_key,
            Pkcs12Algorithms.androidVersion
        )
        ImportError.KeyUnusable -> context.getString(R.string.tls_import_key_unusable, Pkcs12Algorithms.androidVersion)
        ImportError.KeyStoreTimeout -> context.getString(R.string.tls_import_keystore_timeout)
        is ImportError.Expired -> context.getString(
            R.string.tls_import_expired,
            DateFormat.getDateInstance(DateFormat.MEDIUM).format(error.date)
        )

        is ImportError.NotYetValid -> context.getString(
            R.string.tls_import_not_yet_valid,
            DateFormat.getDateInstance(DateFormat.MEDIUM).format(error.date)
        )

        is ImportError.InsecureSignature -> context.getString(R.string.tls_import_insecure_signature, error.algorithm)
    }

    fun describe(context: Context, warning: ImportWarning): String = when (warning) {
        is ImportWarning.NotCertificateAuthority -> context.getString(R.string.tls_warning_not_ca)
        is ImportWarning.WeakSignature -> context.getString(R.string.tls_warning_outdated, warning.algorithm)
        is ImportWarning.WeakKey -> context.getString(R.string.tls_warning_outdated, "RSA ${warning.bits} bit")
    }
}
