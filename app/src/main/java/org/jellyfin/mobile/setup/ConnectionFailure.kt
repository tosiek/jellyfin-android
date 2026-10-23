package org.jellyfin.mobile.setup

import android.content.Context
import org.jellyfin.mobile.R
import org.jellyfin.sdk.api.client.exception.InvalidContentException
import org.jellyfin.sdk.api.client.exception.InvalidStatusException
import org.jellyfin.sdk.api.client.exception.SecureConnectionException
import org.jellyfin.sdk.api.client.exception.TimeoutException
import java.io.InterruptedIOException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.UnknownHostException
import javax.net.ssl.SSLException

/**
 * Why a server could not be reached, derived from the exception of a failed request.
 */
sealed interface ConnectionFailure {
    data class Redirect(val status: Int) : ConnectionFailure
    data class AccessDenied(val status: Int) : ConnectionFailure
    data object NotFound : ConnectionFailure
    data class ServerError(val status: Int) : ConnectionFailure
    data class HttpStatus(val status: Int) : ConnectionFailure
    data object UnknownHost : ConnectionFailure
    data object Refused : ConnectionFailure
    data object Timeout : ConnectionFailure
    data object Tls : ConnectionFailure
    data object NotJellyfin : ConnectionFailure
    data object Other : ConnectionFailure

    companion object {
        private const val MAX_CAUSES = 10

        private fun causes(error: Throwable): List<Throwable> =
            generateSequence(error) { it.cause }.take(MAX_CAUSES).toList()

        /**
         * Classifies [error]. The SDK wraps the network exceptions (an unknown host becomes a TimeoutException),
         * so the deepest cause that matches wins.
         */
        fun classify(error: Throwable): ConnectionFailure =
            causes(error).asReversed().firstNotNullOfOrNull(::classifySingle) ?: Other

        @Suppress("MagicNumber", "CyclomaticComplexMethod")
        private fun classifySingle(error: Throwable): ConnectionFailure? = when (error) {
            is InvalidStatusException -> when (val status = error.status) {
                in 300..399 -> Redirect(status)
                401, 403 -> AccessDenied(status)
                404 -> NotFound
                in 500..599 -> ServerError(status)
                else -> HttpStatus(status)
            }
            is UnknownHostException -> UnknownHost
            is ConnectException, is NoRouteToHostException -> Refused
            is SSLException, is SecureConnectionException -> Tls
            is InterruptedIOException, is TimeoutException -> Timeout
            is InvalidContentException -> NotJellyfin
            else -> null
        }

        /**
         * The deepest cause of [error] as "SimpleName: message", in English for bug reports.
         * Null for a bare HTTP status, the mapped text already says everything.
         */
        fun rawCause(error: Throwable): String? {
            val root = causes(error).last()
            if (root is InvalidStatusException) return null
            val name = root.javaClass.simpleName.ifEmpty { root.javaClass.name }
            return root.message?.takeIf(String::isNotBlank)?.let { "$name: $it" } ?: name
        }

        /**
         * The mapped text and the raw cause joined by [separator], each when there is one. Null when there is neither.
         */
        fun details(context: Context, error: Throwable, separator: String = "\n"): String? =
            listOfNotNull(classify(error).describe(context), rawCause(error))
                .takeIf { it.isNotEmpty() }
                ?.joinToString(separator = separator)
    }
}

fun ConnectionFailure.describe(context: Context): String? = when (this) {
    is ConnectionFailure.Redirect -> context.getString(R.string.connection_error_cause_redirect, status)
    is ConnectionFailure.AccessDenied -> context.getString(R.string.connection_error_cause_access_denied, status)
    ConnectionFailure.NotFound -> context.getString(R.string.connection_error_cause_not_found)
    is ConnectionFailure.ServerError -> context.getString(R.string.connection_error_cause_server_error, status)
    is ConnectionFailure.HttpStatus -> context.getString(R.string.connection_error_cause_http_status, status)
    ConnectionFailure.UnknownHost -> context.getString(R.string.connection_error_cause_unknown_host)
    ConnectionFailure.Refused -> context.getString(R.string.connection_error_cause_refused)
    ConnectionFailure.Timeout -> context.getString(R.string.connection_error_cause_timeout)
    ConnectionFailure.Tls -> context.getString(R.string.connection_error_cause_tls)
    ConnectionFailure.NotJellyfin -> context.getString(R.string.connection_error_cause_not_jellyfin)
    ConnectionFailure.Other -> null
}
