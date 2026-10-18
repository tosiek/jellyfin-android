package org.jellyfin.mobile.tls

import java.net.IDN
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI

/**
 * A TLS endpoint (host + port) used as the key for per-server certificate configuration.
 *
 * The host is used literally (no DNS resolution), so "localhost", "127.0.0.1" and "::1" are different endpoints.
 * Stored as `host_port`, parsed by splitting on the last underscore.
 */
class TlsEndpoint private constructor(
    val host: String,
    val port: Int,
) {
    val key: String get() = "${host}_$port"
    val display: String get() = if (host.contains(':')) "[$host]:$port" else "$host:$port"

    override fun equals(other: Any?): Boolean = other is TlsEndpoint && other.host == host && other.port == port
    override fun hashCode(): Int = key.hashCode()
    override fun toString(): String = display

    companion object {
        const val DEFAULT_HTTPS_PORT = 443
        private const val MAX_PORT = 65535

        /**
         * A port <= 0 means the default https port.
         */
        fun of(host: String?, port: Int): TlsEndpoint? {
            val normalizedHost = normalizeHost(host) ?: return null
            val normalizedPort = if (port <= 0) DEFAULT_HTTPS_PORT else port
            if (normalizedPort > MAX_PORT) return null
            return TlsEndpoint(normalizedHost, normalizedPort)
        }

        /**
         * Create an endpoint from a server address. Addresses without scheme are treated as https.
         * Returns null for plain http addresses as they never use TLS.
         */
        fun fromUrl(url: String?): TlsEndpoint? {
            val trimmed = url?.trim()?.ifEmpty { null } ?: return null
            val withScheme = if (trimmed.contains("://")) trimmed else "https://$trimmed"
            val uri = runCatching { URI(withScheme) }.getOrNull() ?: return null
            val secure = uri.scheme.equals("https", ignoreCase = true) || uri.scheme.equals("wss", ignoreCase = true)
            if (!secure) return null
            return of(uri.host, uri.port)
        }

        fun fromKey(key: String): TlsEndpoint? {
            val separator = key.lastIndexOf('_')
            if (separator <= 0) return null
            val port = key.substring(separator + 1).toIntOrNull() ?: return null
            return of(key.substring(0, separator), port)
        }

        internal fun normalizeHost(host: String?): String? {
            var value = host?.trim()?.ifEmpty { null } ?: return null
            value = value.removePrefix("[").removeSuffix("]").trimEnd('.').lowercase()
            if (value.isEmpty()) return null

            // IPv6 literal, canonicalize without DNS lookups
            if (value.contains(':')) return compressIpv6(value.substringBefore('%'))

            return runCatching { IDN.toASCII(value, IDN.ALLOW_UNASSIGNED) }.getOrNull()?.lowercase()?.ifEmpty { null }
        }

        /**
         * Convert an IPv6 literal to its RFC 5952 compressed form. Returns null for invalid literals.
         */
        @Suppress("ComplexCondition", "CyclomaticComplexMethod", "MagicNumber")
        private fun compressIpv6(literal: String): String? {
            if (!literal.all { it.isDigit() || it in 'a'..'f' || it == ':' || it == '.' }) return null
            // InetAddress.getByName does not perform DNS lookups for literal addresses
            val address = runCatching { InetAddress.getByName(literal) }.getOrNull() ?: return null
            if (address !is Inet6Address) return address.hostAddress
            val bytes = address.address
            val groups = IntArray(
                8
            ) { ((bytes[it * 2].toInt() and 0xff) shl 8) or (bytes[it * 2 + 1].toInt() and 0xff) }

            // Find the longest run of zero groups (minimum 2)
            var bestStart = -1
            var bestLength = 0
            var index = 0
            while (index < groups.size) {
                if (groups[index] == 0) {
                    val start = index
                    while (index < groups.size && groups[index] == 0) index++
                    if (index - start > bestLength && index - start >= 2) {
                        bestStart = start
                        bestLength = index - start
                    }
                } else {
                    index++
                }
            }

            return buildString {
                var i = 0
                while (i < groups.size) {
                    if (i == bestStart) {
                        append("::")
                        i += bestLength
                        continue
                    }
                    if (isNotEmpty() && !endsWith(":")) append(':')
                    append(groups[i].toString(16))
                    i++
                }
            }
        }
    }
}
