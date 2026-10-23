package org.jellyfin.mobile.setup

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import org.jellyfin.mobile.R
import org.jellyfin.mobile.tls.TlsMessages
import org.jellyfin.mobile.ui.state.CheckUrlState
import org.jellyfin.sdk.Jellyfin
import org.jellyfin.sdk.discovery.LocalServerDiscovery
import org.jellyfin.sdk.discovery.RecommendedServerInfo
import org.jellyfin.sdk.discovery.RecommendedServerInfoScore
import org.jellyfin.sdk.model.api.ServerDiscoveryInfo
import timber.log.Timber

class ConnectionHelper(
    private val context: Context,
    private val jellyfin: Jellyfin,
) {
    @Suppress("LongMethod")
    suspend fun checkServerUrl(enteredUrl: String): CheckUrlState {
        Timber.i("checkServerUrlAndConnection $enteredUrl")

        val candidates = withContext(Dispatchers.IO) {
            jellyfin.discovery.getAddressCandidates(enteredUrl)
        }
        Timber.i("Address candidates are $candidates")

        // Find servers and classify them into groups.
        // BAD servers are collected in case we need an error message,
        // GOOD are kept if there's no GREAT one.
        val badServers = mutableListOf<RecommendedServerInfo>()
        val goodServers = mutableListOf<RecommendedServerInfo>()
        val greatServer = withContext(Dispatchers.IO) {
            jellyfin.discovery.getRecommendedServers(candidates)
        }.firstOrNull { recommendedServer ->
            when (recommendedServer.score) {
                RecommendedServerInfoScore.GREAT -> true
                RecommendedServerInfoScore.GOOD -> {
                    goodServers += recommendedServer
                    false
                }
                RecommendedServerInfoScore.OK,
                RecommendedServerInfoScore.BAD,
                -> {
                    badServers += recommendedServer
                    false
                }
            }
        }

        val server = greatServer ?: goodServers.firstOrNull()
        if (server != null) {
            val systemInfo = requireNotNull(server.systemInfo)
            val serverVersion = systemInfo.getOrNull()?.version
            Timber.i("Found valid server at ${server.address} with rating ${server.score} and version $serverVersion")
            return CheckUrlState.Success(server.address)
        }

        // No valid server found, log and show error message
        val loggedServers = badServers.joinToString { "${it.address}/${it.systemInfo}" }
        Timber.i("No valid servers found, invalid candidates were: $loggedServers")

        val error = when {
            badServers.isNotEmpty() -> {
                val count = badServers.size
                val (unreachableServers, incompatibleServers) = badServers.partition { result -> result.systemInfo.getOrNull() == null }

                StringBuilder().apply {
                    append(context.resources.getQuantityString(R.plurals.connection_error_prefix, count, count))
                    if (unreachableServers.isNotEmpty()) {
                        append("\n\n")
                        append(context.getString(R.string.connection_error_unable_to_reach_sever))
                        append(":\n")
                        append(
                            // Addresses that failed the same way (e.g. https:// and http:// of a stopped server) share
                            // one cause, indented under them, one line each
                            unreachableServers.groupBy(
                                keySelector = { result ->
                                    val error = result.systemInfo.exceptionOrNull()
                                    // The TLS text is more precise than the mapped cause, the raw cause is added to both
                                    val reason = TlsMessages.describe(context, result.address, result.issues)
                                        ?: error?.let { ConnectionFailure.classify(it).describe(context) }
                                    listOfNotNull(reason, error?.let(ConnectionFailure::rawCause))
                                        .joinToString(separator = "\n  ")
                                        .ifEmpty { null }
                                },
                                valueTransform = { result -> result.address },
                            ).entries.joinToString(separator = "\n") { (details, addresses) ->
                                addresses.joinToString(separator = "\n") { "\u00b7 $it" } +
                                    details?.let { "\n  $it" }.orEmpty()
                            },
                        )
                    }
                    if (incompatibleServers.isNotEmpty()) {
                        append("\n\n")
                        append(context.getString(R.string.connection_error_unsupported_version_or_product))
                        append(":\n")
                        append(
                            incompatibleServers.joinToString(separator = "\n") { result ->
                                "\u00b7 ${result.address}"
                            },
                        )
                    }
                }.toString()
            }
            else -> null
        }

        return CheckUrlState.Error(error)
    }

    fun discoverServersAsFlow(): Flow<ServerDiscoveryInfo> =
        jellyfin.discovery
            .discoverLocalServers(maxServers = LocalServerDiscovery.DISCOVERY_MAX_SERVERS)
            .flowOn(Dispatchers.IO)
}
