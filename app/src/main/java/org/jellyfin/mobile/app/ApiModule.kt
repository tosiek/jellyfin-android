package org.jellyfin.mobile.app

import org.jellyfin.mobile.utils.Constants
import org.jellyfin.sdk.Jellyfin
import org.jellyfin.sdk.api.okhttp.OkHttpFactory
import org.jellyfin.sdk.createJellyfin
import org.jellyfin.sdk.model.ClientInfo
import org.koin.android.ext.koin.androidContext
import org.koin.dsl.module

val apiModule = module {
    // Jellyfin API builder and API client instance
    single {
        createJellyfin {
            context = androidContext()
            clientInfo = ClientInfo(name = Constants.APP_INFO_NAME, version = Constants.APP_INFO_VERSION)

            // Use the shared OkHttp client with the TLS configuration (custom CA, client certificates)
            val okHttpFactory = OkHttpFactory(get())
            apiClientFactory = okHttpFactory
            socketConnectionFactory = okHttpFactory
        }
    }
    single { get<Jellyfin>().createApi() }
}
