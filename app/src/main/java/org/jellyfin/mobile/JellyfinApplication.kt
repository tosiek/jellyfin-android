package org.jellyfin.mobile

import android.app.Application
import android.os.Handler
import android.os.Looper
import android.webkit.WebView
import org.jellyfin.mobile.app.apiModule
import org.jellyfin.mobile.app.applicationModule
import org.jellyfin.mobile.data.databaseModule
import org.jellyfin.mobile.tls.TlsManager
import org.jellyfin.mobile.utils.JellyTree
import org.jellyfin.mobile.utils.isWebViewSupported
import org.koin.android.ext.koin.androidContext
import org.koin.androidx.fragment.koin.fragmentFactory
import org.koin.core.context.startKoin
import timber.log.Timber

@Suppress("unused")
class JellyfinApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        // Setup logging
        Timber.plant(JellyTree())

        // Custom CA and client certificates for all connections, must happen before any connection is made
        val tls = TlsManager.install(this)
        if (isWebViewSupported()) {
            // The WebView caches client certificate decisions, reset them when the configuration changes
            tls.addChangeListener { Handler(Looper.getMainLooper()).post { WebView.clearClientCertPreferences(null) } }
        }

        if (BuildConfig.DEBUG) {
            // Enable WebView debugging
            if (isWebViewSupported()) {
                WebView.setWebContentsDebuggingEnabled(true)
            }
        }

        startKoin {
            androidContext(this@JellyfinApplication)
            fragmentFactory()

            modules(
                applicationModule,
                apiModule,
                databaseModule,
            )
        }
    }
}
