package org.jellyfin.mobile.tls

import android.app.Activity
import android.widget.Toast
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner

/**
 * Explains TLS problems of requests (e.g. the client certificate was removed) with a toast while the activity is
 * started, once per problem: the failed requests only leave empty or stale screens. Not shown while [suppress] is true.
 */
class TlsProblemToast(
    private val activity: Activity,
    private val suppress: () -> Boolean = { false },
) : DefaultLifecycleObserver {
    private val tls by lazy { TlsManager.get(activity) }
    private var shown: Pair<TlsEndpoint, TlsProblem>? = null
    private var shownVersion = 0
    private var started = false

    private val listener: (TlsEndpoint, TlsProblem) -> Unit = { endpoint, problem ->
        activity.runOnUiThread {
            // Again after the certificates changed: the certificates screen does not stop the activity
            val again = shown != endpoint to problem || shownVersion != tls.configVersion
            if (again && started && !suppress()) {
                shown = endpoint to problem
                shownVersion = tls.configVersion
                Toast.makeText(activity, TlsMessages.describe(activity, endpoint, problem), Toast.LENGTH_LONG).show()
            }
        }
    }

    override fun onStart(owner: LifecycleOwner) {
        // Shown again after coming back, e.g. from the certificates screen
        shown = null
        started = true
        tls.addProblemListener(listener)
    }

    override fun onStop(owner: LifecycleOwner) {
        started = false
        tls.removeProblemListener(listener)
    }
}
