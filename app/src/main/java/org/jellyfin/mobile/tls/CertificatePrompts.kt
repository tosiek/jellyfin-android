package org.jellyfin.mobile.tls

import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CompletableDeferred

/**
 * Questions of a certificate import, shown as dialogs by the screen that imports. Null or false when cancelled.
 */
interface CertificatePrompts {
    suspend fun url(): String?
    suspend fun password(title: String): CharArray?
    suspend fun choose(title: String, items: List<String>): Int?
    suspend fun confirm(confirmation: Confirmation): Boolean
    suspend fun message(text: String)
}

/**
 * With [destructive] the dismiss button is the default, so Enter on a remote does not remove a certificate.
 */
data class Confirmation(
    val title: String?,
    val message: String,
    val confirm: String,
    val dismiss: String,
    val destructive: Boolean = false,
)

sealed class Prompt<T> {
    internal val result = CompletableDeferred<T>()

    fun answer(value: T) {
        result.complete(value)
    }

    class Url : Prompt<String?>()
    class Password(val title: String) : Prompt<CharArray?>()
    class Choice(val title: String, val items: List<String>) : Prompt<Int?>()
    class Confirm(val confirmation: Confirmation) : Prompt<Boolean>()
    class Message(val text: String) : Prompt<Unit>()
}

/**
 * [CertificatePrompts] as Compose state: the screen shows [current] and answers it.
 */
@Stable
class PromptState : CertificatePrompts {
    var current by mutableStateOf<Prompt<*>?>(null)
        private set

    private suspend fun <T> ask(prompt: Prompt<T>): T {
        current = prompt
        return try {
            prompt.result.await()
        } finally {
            if (current === prompt) current = null
        }
    }

    override suspend fun url() = ask(Prompt.Url())

    override suspend fun password(title: String) = ask(Prompt.Password(title))

    override suspend fun choose(title: String, items: List<String>) = ask(Prompt.Choice(title, items))

    override suspend fun confirm(confirmation: Confirmation) = ask(Prompt.Confirm(confirmation))

    override suspend fun message(text: String) = ask(Prompt.Message(text))
}
