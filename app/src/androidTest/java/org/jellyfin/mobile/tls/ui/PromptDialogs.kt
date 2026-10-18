package org.jellyfin.mobile.tls.ui

import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.ComposeTestRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextReplacement
import androidx.test.platform.app.InstrumentationRegistry

/**
 * Answers the dialogs of a certificate import (CertificatePromptDialogs). Imports run in the background, every step
 * waits until the dialog is there.
 */
class PromptDialogs(private val compose: ComposeTestRule) {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    fun waitForText(text: String, substring: Boolean = false, timeoutMs: Long = TIMEOUT_MS) {
        compose.waitUntil(timeoutMs) {
            compose.onAllNodesWithText(text, substring = substring, ignoreCase = true).fetchSemanticsNodes().isNotEmpty()
        }
    }

    /**
     * Waits for a dialog that shows [text].
     */
    fun expect(text: String) = waitFor(hasText(text, substring = true, ignoreCase = true) and inDialog)

    /**
     * Types [text] into the field of the open dialog and confirms it.
     */
    fun enter(text: String) {
        val field = hasSetTextAction() and inDialog
        waitFor(field)
        compose.onNode(field).performTextReplacement(text)
        click(context.getString(android.R.string.ok))
    }

    /**
     * Clicks the button or list item showing [text] in the open dialog.
     */
    fun click(text: String) {
        val node = hasText(text, ignoreCase = true) and hasClickAction() and inDialog
        waitFor(node)
        compose.onNode(node).performClick()
    }

    private fun waitFor(matcher: SemanticsMatcher) {
        compose.waitUntil(TIMEOUT_MS) { compose.onAllNodes(matcher).fetchSemanticsNodes().isNotEmpty() }
    }

    private companion object {
        const val TIMEOUT_MS = 15_000L
        val inDialog = hasAnyAncestor(isDialog())
    }
}
