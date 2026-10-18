package org.jellyfin.mobile.tls

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.AlertDialog
import androidx.compose.material.ContentAlpha
import androidx.compose.material.LocalContentAlpha
import androidx.compose.material.MaterialTheme
import androidx.compose.material.OutlinedTextField
import androidx.compose.material.Text
import androidx.compose.material.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import org.jellyfin.mobile.R

/**
 * Shows the current question of [state] as a dialog.
 */
@Composable
fun CertificatePromptDialogs(state: PromptState) {
    when (val prompt = state.current) {
        is Prompt.Url -> TextInputDialog(
            title = stringResource(R.string.tls_import_from_url),
            hint = stringResource(R.string.tls_import_url_hint),
            keyboardType = KeyboardType.Uri,
            onDone = { prompt.answer(it.trim().ifEmpty { null }) },
            onDismiss = { prompt.answer(null) },
        )
        is Prompt.Password -> TextInputDialog(
            title = prompt.title,
            hint = stringResource(R.string.tls_password),
            keyboardType = KeyboardType.Password,
            onDone = { prompt.answer(it.toCharArray()) },
            onDismiss = { prompt.answer(null) },
        )
        is Prompt.Choice -> AlertDialog(
            onDismissRequest = { prompt.answer(null) },
            title = { Text(text = prompt.title) },
            text = {
                Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                    prompt.items.forEachIndexed { index, item ->
                        Text(
                            text = item,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { prompt.answer(index) }
                                .padding(vertical = 12.dp),
                        )
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { prompt.answer(null) }) {
                    Text(text = stringResource(android.R.string.cancel))
                }
            },
        )
        is Prompt.Confirm -> ConfirmDialog(prompt)
        is Prompt.Message -> AlertDialog(
            onDismissRequest = { prompt.answer(Unit) },
            text = { Text(text = prompt.text) },
            confirmButton = {
                TextButton(onClick = { prompt.answer(Unit) }) {
                    Text(text = stringResource(android.R.string.ok))
                }
            },
        )
        null -> Unit
    }
}

@Composable
private fun ConfirmDialog(prompt: Prompt.Confirm) {
    val confirmation = prompt.confirmation
    val dismissFocus = remember { FocusRequester() }
    AlertDialog(
        onDismissRequest = { prompt.answer(false) },
        title = confirmation.title?.let { title -> { Text(text = title) } },
        text = {
            Text(text = confirmation.message, modifier = Modifier.verticalScroll(rememberScrollState()))
        },
        confirmButton = {
            TextButton(onClick = { prompt.answer(true) }) {
                Text(text = confirmation.confirm)
            }
        },
        dismissButton = {
            TextButton(onClick = { prompt.answer(false) }, modifier = Modifier.focusRequester(dismissFocus)) {
                Text(text = confirmation.dismiss)
            }
        },
    )
    if (confirmation.destructive) LaunchedEffect(prompt) { dismissFocus.requestFocus() }
}

@Composable
private fun TextInputDialog(
    title: String,
    hint: String,
    keyboardType: KeyboardType,
    onDone: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var text by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        // The title is part of the text: AlertDialog places the text by its first baseline, which is the label inside
        // the empty field and moves up when the label floats on focus, so the field jumped down on the first tap
        text = {
            Column {
                CompositionLocalProvider(LocalContentAlpha provides ContentAlpha.high) {
                    Text(text = title, style = MaterialTheme.typography.subtitle1)
                }
                Spacer(modifier = Modifier.height(16.dp))
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    label = { Text(text = hint) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
                    visualTransformation = if (keyboardType == KeyboardType.Password) {
                        PasswordVisualTransformation()
                    } else {
                        VisualTransformation.None
                    },
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onDone(text) }) {
                Text(text = stringResource(android.R.string.ok))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(text = stringResource(android.R.string.cancel))
            }
        },
    )
}
