package dev.passweird.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay

@Composable
fun App(state: AppState, security: PlatformSecurity) {
    MaterialTheme {
        var tab by remember { mutableStateOf(0) }

        Column(Modifier.fillMaxSize()) {
            TabRow(selectedTabIndex = tab) {
                Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("Password") })
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("TOTP") })
            }

            Column(
                Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SecretInputs(state)

                when (tab) {
                    0 -> PasswordSection(state, security)
                    else -> TotpSection(state, security)
                }

                state.errorMessage?.let {
                    Text(it, color = MaterialTheme.colorScheme.error)
                }

                Spacer(Modifier.height(8.dp))
                TextButton(onClick = { state.clearSecrets() }) {
                    Text("Clear secrets from memory")
                }
            }
        }
    }
}

@Composable
private fun SecretInputs(state: AppState) {
    OutlinedTextField(
        value = state.masterPassword,
        onValueChange = { state.masterPassword = it; state.invalidate() },
        label = { Text("Master password") },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = state.context,
        onValueChange = { state.context = it; state.invalidate() },
        label = { Text("Context (e.g. github)") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = state.temporalSecret,
        onValueChange = { state.temporalSecret = it; state.invalidate() },
        label = { Text("Temporal secret (optional)") },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier.fillMaxWidth(),
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PasswordSection(state: AppState, security: PlatformSecurity) {
    val classes = state.classes

    Text("Length: ${state.length}", style = MaterialTheme.typography.labelLarge)
    Slider(
        value = state.length.toFloat(),
        onValueChange = { state.updateLength(it.toInt()) },
        valueRange = classes.minimumLength.toFloat()..64f,
        modifier = Modifier.fillMaxWidth(),
    )

    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        ClassChip("a-z", classes.lower) { state.updateClasses(classes.copy(lower = it)) }
        ClassChip("A-Z", classes.upper) { state.updateClasses(classes.copy(upper = it)) }
        ClassChip("0-9", classes.digits) { state.updateClasses(classes.copy(digits = it)) }
        ClassChip("!@#", classes.special) { state.updateClasses(classes.copy(special = it)) }
    }

    Button(
        onClick = { state.generatePassword() },
        enabled = state.inputsComplete && classes.anyEnabled,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text("Generate password")
    }

    state.generatedPassword?.let { password ->
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    password,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.titleMedium,
                )
                OutlinedButton(onClick = { security.copySecret(password) }) {
                    Text("Copy (clears in 45s)")
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ClassChip(label: String, selected: Boolean, onChange: (Boolean) -> Unit) {
    // The leading check mark is not decoration: without it a selected and an
    // unselected FilterChip differ only by a subtle container tint, and which
    // character classes are enabled changes every password generated.
    FilterChip(
        selected = selected,
        onClick = { onChange(!selected) },
        label = { Text(label) },
        leadingIcon = if (selected) {
            { Icon(Icons.Filled.Check, contentDescription = "enabled", Modifier.size(18.dp)) }
        } else {
            null
        },
    )
}

@Composable
private fun TotpSection(state: AppState, security: PlatformSecurity) {
    Button(
        onClick = { state.generateTotp() },
        enabled = state.inputsComplete,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text("Derive TOTP secret")
    }

    state.totpSecret?.let { secret ->
        // Recomposes once per second so the code and countdown stay live. The
        // clock is read here rather than inside the core, which takes the epoch
        // second explicitly so it can be tested at fixed instants.
        var tick by remember { mutableStateOf(0) }
        LaunchedEffect(secret) {
            while (true) {
                delay(1000)
                tick++
            }
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                @Suppress("UNUSED_EXPRESSION") tick
                Text(
                    state.totpCodeNow() ?: "",
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.headlineMedium,
                )
                Text(
                    "expires in ${state.totpSecondsRemaining()}s",
                    style = MaterialTheme.typography.labelMedium,
                )
                Text(
                    secret,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                )
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    OutlinedButton(onClick = { security.copySecret(secret) }) {
                        Text("Copy secret")
                    }
                    state.totpUri()?.let { uri ->
                        OutlinedButton(onClick = { security.copySecret(uri) }) {
                            Text("Copy otpauth URI")
                        }
                    }
                }
            }
        }
    }
}
