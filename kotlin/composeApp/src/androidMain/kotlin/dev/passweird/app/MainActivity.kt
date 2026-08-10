package dev.passweird.app

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity

/**
 * FragmentActivity rather than ComponentActivity because BiometricPrompt needs
 * a FragmentManager to host its dialog.
 */
class MainActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Blocks screenshots, screen recording, and the thumbnail Android shows
        // in the recents switcher - which would otherwise leave a generated
        // password visible after the app is backgrounded.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

        val security = AndroidSecurity(this)
        val preferences = createPreferences(this)

        setContent {
            var unlocked by remember { mutableStateOf(false) }

            if (unlocked) {
                val state = remember { AppState(preferences) }
                App(state, security)
            } else {
                LockScreen(onUnlock = { security.authenticate { ok -> unlocked = ok } })
            }
        }
    }
}

@androidx.compose.runtime.Composable
private fun LockScreen(onUnlock: () -> Unit) {
    MaterialTheme {
        Column(
            Modifier.fillMaxSize().padding(32.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text("Passweird", style = MaterialTheme.typography.headlineMedium)
            Text(
                // Said plainly rather than implied: in a stateless generator the
                // gate guards app access, not the passwords. The master password
                // is never stored, so it remains the only thing that derives them.
                "Nothing is stored on this device. This lock guards app access; " +
                    "your master password is what protects the generated secrets.",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(vertical = 16.dp),
            )
            Button(onClick = onUnlock) { Text("Unlock") }
        }
    }
}
