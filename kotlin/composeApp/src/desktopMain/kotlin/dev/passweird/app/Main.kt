package dev.passweird.app

import androidx.compose.runtime.remember
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState

fun main() = application {
    Window(
        onCloseRequest = ::exitApplication,
        title = "Passweird",
        state = rememberWindowState(size = DpSize(480.dp, 760.dp)),
    ) {
        val security = remember { DesktopSecurity() }
        val state = remember { AppState(createPreferences()) }
        App(state, security)
    }
}
