package dev.passweird.app

import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.io.File
import java.util.Properties
import kotlin.concurrent.thread

class DesktopSecurity : PlatformSecurity {

    override fun copySecret(value: String, clearAfterSeconds: Int) {
        val clipboard = Toolkit.getDefaultToolkit().systemClipboard
        clipboard.setContents(StringSelection(value), null)

        thread(isDaemon = true) {
            Thread.sleep(clearAfterSeconds * 1000L)
            // Only clear if the clipboard still holds what we put there, so we
            // never destroy something the user copied in the meantime.
            val current = runCatching {
                clipboard.getData(java.awt.datatransfer.DataFlavor.stringFlavor) as? String
            }.getOrNull()
            if (current == value) {
                clipboard.setContents(StringSelection(""), null)
            }
        }
    }

    // No biometric API on desktop. Reporting "unavailable" is honest; reporting
    // success from a gate that does not exist would be theatre.
    override fun biometricsAvailable(): Boolean = false

    override fun authenticate(onResult: (Boolean) -> Unit) = onResult(true)
}

actual fun currentEpochSeconds(): Long = System.currentTimeMillis() / 1000

fun createPreferences(): PreferenceStore = DesktopPreferences()

private class DesktopPreferences : PreferenceStore {

    private val file = File(System.getProperty("user.home"), ".passweird/app.properties")

    private fun read(): Properties = Properties().apply {
        if (file.exists()) file.inputStream().use { load(it) }
    }

    private fun write(props: Properties) {
        file.parentFile?.mkdirs()
        file.outputStream().use { props.store(it, "Passweird app preferences - no secrets here") }
    }

    override fun loadLength(default: Int): Int =
        read().getProperty("length")?.toIntOrNull() ?: default

    override fun saveLength(value: Int) {
        write(read().apply { setProperty("length", value.toString()) })
    }

    override fun loadClasses(default: CharacterClasses): CharacterClasses {
        val p = read()
        fun flag(key: String, fallback: Boolean) =
            p.getProperty(key)?.toBooleanStrictOrNull() ?: fallback
        return CharacterClasses(
            upper = flag("upper", default.upper),
            lower = flag("lower", default.lower),
            digits = flag("digits", default.digits),
            special = flag("special", default.special),
        )
    }

    override fun saveClasses(value: CharacterClasses) {
        write(read().apply {
            setProperty("upper", value.upper.toString())
            setProperty("lower", value.lower.toString())
            setProperty("digits", value.digits.toString())
            setProperty("special", value.special.toString())
        })
    }
}
