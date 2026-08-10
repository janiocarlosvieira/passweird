package dev.passweird.app

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity

/**
 * Android is the platform Passweird's threat model actually changes on: a phone
 * is lost and stolen far more often than a workstation, and it holds the master
 * password in an input field.
 */
class AndroidSecurity(private val activity: FragmentActivity) : PlatformSecurity {

    private val clipboard by lazy {
        activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    }

    override fun copySecret(value: String, clearAfterSeconds: Int) {
        val clip = ClipData.newPlainText("passweird", value).apply {
            // Android 13+ omits the value from the clipboard preview toast when
            // the item is marked sensitive - otherwise the password is shown on
            // screen precisely as the user copies it.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                description.extras = PersistableBundle().apply {
                    putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                }
            }
        }
        clipboard.setPrimaryClip(clip)

        Handler(Looper.getMainLooper()).postDelayed({
            // Only clear if our value is still there, so we never destroy
            // something the user copied in the meantime.
            val current = clipboard.primaryClip?.getItemAt(0)?.text?.toString()
            if (current == value) {
                clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        }, clearAfterSeconds * 1000L)
    }

    override fun biometricsAvailable(): Boolean =
        BiometricManager.from(activity).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_WEAK or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL,
        ) == BiometricManager.BIOMETRIC_SUCCESS

    override fun authenticate(onResult: (Boolean) -> Unit) {
        if (!biometricsAvailable()) {
            // No enrolled biometric and no device credential: refusing to start
            // would lock the user out of a tool that stores nothing, so the gate
            // simply does not apply.
            onResult(true)
            return
        }

        val prompt = BiometricPrompt(
            activity,
            androidx.core.content.ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) =
                    onResult(true)

                override fun onAuthenticationError(code: Int, message: CharSequence) =
                    onResult(false)
            },
        )

        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock Passweird")
                .setSubtitle("Passweird stores nothing; this only guards app access.")
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_WEAK or
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                )
                .build(),
        )
    }
}

actual fun currentEpochSeconds(): Long = System.currentTimeMillis() / 1000

fun createPreferences(context: Context): PreferenceStore = AndroidPreferences(context)

/**
 * SharedPreferences rather than DataStore: these are five non-secret values read
 * once at startup, and DataStore's coroutine API would push suspend functions
 * through the whole shared state layer for no benefit.
 */
private class AndroidPreferences(context: Context) : PreferenceStore {

    private val prefs = context.getSharedPreferences("passweird", Context.MODE_PRIVATE)

    override fun loadLength(default: Int): Int = prefs.getInt("length", default)

    override fun saveLength(value: Int) = prefs.edit { putInt("length", value) }

    override fun loadClasses(default: CharacterClasses) = CharacterClasses(
        upper = prefs.getBoolean("upper", default.upper),
        lower = prefs.getBoolean("lower", default.lower),
        digits = prefs.getBoolean("digits", default.digits),
        special = prefs.getBoolean("special", default.special),
    )

    override fun saveClasses(value: CharacterClasses) = prefs.edit {
        putBoolean("upper", value.upper)
        putBoolean("lower", value.lower)
        putBoolean("digits", value.digits)
        putBoolean("special", value.special)
    }
}
