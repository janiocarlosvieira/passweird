package dev.passweird.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import dev.passweird.core.Derivation
import dev.passweird.core.Totp

/**
 * Holds what the user typed and what was derived from it.
 *
 * Nothing here is persisted. The master password, context and temporal secret
 * exist only while the screen does - that is the whole premise, and it is why the
 * app has no vault to protect in the first place.
 */
class AppState(private val preferences: PreferenceStore) {

    var masterPassword by mutableStateOf("")
    var context by mutableStateOf("")
    var temporalSecret by mutableStateOf("")

    var length by mutableStateOf(preferences.loadLength(default = 18))
        private set
    var classes by mutableStateOf(preferences.loadClasses(default = CharacterClasses()))
        private set

    var generatedPassword by mutableStateOf<String?>(null)
        private set
    var totpSecret by mutableStateOf<String?>(null)
        private set
    var errorMessage by mutableStateOf<String?>(null)
        private set

    val inputsComplete: Boolean
        get() = masterPassword.isNotEmpty() && context.isNotEmpty()

    fun updateLength(value: Int) {
        length = value
        preferences.saveLength(value)
        invalidate()
    }

    fun updateClasses(value: CharacterClasses) {
        classes = value
        preferences.saveClasses(value)
        invalidate()
    }

    /**
     * Any change to an input invalidates the previous result. Leaving a stale
     * password on screen after the context is edited is how someone copies the
     * wrong one.
     */
    fun invalidate() {
        generatedPassword = null
        totpSecret = null
        errorMessage = null
    }

    fun generatePassword() {
        errorMessage = null
        try {
            val masterHash = Derivation.modifiedHash(masterPassword)
            val appHash = Derivation.modifiedHash(context)
            generatedPassword = Derivation.generatePasswordVersioned(
                version = Derivation.ENGINE_VERSION,
                masterHash = masterHash,
                appHash = appHash,
                length = length,
                useUpper = classes.upper,
                useLower = classes.lower,
                useDigits = classes.digits,
                useSpecial = classes.special,
                temporalSalt = temporalSecret,
            )
        } catch (e: IllegalArgumentException) {
            generatedPassword = null
            errorMessage = e.message
        }
    }

    fun generateTotp() {
        errorMessage = null
        totpSecret = Derivation.generateTotpSecret(
            Derivation.modifiedHash(masterPassword),
            Derivation.modifiedHash(context),
            temporalSecret,
        )
    }

    fun totpCodeNow(): String? = totpSecret?.let { Totp.codeAt(it, currentEpochSeconds()) }

    fun totpSecondsRemaining(): Int = Totp.secondsRemaining(currentEpochSeconds())

    fun totpUri(): String? = totpSecret?.let { Totp.provisioningUri(it, context) }

    /** Clears every secret held in memory, on leaving the screen. */
    fun clearSecrets() {
        masterPassword = ""
        temporalSecret = ""
        invalidate()
    }
}
