package dev.passweird.app

/**
 * Platform capabilities the screens need but cannot implement themselves.
 *
 * Plain interfaces, constructed by each platform's entry point and injected into
 * [App], rather than expect/actual classes. The Android implementation needs an
 * Activity, which an expect class with no constructor parameters cannot express -
 * and injecting them keeps `commonMain` free of Android-only branches while
 * letting tests substitute doubles.
 */
interface PlatformSecurity {

    /**
     * Copies a secret to the clipboard, marking it sensitive where the platform
     * supports it and clearing it after [clearAfterSeconds].
     *
     * A password generator that leaves the password on the clipboard indefinitely
     * has undone most of its own work: on a phone every app that gains focus can
     * read it.
     */
    fun copySecret(value: String, clearAfterSeconds: Int = 45)

    /** Whether a biometric gate can be shown at all on this device. */
    fun biometricsAvailable(): Boolean

    /**
     * Requests biometric authentication, invoking [onResult] with the outcome.
     * Platforms without biometrics report success immediately - the gate is
     * defence in depth, never the thing protecting the derived passwords.
     */
    fun authenticate(onResult: (Boolean) -> Unit)
}

/** Wall-clock seconds since the epoch, for the TOTP countdown. */
expect fun currentEpochSeconds(): Long

/**
 * The only state persisted on the device: output shape, never anything secret
 * and never anything revealing which services the user has an account with.
 *
 * An interface rather than an `expect class` so tests can substitute a plain
 * in-memory double - an expect class cannot be implemented in `commonTest`.
 */
interface PreferenceStore {
    fun loadLength(default: Int): Int
    fun saveLength(value: Int)
    fun loadClasses(default: CharacterClasses): CharacterClasses
    fun saveClasses(value: CharacterClasses)
}

data class CharacterClasses(
    val upper: Boolean = true,
    val lower: Boolean = true,
    val digits: Boolean = true,
    val special: Boolean = true,
) {
    /** Mirrors the core's rule: digits-only allows 6, everything else needs 8. */
    val minimumLength: Int
        get() = if (digits && !(upper || lower || special)) 6 else 8

    val anyEnabled: Boolean get() = upper || lower || digits || special
}
