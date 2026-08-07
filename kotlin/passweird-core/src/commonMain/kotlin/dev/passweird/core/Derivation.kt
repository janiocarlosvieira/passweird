package dev.passweird.core

/**
 * Passweird's deterministic derivation core.
 *
 * This is a second implementation of a specification whose normative form is the
 * Python code (ADR-0008). Every function here must reproduce its Python
 * counterpart bit for bit — a password that is "almost right" is simply a wrong
 * password, discovered when someone is locked out of an account.
 *
 * Correctness is not argued, it is asserted: `DerivationVectorsTest` runs the
 * same `tests/vectors/derivation-v1.json` the Python suite runs.
 */
object Derivation {

    const val ENGINE_VERSION: String = "v2"

    private const val LOWERS = "abcdefghijklmnopqrstuvwxyz"
    private const val UPPERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val DIGITS = "0123456789"
    private const val SPECIALS = "!@#\$%^&*()_+-=."

    /**
     * Pre-hash applied to the master password and to the context string.
     *
     * Mirrors Python's `modified_hash`: SHA-256 to hex, drop the final hex
     * character, then SHA-256 over that shortened **ASCII string** — not over the
     * bytes it represents.
     */
    fun modifiedHash(value: String): String {
        val firstHash = sha256(value.encodeToByteArray()).toHex()
        val withoutLast = firstHash.substring(0, firstHash.length - 1)
        return sha256(withoutLast.encodeToByteArray()).toHex()
    }

    /** Blends keyfile / FIDO2 entropy into an already-computed hash. */
    fun blendSecondaryFactor(baseHash: String, factorBytes: ByteArray): String =
        sha256(baseHash.encodeToByteArray() + sha256(factorBytes)).toHex()

    /**
     * HKDF-Expand (RFC 5869) over HMAC-SHA512 — Expand only, with no Extract step.
     *
     * Note the PRK is the 64-character hex **string** encoded as ASCII, not the
     * 32 raw bytes it represents. That is what the Python implementation does, so
     * that is what this must do.
     */
    fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val hashLen = 64
        require(length <= 255 * hashLen) { "Requested length too large for HKDF-Expand." }

        val okm = ByteArray(length)
        var t = ByteArray(0)
        var i = 1
        var filled = 0
        while (filled < length) {
            t = hmacSha512(prk, t + info + byteArrayOf(i.toByte()))
            val take = minOf(t.size, length - filled)
            t.copyInto(okm, filled, 0, take)
            filled += take
            i++
        }
        return okm
    }

    /**
     * Deterministic password generation with the compliance retry loop.
     *
     * The single most dangerous line in this file is the charset index. Python
     * iterates bytes as unsigned 0..255; on the JVM `Byte` is -128..127 and `%`
     * preserves the sign, which yields negative indices for roughly half of every
     * derivation — and still produces a plausible-looking password. `and 0xFF` is
     * what keeps the two implementations identical.
     */
    fun generatePassword(
        masterHash: String,
        appHash: String,
        length: Int = 18,
        useUpper: Boolean = true,
        useLower: Boolean = true,
        useDigits: Boolean = true,
        useSpecial: Boolean = true,
        temporalSalt: String = "",
    ): String {
        val isNumericOnly = useDigits && !(useUpper || useLower || useSpecial)
        val minLen = if (isNumericOnly) 6 else 8
        require(length >= minLen) { "Minimum recommended length is $minLen characters." }

        val lowers = if (useLower) LOWERS else ""
        val uppers = if (useUpper) UPPERS else ""
        val digits = if (useDigits) DIGITS else ""
        val specials = if (useSpecial) SPECIALS else ""

        // Order is load-bearing: the charset is indexed by `byte % length`, so any
        // reordering changes every password ever generated.
        val charset = lowers + uppers + digits + specials
        require(charset.isNotEmpty()) { "At least one character type must be enabled." }

        var nonce = 0
        while (true) {
            val info = "$appHash:$length:$temporalSalt:$nonce".encodeToByteArray()
            val raw = hkdfExpand(masterHash.encodeToByteArray(), info, length)

            val password = buildString(length) {
                for (b in raw) append(charset[(b.toInt() and 0xFF) % charset.length])
            }

            val ok = (!useLower || password.any { it in lowers }) &&
                (!useUpper || password.any { it in uppers }) &&
                (!useDigits || password.any { it in digits }) &&
                (!useSpecial || password.any { it in specials })

            if (ok) return password
            nonce++
        }
    }

    /** Version router, mirroring Python's `generate_password`. */
    fun generatePasswordVersioned(
        version: String,
        masterHash: String,
        appHash: String,
        length: Int = 18,
        useUpper: Boolean = true,
        useLower: Boolean = true,
        useDigits: Boolean = true,
        useSpecial: Boolean = true,
        temporalSalt: String = "",
    ): String {
        require(version == ENGINE_VERSION) {
            "This cryptographic engine only supports standardized v2 (HKDF)."
        }
        return generatePassword(
            masterHash, appHash, length, useUpper, useLower, useDigits, useSpecial, temporalSalt,
        )
    }

    /** 160-bit TOTP seed, Base32-encoded (RFC 4648) with padding stripped. */
    fun generateTotpSecret(masterHash: String, appHash: String, temporalSalt: String = ""): String {
        val info = "$appHash:totp_seed:$temporalSalt".encodeToByteArray()
        val seed = hkdfExpand(masterHash.encodeToByteArray(), info, 20)
        return base32Encode(seed).trimEnd('=')
    }

    /** 20-character visual summary of a hash, used by the local log. */
    fun summarizeHash(hashValue: String): String =
        hashValue.substring(0, 10) + hashValue.substring(hashValue.length - 10)

    /** Hashes a password and returns its 20-character summary. */
    fun summarizePasswordHash(password: String): String =
        summarizeHash(sha256(password.encodeToByteArray()).toHex())

    private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    private fun base32Encode(data: ByteArray): String {
        if (data.isEmpty()) return ""
        val out = StringBuilder()
        var buffer = 0
        var bitsLeft = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                out.append(BASE32_ALPHABET[(buffer shr (bitsLeft - 5)) and 0x1F])
                bitsLeft -= 5
            }
        }
        if (bitsLeft > 0) {
            out.append(BASE32_ALPHABET[(buffer shl (5 - bitsLeft)) and 0x1F])
        }
        while (out.length % 8 != 0) out.append('=')
        return out.toString()
    }
}
