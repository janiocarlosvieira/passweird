package dev.passweird.core

/**
 * RFC 6238 TOTP, over the secrets [Derivation.generateTotpSecret] produces.
 *
 * The Python reference delegates this to `pyotp`, which an app cannot do, so it
 * is implemented here. The parameters are not configurable on purpose: they are
 * pyotp's defaults, which are also what authenticator apps assume, and changing
 * any of them would produce codes that neither the CLI nor Google Authenticator
 * would agree with.
 */
object Totp {

    const val DIGITS: Int = 6
    const val PERIOD_SECONDS: Int = 30
    const val ISSUER: String = "Passweird"

    /**
     * The code valid at [epochSeconds]. Takes the time explicitly rather than
     * reading a clock, so callers can be tested at fixed instants - a test using
     * "now" would pass under any wrong time offset.
     */
    fun codeAt(secretBase32: String, epochSeconds: Long): String {
        val counter = epochSeconds / PERIOD_SECONDS
        val key = Base32.decode(secretBase32)

        // 8-byte big-endian counter, per RFC 4226.
        val message = ByteArray(8)
        var value = counter
        for (i in 7 downTo 0) {
            message[i] = (value and 0xFF).toByte()
            value = value ushr 8
        }

        val digest = hmacSha1(key, message)

        // Dynamic truncation (RFC 4226 §5.3): the low nibble of the last byte
        // selects the offset; the high bit of the extracted word is masked off so
        // the result is unambiguously positive regardless of platform sign rules.
        val offset = digest[digest.size - 1].toInt() and 0x0F
        val binary = ((digest[offset].toInt() and 0x7F) shl 24) or
            ((digest[offset + 1].toInt() and 0xFF) shl 16) or
            ((digest[offset + 2].toInt() and 0xFF) shl 8) or
            (digest[offset + 3].toInt() and 0xFF)

        var modulus = 1
        repeat(DIGITS) { modulus *= 10 }
        return (binary % modulus).toString().padStart(DIGITS, '0')
    }

    /** Seconds until the current code expires, for a countdown indicator. */
    fun secondsRemaining(epochSeconds: Long): Int =
        (PERIOD_SECONDS - (epochSeconds % PERIOD_SECONDS)).toInt()

    /**
     * `otpauth://` URI, byte-identical to what pyotp's `provisioning_uri`
     * emits for the same inputs - so a QR scanned from the app and one from the
     * CLI enrol the same account.
     */
    fun provisioningUri(secretBase32: String, context: String): String {
        val label = "$ISSUER:${percentEncode(context)}"
        return "otpauth://totp/$label?secret=$secretBase32&issuer=$ISSUER"
    }

    /**
     * Percent-encodes UTF-8 bytes, matching Python's `urllib.parse.quote`, whose
     * unreserved set is the RFC 3986 one plus `_.-~`. Notably `@` IS encoded,
     * which matters because contexts are often email addresses.
     */
    private fun percentEncode(value: String): String {
        val unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~"
        val hex = "0123456789ABCDEF"
        val out = StringBuilder()
        for (b in value.encodeToByteArray()) {
            val c = (b.toInt() and 0xFF).toChar()
            if (c in unreserved) {
                out.append(c)
            } else {
                val v = b.toInt() and 0xFF
                out.append('%').append(hex[v ushr 4]).append(hex[v and 0x0F])
            }
        }
        return out.toString()
    }
}
