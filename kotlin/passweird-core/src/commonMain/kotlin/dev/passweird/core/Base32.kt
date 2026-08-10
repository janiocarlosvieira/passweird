package dev.passweird.core

/**
 * RFC 4648 Base32, the encoding every authenticator app expects for TOTP secrets.
 *
 * Hand-rolled because `java.util.Base64` has no Base32 variant, and pulling a
 * dependency for this would not survive the move to non-JVM targets.
 */
internal object Base32 {

    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun encode(data: ByteArray): String {
        if (data.isEmpty()) return ""
        val out = StringBuilder()
        var buffer = 0
        var bitsLeft = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                out.append(ALPHABET[(buffer shr (bitsLeft - 5)) and 0x1F])
                bitsLeft -= 5
            }
        }
        if (bitsLeft > 0) {
            out.append(ALPHABET[(buffer shl (5 - bitsLeft)) and 0x1F])
        }
        while (out.length % 8 != 0) out.append('=')
        return out.toString()
    }

    /**
     * Tolerates missing padding and lowercase input: Passweird strips the `=`
     * padding from the secrets it emits, and users pasting a secret from another
     * tool may bring either form.
     */
    fun decode(encoded: String): ByteArray {
        val cleaned = encoded.trimEnd('=').uppercase().filterNot { it == ' ' || it == '-' }
        if (cleaned.isEmpty()) return ByteArray(0)

        val out = ArrayList<Byte>(cleaned.length * 5 / 8)
        var buffer = 0
        var bitsLeft = 0
        for (c in cleaned) {
            val index = ALPHABET.indexOf(c)
            require(index >= 0) { "Invalid Base32 character: '$c'" }
            buffer = (buffer shl 5) or index
            bitsLeft += 5
            if (bitsLeft >= 8) {
                out.add(((buffer shr (bitsLeft - 8)) and 0xFF).toByte())
                bitsLeft -= 8
            }
        }
        // Any leftover bits are the encoder's padding, not data - discarded.
        return out.toByteArray()
    }
}
