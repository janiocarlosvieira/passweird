package dev.passweird.core

/**
 * Hash primitives, which `commonMain` does not provide.
 *
 * Android and Desktop are both JVM, so a single `actual` backed by
 * `java.security.MessageDigest` / `javax.crypto.Mac` covers both. Only an
 * eventual iOS target would need a second one.
 */
internal expect fun sha256(data: ByteArray): ByteArray

internal expect fun sha512(data: ByteArray): ByteArray

internal expect fun hmacSha512(key: ByteArray, message: ByteArray): ByteArray

/** Lowercase hex, matching Python's `hashlib.*.hexdigest()`. */
internal fun ByteArray.toHex(): String {
    val digits = "0123456789abcdef"
    val out = StringBuilder(size * 2)
    for (b in this) {
        val v = b.toInt() and 0xFF
        out.append(digits[v ushr 4]).append(digits[v and 0x0F])
    }
    return out.toString()
}
