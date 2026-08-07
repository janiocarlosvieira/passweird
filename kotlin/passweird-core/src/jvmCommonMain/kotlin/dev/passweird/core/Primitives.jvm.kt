package dev.passweird.core

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal actual fun sha256(data: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").digest(data)

internal actual fun sha512(data: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-512").digest(data)

internal actual fun hmacSha512(key: ByteArray, message: ByteArray): ByteArray =
    Mac.getInstance("HmacSHA512").apply {
        init(SecretKeySpec(key, "HmacSHA512"))
    }.doFinal(message)
