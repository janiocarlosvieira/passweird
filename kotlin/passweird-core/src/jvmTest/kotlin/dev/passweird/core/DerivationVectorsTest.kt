package dev.passweird.core

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory

/**
 * Runs the golden derivation vectors (ADR-0008) against the Kotlin core.
 *
 * This reads the very same `tests/vectors/derivation-v1.json` the Python suite
 * asserts against — not a copy — so the two implementations can never drift onto
 * different files. Python is normative; a failure here means Kotlin is wrong.
 *
 * Cases are emitted as dynamic tests labelled by scenario, so a failure names the
 * case ("compliance-loop-ctx-5-nonce-2") instead of reporting a bare mismatch.
 */
class DerivationVectorsTest {

    private val vectors: JsonObject by lazy {
        val path = System.getProperty("passweird.vectors")
            ?: error("passweird.vectors system property not set (see build.gradle.kts)")
        val file = File(path)
        check(file.exists()) { "Vector file not found: $path" }
        Json.parseToJsonElement(file.readText()).jsonObject
    }

    private fun group(name: String) = vectors[name]!!.jsonArray.map { it.jsonObject }

    private fun JsonObject.str(key: String) = this[key]!!.jsonPrimitive.content
    private fun JsonObject.int(key: String) = this[key]!!.jsonPrimitive.int
    private fun JsonObject.bool(key: String) = this[key]!!.jsonPrimitive.boolean

    private fun hexToBytes(hex: String) =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @TestFactory
    fun `vector file metadata`(): List<DynamicTest> = listOf(
        DynamicTest.dynamicTest("format_version == 1") {
            assertEquals(1, vectors["format_version"]!!.jsonPrimitive.int)
        },
        DynamicTest.dynamicTest("engine_version == v2") {
            assertEquals(Derivation.ENGINE_VERSION, vectors["engine_version"]!!.jsonPrimitive.content)
        },
    )

    @TestFactory
    fun `modified_hash vectors`(): List<DynamicTest> = group("modified_hash").map { case ->
        DynamicTest.dynamicTest(case.str("label")) {
            assertEquals(case.str("expected"), Derivation.modifiedHash(case.str("input")))
        }
    }

    @TestFactory
    fun `blend_secondary_factor vectors`(): List<DynamicTest> =
        group("blend_secondary_factor").map { case ->
            DynamicTest.dynamicTest(case.str("label")) {
                assertEquals(
                    case.str("expected"),
                    Derivation.blendSecondaryFactor(
                        case.str("base_hash"), hexToBytes(case.str("factor_hex")),
                    ),
                )
            }
        }

    @TestFactory
    fun `hkdf_expand vectors`(): List<DynamicTest> = group("hkdf_expand").map { case ->
        DynamicTest.dynamicTest(case.str("label")) {
            val result = Derivation.hkdfExpand(
                case.str("prk_utf8").toByteArray(Charsets.UTF_8),
                case.str("info_utf8").toByteArray(Charsets.UTF_8),
                case.int("length"),
            )
            assertEquals(case.str("expected_hex"), result.toHex())
            assertEquals(case.int("length"), result.size)
        }
    }

    @TestFactory
    fun `password vectors`(): List<DynamicTest> = group("password").map { case ->
        DynamicTest.dynamicTest(case.str("label")) {
            // Intermediates first, so a divergence localizes to a stage rather
            // than only reporting that the final password differs.
            val masterHash = Derivation.modifiedHash(case.str("master_password"))
            val appHash = Derivation.modifiedHash(case.str("context"))
            assertEquals(case.str("master_hash"), masterHash, "master_hash stage")
            assertEquals(case.str("app_hash"), appHash, "app_hash stage")

            val password = Derivation.generatePasswordVersioned(
                version = "v2",
                masterHash = masterHash,
                appHash = appHash,
                length = case.int("length"),
                useUpper = case.bool("use_upper"),
                useLower = case.bool("use_lower"),
                useDigits = case.bool("use_digits"),
                useSpecial = case.bool("use_special"),
                temporalSalt = case.str("temporal_salt"),
            )
            assertEquals(case.str("expected_password"), password)
            assertEquals(case.int("length"), password.length)
        }
    }

    @TestFactory
    fun `raw hkdf stage at the final compliance nonce`(): List<DynamicTest> =
        group("password").map { case ->
            DynamicTest.dynamicTest(case.str("label")) {
                // Pins the bytes one step before the visible symptom: a signed-byte
                // port produces the right raw bytes and the wrong password, so this
                // separates "HKDF is wrong" from "indexing is wrong".
                val info = "${case.str("app_hash")}:${case.int("length")}:" +
                    "${case.str("temporal_salt")}:${case.int("compliance_nonce")}"
                val raw = Derivation.hkdfExpand(
                    case.str("master_hash").toByteArray(Charsets.UTF_8),
                    info.toByteArray(Charsets.UTF_8),
                    case.int("length"),
                )
                assertEquals(case.str("raw_hkdf_hex"), raw.toHex())
            }
        }

    @TestFactory
    fun `totp vectors`(): List<DynamicTest> = group("totp").map { case ->
        DynamicTest.dynamicTest(case.str("label")) {
            val secret = Derivation.generateTotpSecret(
                Derivation.modifiedHash(case.str("master_password")),
                Derivation.modifiedHash(case.str("context")),
                case.str("temporal_salt"),
            )
            assertEquals(case.str("expected_base32"), secret)
            assertEquals(32, secret.length)
            assertEquals(false, secret.contains('='))
        }
    }

    @TestFactory
    fun `summary vectors`(): List<DynamicTest> = group("summaries").map { case ->
        DynamicTest.dynamicTest(case.str("label")) {
            val actual = when (case.str("label")) {
                "summarize_hash" -> Derivation.summarizeHash(case.str("input"))
                "summarize_password_hash" -> Derivation.summarizePasswordHash(case.str("input"))
                else -> error("unknown summary case")
            }
            assertEquals(case.str("expected"), actual)
        }
    }
}
