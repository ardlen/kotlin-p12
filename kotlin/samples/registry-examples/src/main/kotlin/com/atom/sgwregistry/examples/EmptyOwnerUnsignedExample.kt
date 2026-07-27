package com.atom.sgwregistry.examples

import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.builder.VerAttribute
import com.atom.sgwregistry.util.parseRfc3339Instant
import java.nio.file.Files
import java.nio.file.Path

/**
 * Пустой owner **без подписи**: только SafeContents (0 bags) + черновик заголовка.
 *
 * Этот пример — когда ключа ещё нет / подпись будет позже.
 *`empty-owner-unsigned` — без аргументов
 *`empty-owner-unsigned kotlin-out/owner-unsigned MYVIN 'CN=Draft' 2026-03-01T08:30:00Z 1` — с аргументами
 * ./gradlew :samples:registry-examples:run --args="empty-owner-unsigned"
 * ./gradlew :samples:registry-examples:run --args="empty-owner-unsigned kotlin-out/owner-unsigned MYVIN 'CN=Draft' 2026-03-01T08:30:00Z 1"
 * ```
 *
 * Пишет:
 * - `{outPrefix}.safecontents.der` — SEQUENCE OF SafeBag (пусто)
 * - `{outPrefix}.header.json` — VIN / UID / VER для последующего `empty-owner`
 */
object EmptyOwnerUnsignedExample {
    fun run(
        outPrefix: Path,
        vin: String = "DRAFT-VIN",
        uid: String = "CN=Draft Owner",
        verTimestamp: String = "2026-01-01T00:00:00Z",
        verVersion: Int = 1,
    ) {
        SampleSupport.section("Empty owner — unsigned (SafeContents + header draft)")

        require(vin.isNotBlank()) { "vin required" }
        require(uid.isNotBlank()) { "uid required" }
        require(verVersion > 0) { "verVersion must be >= 1" }

        val ts = parseRfc3339Instant(verTimestamp)
        val verText = VerAttribute.formatText(ts, verVersion)

        println("No signer key — CMS / .p12 not built.")
        println("header draft (for later empty-owner):")
        println("  VIN: $vin")
        println("  UID: $uid")
        println("  VER: $verText")
        println()

        val safeContents = RegistryBuilder.buildSafeContents(emptyList())
        Files.createDirectories(outPrefix.parent)

        val derPath = Path.of(outPrefix.toString() + ".safecontents.der")
        val headerPath = Path.of(outPrefix.toString() + ".header.json")

        Files.write(derPath, safeContents)
        val headerJson = buildString {
            appendLine("{")
            appendLine("""  "vin": ${jsonString(vin)},""")
            appendLine("""  "uid": ${jsonString(uid)},""")
            appendLine("""  "verTimestamp": ${jsonString(verTimestamp)},""")
            appendLine("""  "verVersion": $verVersion,""")
            appendLine("""  "verText": ${jsonString(verText)},""")
            appendLine("""  "safeBags": [],""")
            appendLine("""  "note": "Unsigned draft. Sign with: empty-owner owner-empty-config.json kotlin-out/owner.p12 <vin> <uid> <verTimestamp> <verVersion>" """)
            appendLine("}")
        }
        Files.write(headerPath, headerJson.encodeToByteArray())

        println("buildSafeContents: ${safeContents.size} bytes (empty SEQUENCE)")
        println("written: $derPath")
        println("written: $headerPath")
        println()
        println("Next (when signer is available):")
        println(
            "  ./gradlew :samples:registry-examples:run --args=" +
                "\"empty-owner owner-empty-config.json kotlin-out/owner.p12 " +
                "${shellArg(vin)} ${shellArg(uid)} $verTimestamp $verVersion\"",
        )
    }

    private fun jsonString(s: String): String =
        "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

    private fun shellArg(s: String): String =
        if (s.any { it.isWhitespace() || it == '\'' || it == '"' }) "'$s'" else s
}
