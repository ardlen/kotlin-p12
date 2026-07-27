package com.atom.sgwregistry.examples

import com.atom.sgwregistry.analyzer.RegistryAnalyzer
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.builder.VerAttribute
import com.atom.sgwregistry.config.ConfigLoader
import com.atom.sgwregistry.model.BuildConfig
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.util.parseRfc3339Instant
import com.atom.sgwregistry.verifier.SignatureVerifier
import java.nio.file.Files
import java.nio.file.Path

/**
 * Сборка **пустого** owner-реестра (0 SafeBag) с произвольными заголовочными
 * authenticatedAttributes: VIN, UID, VER.
 *
 * ```
 * ./gradlew :samples:registry-examples:run --args="empty-owner owner-empty-config.json kotlin-out/owner.p12"
 * ./gradlew :samples:registry-examples:run --args="empty-owner owner-empty-config.json kotlin-out/owner.p12 MYVIN 'CN=Demo Owner' 2026-01-15T10:00:00Z 3"
 * ```
 */
object EmptyOwnerP12Example {
    fun run(
        configPath: Path,
        outputPath: Path,
        vinOverride: String? = null,
        uidOverride: String? = null,
        verTimestampOverride: String? = null,
        verVersionOverride: Int? = null,
    ) {
        SampleSupport.section("Empty owner.p12 — header attrs only (no SafeBags)")

        val configDir = configPath.parent?.toString() ?: "."
        val fileConfig = ConfigLoader.readConfig(configPath.toString())
        require(fileConfig.safeBags.isEmpty()) {
            "empty-owner expects safeBags: [] in config (got ${fileConfig.safeBags.size}); " +
                "use `build` for a registry with certificates"
        }

        val base = ConfigLoader.toBuildConfig(fileConfig, configDir)
        val vin = vinOverride?.takeIf { it.isNotBlank() } ?: base.vin
        val uid = uidOverride?.takeIf { it.isNotBlank() } ?: base.uid
        val verTimestamp = if (!verTimestampOverride.isNullOrBlank()) {
            parseRfc3339Instant(verTimestampOverride)
        } else {
            base.verTimestamp
        }
        val verVersion = verVersionOverride ?: base.verVersion

        require(vin.isNotBlank()) { "vin is required (config or CLI)" }
        require(uid.isNotBlank()) { "uid is required (config or CLI)" }
        require(verVersion > 0) { "verVersion must be >= 1 (got $verVersion)" }

        val buildConfig = BuildConfig(
            signerCertDer = base.signerCertDer,
            signerKey = base.signerKey,
            vin = vin,
            uid = uid,
            verTimestamp = verTimestamp,
            verVersion = verVersion,
            safeBags = emptyList(),
        )

        println("header (authenticatedAttributes):")
        println("  VIN: $vin")
        println("  UID: $uid")
        println("  VER: ${VerAttribute.formatText(verTimestamp, verVersion)}")
        println("  safeBags: 0 (empty SafeContents)")
        println()

        val p12 = RegistryBuilder.buildRegistry(buildConfig)
        Files.createDirectories(outputPath.parent)
        Files.write(outputPath, p12)
        println("buildRegistry: ${p12.size} bytes → $outputPath")

        val parsed = RegistryParser.parse(p12)
        println("round-trip safeBags: ${parsed.safeBagInfos.size}")
        println("signerCertResolved: ${parsed.signerCertResolved}")

        val attrs = RegistryAnalyzer.parseAuthenticatedAttributes(parsed.authenticatedAttributesSetBytes)
        println()
        println("=== authenticatedAttributes in owner.p12 ===")
        for ((name, value) in attrs) {
            println("  $name: $value")
        }
        SampleSupport.printVer("VER check", parsed)

        SignatureVerifier.verifyRegistry(p12)
        println()
        println("verifyRegistry: OK")
    }
}
