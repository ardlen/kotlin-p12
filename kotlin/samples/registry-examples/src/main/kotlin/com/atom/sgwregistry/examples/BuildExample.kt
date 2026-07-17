package com.atom.sgwregistry.examples

import com.atom.sgwregistry.analyzer.RegistryAnalyzer
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.builder.VerAttribute
import com.atom.sgwregistry.config.ConfigLoader
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.verifier.SignatureVerifier
import java.nio.file.Files
import java.nio.file.Path

/**
 * Пример: сборка из config.json и round-trip verify.
 */
object BuildExample {
    fun run(configPath: Path, outputPath: Path) {
        SampleSupport.section("ConfigLoader → RegistryBuilder.buildRegistry")

        val configDir = configPath.parent?.toString() ?: "."
        val fileConfig = ConfigLoader.readConfig(configPath.toString())
        val buildConfig = ConfigLoader.toBuildConfig(fileConfig, configDir)

        val eContentOnly = RegistryBuilder.buildSafeContents(buildConfig.safeBags)
        println("buildSafeContents: ${eContentOnly.size} bytes (SEQUENCE OF SafeBag)")

        val p12 = RegistryBuilder.buildRegistry(buildConfig)
        Files.write(outputPath, p12)
        println("buildRegistry: ${p12.size} bytes → $outputPath")

        val parsed = RegistryParser.parse(p12)
        println("round-trip safeBags: ${parsed.safeBagInfos.size} (expected ${buildConfig.safeBags.size})")
        println("signerCertResolved: ${parsed.signerCertResolved}")
        val configVer = VerAttribute.formatText(buildConfig.verTimestamp, buildConfig.verVersion)
        println("VER from config: $configVer")
        SampleSupport.printVer("VER in built .p12", parsed)

        try {
            SignatureVerifier.verifyRegistry(p12)
            println("verifyRegistry(built): OK")
        } catch (e: Exception) {
            println("verifyRegistry(built): FAIL — ${e.message}")
        }
    }
}
