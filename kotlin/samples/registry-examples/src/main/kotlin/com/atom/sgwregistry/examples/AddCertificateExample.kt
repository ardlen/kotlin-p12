package com.atom.sgwregistry.examples

import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.config.ConfigLoader
import com.atom.sgwregistry.model.AddCertificateRequest
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.verifier.SignatureVerifier
import java.nio.file.Files
import java.nio.file.Path

/**
 * Пример: добавить сертификат в существующий .p12 и переподписать реестр.
 *
 * При изменении реестра VER обязателен и автоматически увеличивается (Vn→V{n+1}).
 */
object AddCertificateExample {
    fun run(p12Path: Path, configPath: Path, outputPath: Path, bagIndex: Int = 0) {
        SampleSupport.section("RegistryBuilder.addCertificateAndResign")

        val p12 = SampleSupport.readBytes(p12Path)
        val before = RegistryParser.parse(p12)
        println("input: $p12Path (${before.safeBagInfos.size} safeBags)")

        val configDir = configPath.parent?.toString() ?: "."
        val buildConfig = ConfigLoader.toBuildConfig(ConfigLoader.readConfig(configPath.toString()), configDir)
        require(buildConfig.safeBags.isNotEmpty()) { "config safeBags is empty" }

        val existingDer = before.safeBagInfos.mapNotNull { it.certValueDer }
        val candidates = if (bagIndex >= 0 && bagIndex < buildConfig.safeBags.size) {
            listOf(buildConfig.safeBags[bagIndex])
        } else {
            buildConfig.safeBags
        }
        val newBag = candidates.firstOrNull { bag ->
            existingDer.none { it.contentEquals(bag.certDer) }
        } ?: throw IllegalStateException(
            "No safeBag in config that is not already in registry (try another bagIndex)",
        )
        println("adding: roleName=${newBag.roleName}, cert=${newBag.certDer.size} bytes")
        SampleSupport.printVer("VER before add", before)

        println("API: RegistryBuilder.addCertificateAndResign — VER auto-bump required")

        val updated = RegistryBuilder.addCertificateAndResign(
            before,
            AddCertificateRequest(
                existingP12 = p12,
                newBag = newBag,
                signerCertDer = buildConfig.signerCertDer,
                signerKey = buildConfig.signerKey,
            ),
        )

        Files.createDirectories(outputPath.parent)
        Files.write(outputPath, updated)
        println("output: $outputPath (${updated.size} bytes)")

        val after = RegistryParser.parse(updated)
        SampleSupport.printVerBump(before, after)
        println("safeBags: ${before.safeBagInfos.size} → ${after.safeBagInfos.size}")
        SignatureVerifier.verifyRegistry(updated)
        println("verifyRegistry(updated): OK")
    }
}
