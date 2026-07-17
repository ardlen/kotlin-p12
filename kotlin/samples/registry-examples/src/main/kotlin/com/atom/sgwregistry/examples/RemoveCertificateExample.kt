package com.atom.sgwregistry.examples

import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.config.ConfigLoader
import com.atom.sgwregistry.crypto.PemUtils
import com.atom.sgwregistry.model.RemoveCertificateBySkidRequest
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.verifier.SignatureVerifier
import java.nio.file.Files
import java.nio.file.Path

/**
 * Пример: удалить сертификат из .p12 по SKID и переподписать реестр.
 * При изменении реестра VER обязателен и автоматически увеличивается (Vn→V{n+1}).
 *
 * Не путать с [UpdateRegistryExample]: здесь удаляется bag по явному SKID (или первый из
 * config, уже присутствующий в реестре). `update-registry` после add удаляет только что
 * добавленный сертификат (round-trip), а не произвольный существующий bag.
 */
object RemoveCertificateExample {
    fun run(p12Path: Path, configPath: Path, outputPath: Path, subjectKeyIdHex: String?) {
        SampleSupport.section("RegistryBuilder.removeCertificateBySkidAndResign")

        val p12 = SampleSupport.readBytes(p12Path)
        val before = RegistryParser.parse(p12)
        println("input: $p12Path (${before.safeBagInfos.size} safeBags)")

        val configDir = configPath.parent?.toString() ?: "."
        val buildConfig = ConfigLoader.toBuildConfig(ConfigLoader.readConfig(configPath.toString()), configDir)

        val skidHex = subjectKeyIdHex?.takeIf { it.isNotBlank() }
            ?: resolveSkidHexToRemove(before, buildConfig)
            ?: throw IllegalStateException("Cannot determine SKID to remove; pass subjectKeyIdHex argument")

        println("removing SKID: $skidHex")
        SampleSupport.printVer("VER before remove", before)
        println("API: RegistryBuilder.removeCertificateBySkidAndResign — VER auto-bump required")

        val updated = RegistryBuilder.removeCertificateBySkidAndResign(
            before,
            RemoveCertificateBySkidRequest(
                existingP12 = p12,
                subjectKeyId = PemUtils.decodeSkidHex(skidHex),
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

    /** Берёт SKID первого bag из config, который есть в реестре. */
    private fun resolveSkidHexToRemove(
        before: com.atom.sgwregistry.model.RegistryContainer,
        buildConfig: com.atom.sgwregistry.model.BuildConfig,
    ): String? {
        val bags = com.atom.sgwregistry.builder.RegistryConverters.safeBagInfosToInputs(before.safeBagInfos)
        for (candidate in buildConfig.safeBags) {
            val skid = candidate.localKeyId
                ?: PemUtils.getSubjectKeyId(PemUtils.loadCertificate(candidate.certDer))
            if (skid.isEmpty()) continue
            if (bags.any { com.atom.sgwregistry.builder.RegistryConverters.bagMatchesSkid(it, skid) }) {
                return PemUtils.skidToHex(skid)
            }
        }
        return null
    }
}
