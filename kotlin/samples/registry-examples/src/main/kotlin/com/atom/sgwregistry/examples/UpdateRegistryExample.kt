package com.atom.sgwregistry.examples

import com.atom.sgwregistry.api.SgwRegistry
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.builder.RegistryConverters
import com.atom.sgwregistry.config.ConfigLoader
import com.atom.sgwregistry.crypto.PemUtils
import com.atom.sgwregistry.model.AddCertificateRequest
import com.atom.sgwregistry.model.RemoveCertificateBySkidRequest
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.verifier.SignatureVerifier
import java.nio.file.Files
import java.nio.file.Path

/**
 * Полный сценарий: добавить сертификат → проверить → удалить по SKID → проверить.
 *
 * Демонстрирует:
 * - [RegistryBuilder.addCertificateAndResign]
 * - [RegistryBuilder.removeCertificateBySkidAndResign]
 * - фасад [SgwRegistry]
 * - перегрузки с hex SKID
 */
object UpdateRegistryExample {
    fun run(p12Path: Path, configPath: Path, addedPath: Path, finalPath: Path) {
        SampleSupport.section("Update registry: add → verify → remove → verify")

        val p12 = SampleSupport.readBytes(p12Path)
        val before = RegistryParser.parse(p12)
        println("1) input: $p12Path (${before.safeBagInfos.size} safeBags)")
        SampleSupport.printVer("   VER before changes", before)

        val configDir = configPath.parent?.toString() ?: "."
        val buildConfig = ConfigLoader.toBuildConfig(
            ConfigLoader.readConfig(configPath.toString()),
            configDir,
        )
        val newBag = pickBagToAdd(before, buildConfig)
        val newBagSkid = newBag.localKeyId
            ?: PemUtils.getSubjectKeyId(PemUtils.loadCertificate(newBag.certDer))
        val skidHex = PemUtils.skidToHex(newBagSkid)
        println("   cert to add: role=${newBag.roleName}, SKID=$skidHex")

        // --- addCertificateAndResign (вариант 1: AddCertificateRequest) ---
        println()
        println("2) RegistryBuilder.addCertificateAndResign(container, AddCertificateRequest(...))")
        val withAdded = RegistryBuilder.addCertificateAndResign(
            before,
            AddCertificateRequest(
                existingP12 = p12,
                newBag = newBag,
                signerCertDer = buildConfig.signerCertDer,
                signerKey = buildConfig.signerKey,
            ),
        )
        Files.createDirectories(addedPath.parent)
        Files.write(addedPath, withAdded)
        val afterAdd = RegistryParser.parse(withAdded)
        SampleSupport.printVerBump(before, afterAdd)
        println("   safeBags: ${before.safeBagInfos.size} → ${afterAdd.safeBagInfos.size}")
        println("   written: $addedPath")
        SignatureVerifier.verifyRegistry(withAdded)
        println("   verifyRegistry: OK")

        printSafeBagSkids(afterAdd, "   bags after add:")

        // --- removeCertificateBySkidAndResign (вариант 2: hex-перегрузка) ---
        println()
        println("3) RegistryBuilder.removeCertificateBySkidAndResign(container, RemoveCertificateBySkidRequest(...))")
        val afterRemoveBytes = RegistryBuilder.removeCertificateBySkidAndResign(
            afterAdd,
            RemoveCertificateBySkidRequest(
                existingP12 = withAdded,
                subjectKeyId = newBagSkid,
                signerCertDer = buildConfig.signerCertDer,
                signerKey = buildConfig.signerKey,
            ),
        )
        Files.write(finalPath, afterRemoveBytes)
        val afterRemove = RegistryParser.parse(afterRemoveBytes)
        SampleSupport.printVerBump(afterAdd, afterRemove)
        println("   safeBags: ${afterAdd.safeBagInfos.size} → ${afterRemove.safeBagInfos.size}")
        println("   written: $finalPath")
        SignatureVerifier.verifyRegistry(afterRemoveBytes)
        println("   verifyRegistry: OK")

        // --- фасад SgwRegistry (вариант 3: повторное добавление на финальный файл для демо API) ---
        println()
        println("4) SgwRegistry.addCertificateAndResign / removeCertificateBySkidAndResign")
        val viaFacadeAdd = SgwRegistry.addCertificateAndResign(
            AddCertificateRequest(
                existingP12 = afterRemoveBytes,
                newBag = newBag,
                signerCertDer = buildConfig.signerCertDer,
                signerKey = buildConfig.signerKey,
                rejectDuplicateCert = false,
            ),
        )
        SgwRegistry.verifyRegistry(viaFacadeAdd)
        val viaFacadeRemove = SgwRegistry.removeCertificateBySkidAndResign(
            RemoveCertificateBySkidRequest(
                existingP12 = viaFacadeAdd,
                subjectKeyId = newBagSkid,
                signerCertDer = buildConfig.signerCertDer,
                signerKey = buildConfig.signerKey,
            ),
        )
        SgwRegistry.verifyRegistry(viaFacadeRemove)
        println("   SgwRegistry round-trip: OK (back to ${RegistryParser.parse(viaFacadeRemove).safeBagInfos.size} bags)")
    }

    private fun pickBagToAdd(
        before: com.atom.sgwregistry.model.RegistryContainer,
        buildConfig: com.atom.sgwregistry.model.BuildConfig,
    ) = buildConfig.safeBags.firstOrNull { candidate ->
        val existing = before.safeBagInfos.mapNotNull { it.certValueDer }
        existing.none { it.contentEquals(candidate.certDer) }
    } ?: throw IllegalStateException("No cert in config that is missing from registry")

    private fun printSafeBagSkids(
        container: com.atom.sgwregistry.model.RegistryContainer,
        prefix: String,
    ) {
        val bags = RegistryConverters.safeBagInfosToInputs(container.safeBagInfos)
        bags.forEachIndexed { i, bag ->
            val skid = bag.localKeyId
                ?: PemUtils.getSubjectKeyId(PemUtils.loadCertificate(bag.certDer))
            println("$prefix [$i] role=${bag.roleName} SKID=${PemUtils.skidToHex(skid)}")
        }
    }
}
