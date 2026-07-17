package com.atom.sgwregistry.examples

import com.atom.sgwregistry.config.ConfigLoader
import com.atom.sgwregistry.crypto.PemUtils
import com.atom.sgwregistry.builder.VerAttribute
import com.atom.sgwregistry.util.isEpoch
import java.nio.file.Path

/**
 * Пример: [ConfigLoader] и вспомогательные вызовы [PemUtils].
 *
 * Покрывает readConfig, resolvePath, validateConfig, parseRfc3339,
 * decodeLocalKeyId, toBuildConfig, getSubjectKeyId.
 */
object ConfigExample {
    fun run(configPath: Path) {
        SampleSupport.section("ConfigLoader")
        val configDir = configPath.parent?.toString() ?: "."

        val cfg = ConfigLoader.readConfig(configPath.toString())
        println("readConfig: vin=${cfg.vin}, uid=${cfg.uid}, safeBags=${cfg.safeBags.size}")
        println("  verTimestamp=${cfg.verTimestamp}, verVersion=${cfg.verVersion}")

        val nb = ConfigLoader.parseRfc3339(cfg.verTimestamp)
        val previewVer = if (cfg.verVersion > 0 && !isEpoch(nb)) {
            VerAttribute.formatText(nb, cfg.verVersion)
        } else {
            "(set verTimestamp + verVersion>0 for CMS VER)"
        }
        println("  VER preview (initial build): $previewVer")

        val signerPath = ConfigLoader.resolvePath(configDir, cfg.signerCert)
        println("resolvePath(signerCert): $signerPath")

        ConfigLoader.validateConfig(cfg, configDir)
        println("validateConfig: OK")

        val parsedNotBefore = ConfigLoader.parseRfc3339(cfg.safeBags.firstOrNull()?.roleNotBefore)
        println("parseRfc3339(roleNotBefore): $parsedNotBefore")

        val keyId = ConfigLoader.decodeLocalKeyId(cfg.safeBags.firstOrNull()?.localKeyID)
        println("decodeLocalKeyId: ${keyId?.joinToString("") { "%02x".format(it) } ?: "null"}")

        val buildCfg = ConfigLoader.toBuildConfig(cfg, configDir)
        val signerCert = PemUtils.loadCertificate(buildCfg.signerCertDer)
        println("toBuildConfig: signer=${signerCert.subjectX500Principal.name}")
        println("  safeBags=${buildCfg.safeBags.size}")
        println("  SignerAttrs VER: ${VerAttribute.formatText(buildCfg.verTimestamp, buildCfg.verVersion)}")

        SampleSupport.section("PemUtils (used by ConfigLoader / Builder)")
        val skid = PemUtils.getSubjectKeyId(signerCert)
        println("getSubjectKeyId: ${skid.joinToString("") { "%02x".format(it) }}")
        println("certToPem length: ${PemUtils.certToPem(buildCfg.signerCertDer).length} chars")
    }
}
