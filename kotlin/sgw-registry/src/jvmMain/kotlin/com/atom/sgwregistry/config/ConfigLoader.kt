/**
 * JVM: чтение config.json с диска → [BuildConfig] через [BuildConfigFactory].
 */
package com.atom.sgwregistry.config

import com.atom.sgwregistry.crypto.PemUtils
import com.atom.sgwregistry.crypto.signingKeyFrom
import com.atom.sgwregistry.model.BuildConfig
import java.io.File
import java.security.KeyPair
import java.security.cert.X509Certificate

object ConfigLoader {
    fun readConfig(configPath: String): RegistryConfig {
        val text = File(configPath).readText()
        return BuildConfigFactory.parseConfig(text)
    }

    fun resolvePath(configDir: String, path: String): String {
        val p = path.trim()
        val f = File(p)
        return if (f.isAbsolute) p else File(configDir, p).canonicalPath
    }

    fun validateConfig(cfg: RegistryConfig, configDir: String) {
        val hasCertPem = !cfg.signerCertPem.isNullOrBlank()
        val hasKeyPem = !cfg.signerKeyPem.isNullOrBlank()
        require(hasCertPem || cfg.signerCert.isNotBlank()) { "signerCert/signerCertPem required" }
        require(hasKeyPem || cfg.signerKey.isNotBlank()) { "signerKey/signerKeyPem required" }
        require(cfg.vin.isNotBlank()) { "vin required" }
        require(cfg.uid.isNotBlank()) { "uid required" }
        if (!hasCertPem) require(File(resolvePath(configDir, cfg.signerCert)).exists()) { "signerCert not found" }
        if (!hasKeyPem) require(File(resolvePath(configDir, cfg.signerKey)).exists()) { "signerKey not found" }
        cfg.safeBags.forEachIndexed { i, sb ->
            val hasPem = !sb.certPem.isNullOrBlank()
            require(hasPem || sb.cert.isNotBlank()) { "safeBags[$i].cert required" }
            if (!hasPem) require(File(resolvePath(configDir, sb.cert)).exists()) { "safeBags[$i].cert not found" }
        }
    }

    fun toBuildConfig(cfg: RegistryConfig, configDir: String): BuildConfig {
        validateConfig(cfg, configDir)
        if (!cfg.signerCertPem.isNullOrBlank() && !cfg.signerKeyPem.isNullOrBlank()) {
            val buildCfg = BuildConfigFactory.toBuildConfigFromInlinePem(cfg)
            verifyKeyMatchesCert(
                PemUtils.loadCertificate(buildCfg.signerCertDer),
                PemUtils.loadKeyPairFromPem(cfg.signerKeyPem),
            )
            return buildCfg
        }
        val buildCfg = BuildConfigFactory.toBuildConfig(cfg) { path ->
            File(resolvePath(configDir, path)).readBytes()
        }
        verifyKeyMatchesCert(
            PemUtils.loadCertificate(buildCfg.signerCertDer),
            PemUtils.loadKeyPair(resolvePath(configDir, cfg.signerKey)),
        )
        return buildCfg
    }

    fun decodeLocalKeyId(s: String?) = BuildConfigFactory.decodeLocalKeyId(s)

    fun parseRfc3339(s: String?) = BuildConfigFactory.parseRfc3339(s)

    private fun verifyKeyMatchesCert(cert: X509Certificate, keyPair: KeyPair) {
        if (!keyPair.public.encoded.contentEquals(cert.publicKey.encoded)) {
            throw IllegalStateException("Key does not match signer certificate")
        }
    }
}
