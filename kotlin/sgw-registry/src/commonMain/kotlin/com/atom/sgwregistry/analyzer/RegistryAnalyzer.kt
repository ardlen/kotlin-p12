/**
 * Анализ, отчёты и сериализация ATOM-PKCS12-REGISTRY.
 */
package com.atom.sgwregistry.analyzer

import com.atom.sgwregistry.api.RegistryAnalyzerService
import com.atom.sgwregistry.asn1.AttributeDecoder
import com.atom.sgwregistry.asn1.Oids
import com.atom.sgwregistry.crypto.CertificateCache
import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.crypto.PlatformCertificate
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.model.RegistryContainer
import com.atom.sgwregistry.model.SafeBagInfo
import com.atom.sgwregistry.internal.bytesToHex
import com.atom.sgwregistry.util.formatVerTimestamp
import com.atom.sgwregistry.util.instantToIsoString
import com.atom.sgwregistry.util.isEpoch
import com.atom.sgwregistry.verifier.SignatureVerifier
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

object RegistryAnalyzer : RegistryAnalyzerService {
    private val json = Json { prettyPrint = true }

    override fun verifyRegistry(p12Der: ByteArray) = SignatureVerifier.verifyRegistry(p12Der)

    fun toPem(c: RegistryContainer): ByteArray {
        val sb = StringBuilder()
        for (certDer in c.certificatesDer) sb.append(PemEncoding.certToPem(certDer))
        return sb.toString().encodeToByteArray()
    }

    fun toSafeBagsPem(c: RegistryContainer): ByteArray {
        val sb = StringBuilder()
        for (bag in c.safeBagInfos) {
            bag.certValueDer?.let { sb.append(PemEncoding.certToPem(it)) }
        }
        return sb.toString().encodeToByteArray()
    }

    fun signerCertPem(c: RegistryContainer): ByteArray {
        val der = c.signerCertDer ?: return ByteArray(0)
        return PemEncoding.certToPem(der).encodeToByteArray()
    }

    override fun toJson(c: RegistryContainer): ByteArray {
        val cache = CertificateCache()
        val obj = buildJsonObject {
            put("pfxVersion", c.pfxVersion)
            put("contentType", c.contentType)
            put("certificatesCount", c.certificatesDer.size)
            put("safeBagsCount", c.safeBagInfos.size)
            put("hasSignerCert", c.signerCertDer != null)
            put("signerCertResolved", c.signerCertResolved)
            if (c.parseWarnings.isNotEmpty()) {
                putJsonArray("parseWarnings") { c.parseWarnings.forEach { add(JsonPrimitive(it)) } }
            }
            putJsonArray("certificates") {
                c.certificatesDer.forEach { der ->
                    try {
                        val cert = cache.load(der)
                        val isSigner = c.signerCertDer != null && der.contentEquals(c.signerCertDer)
                        add(buildJsonObject {
                            put("subject", cert.subject)
                            put("issuer", cert.issuer)
                            put("serialNumber", cert.serialHex)
                            put("notBefore", instantToIsoString(cert.notBefore))
                            put("notAfter", instantToIsoString(cert.notAfter))
                            put("publicKeyAlgorithm", cert.keyAlgorithm)
                            put("isSigner", isSigner)
                        })
                    } catch (_: Exception) { }
                }
            }
            putJsonArray("safeBagInfos") {
                c.safeBagInfos.forEach { info ->
                    add(buildJsonObject {
                        put("roleName", info.roleName)
                        put("roleNotBefore", info.roleNotBefore.toString())
                        put("roleNotAfter", info.roleNotAfter.toString())
                        if (info.localKeyId != null) {
                            put("localKeyIdHex", PemEncoding.skidToHex(info.localKeyId))
                        } else {
                            put("localKeyIdHex", JsonNull)
                        }
                        info.certSummary?.let { s ->
                            putJsonObject("certSummary") {
                                put("subject", s.subject)
                                put("issuer", s.issuer)
                                put("serial", s.serial)
                                put("notBefore", s.notBefore)
                                put("notAfter", s.notAfter)
                                put("keyAlg", s.keyAlg)
                            }
                        }
                    })
                }
            }
        }
        return json.encodeToString(
            kotlinx.serialization.json.JsonObject.serializer(),
            obj,
        ).encodeToByteArray()
    }

    fun toText(c: RegistryContainer): String {
        val cache = CertificateCache()
        val sb = StringBuilder()
        sb.appendLine("=== PFX ===")
        sb.appendLine("  Version:     ${c.pfxVersion}")
        sb.appendLine("  ContentType: ${c.contentType}")
        sb.appendLine()
        sb.appendLine("=== Certificates ===")
        c.certificatesDer.forEachIndexed { i, der ->
            try {
                val cert = cache.load(der)
                val isSigner = c.signerCertDer != null && der.contentEquals(c.signerCertDer)
                sb.appendLine("  [${i + 1}] Subject: ${cert.subject}")
                if (isSigner) sb.appendLine("       (подписант контейнера)")
            } catch (_: Exception) {
                sb.appendLine("  [${i + 1}] (parse error)")
            }
        }
        return sb.toString()
    }

    fun toTextDetailed(c: RegistryContainer): String = toTextDetailed(c, false, false)

    override fun toTextDetailed(c: RegistryContainer, useColor: Boolean, skipVerify: Boolean): String {
        val cache = CertificateCache()
        val sb = StringBuilder()
        sb.appendLine("=== PFX ===")
        sb.appendLine("  Version:     ${c.pfxVersion}")
        sb.appendLine("  ContentType: ${c.contentType}")

        sb.appendLine()
        sb.appendLine("=== Certificates ===")
        c.certificatesDer.forEachIndexed { i, der ->
            try {
                val cert = cache.load(der)
                val isSigner = c.signerCertDer != null && der.contentEquals(c.signerCertDer)
                sb.appendLine("  [${i + 1}] Subject: ${cert.subject}")
                sb.appendLine("       Issuer:   ${cert.issuer}")
                sb.appendLine("       Serial:   ${cert.serialHex}")
                sb.appendLine("       KeyAlg:   ${keyAlgName(cert)}")
                val skid = PlatformCrypto.getSubjectKeyId(cert)
                if (skid.isNotEmpty()) {
                    sb.appendLine("       SubjectKeyId: ${PemEncoding.skidToHex(skid)}")
                }
                if (isSigner) sb.appendLine("       (подписант контейнера)")
            } catch (_: Exception) {
                sb.appendLine("  [${i + 1}] (parse error)")
            }
        }

        if (c.signerCertDer != null) {
            sb.appendLine()
            sb.appendLine("=== Подписант контейнера ===")
            if (!c.signerCertResolved) {
                sb.appendLine("  (не найден по SKID/issuerAndSerial)")
            }
            try {
                val signer = cache.load(c.signerCertDer)
                sb.appendLine("  Subject: ${signer.subject}")
                sb.appendLine("  Serial:  ${signer.serialHex}")
                val skid = PlatformCrypto.getSubjectKeyId(signer)
                if (skid.isNotEmpty()) {
                    sb.appendLine("  SKID:    ${PemEncoding.skidToHex(skid)}")
                }
            } catch (_: Exception) {
                sb.appendLine("  (cert parse error)")
            }
        }

        sb.appendLine()
        sb.appendLine("=== SafeContents (eContent) ===")
        c.safeBagInfos.forEachIndexed { i, bag ->
            sb.appendLine("  [${i + 1}] bagId: ${bag.bagId}")
            if (bag.certId.isNotEmpty()) sb.appendLine("       certId:   ${bag.certId} (${bag.certTypeName})")
            bag.certSummary?.let {
                sb.appendLine("       Subject:  ${it.subject}")
                sb.appendLine("       Serial:   ${it.serial}")
            }
            if (bag.roleName.isNotEmpty()) sb.appendLine("       roleName: ${bag.roleName}")
            if (!isEpoch(bag.roleNotBefore) || !isEpoch(bag.roleNotAfter)) {
                sb.appendLine(
                    "       roleValidityPeriod: ${formatVerTimestamp(bag.roleNotBefore)} — " +
                        formatVerTimestamp(bag.roleNotAfter),
                )
            }
            bag.localKeyId?.let {
                if (it.isNotEmpty()) sb.appendLine("       localKeyID: ${PemEncoding.skidToHex(it)}")
            }
        }

        if (c.parseWarnings.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("=== Parse warnings ===")
            c.parseWarnings.forEach { sb.appendLine("  - $it") }
        }

        sb.appendLine()
        sb.appendLine("=== Signers and ATOM attributes ===")
        sb.appendLine("  Signer [1]")
        sb.appendLine("    DigestAlgorithm: ${Oids.oidString(c.digestAlgorithmOid)}")
        sb.appendLine("    SignatureAlgorithm: ${Oids.oidString(c.signatureAlgorithmOid)}")
        if (c.firstSignerSidTag != 0) {
            val sidOk = c.firstSignerSidTag == 0x30 || c.firstSignerSidTag == 0xA0
            sb.appendLine("    SID tag: 0x${c.firstSignerSidTag.toString(16)} (sn1tools: ${if (sidOk) "OK" else "expects 0x30 or 0xa0"})")
        }
        for ((name, value) in parseAuthenticatedAttributes(c.authenticatedAttributesSetBytes)) {
            sb.appendLine("    $name: $value")
        }
        sb.appendLine("    messageDigest check: ${verifyMessageDigestMessage(c)}")
        if (!skipVerify) {
            sb.appendLine("    signature check (signer cert): ${verifySignatureMessage(c)}")
        }

        return sb.toString()
    }

    fun parseAuthenticatedAttributes(setBytes: ByteArray?): List<Pair<String, String>> =
        AttributeDecoder.parseAuthenticatedAttributes(setBytes)

    private fun verifyMessageDigestMessage(c: RegistryContainer): String {
        val eContent = c.eContentBytes ?: return "(no eContent)"
        val expected = parseAuthenticatedAttributes(c.authenticatedAttributesSetBytes)
            .firstOrNull { it.first == "messageDigest" }?.second
            ?: return "(no messageDigest attr)"
        val computed = PlatformCrypto.sha256(eContent)
            .let(::bytesToHex)
        return if (expected.equals(computed, ignoreCase = true)) "OK" else "MISMATCH (computed $computed)"
    }

    private fun verifySignatureMessage(c: RegistryContainer): String = try {
        SignatureVerifier.verifyContainer(c)
        "OK"
    } catch (e: Exception) {
        "FAIL — ${e.message}"
    }

    private fun keyAlgName(cert: PlatformCertificate): String = when (cert.keyAlgorithm) {
        "EC", "ECDSA" -> "ECDSA"
        "RSA" -> "RSA"
        else -> cert.keyAlgorithm
    }
}
