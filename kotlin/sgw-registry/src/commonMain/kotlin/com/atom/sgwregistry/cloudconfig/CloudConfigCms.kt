/**
 * Фасад: mob-dev cloud_configuration — parse / verify / resign `cloud_config_pem`.
 */
package com.atom.sgwregistry.cloudconfig

import com.atom.sgwregistry.asn1.AttributeDecoder
import com.atom.sgwregistry.crypto.CertificateCache
import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.internal.bytesToHex
import com.atom.sgwregistry.model.CloudConfigCmsContainer
import com.atom.sgwregistry.model.CloudConfigResignOnlyRequest
import com.atom.sgwregistry.model.CloudConfigResignRequest
import com.atom.sgwregistry.model.CloudConfigurationDto
import com.atom.sgwregistry.model.MobDevCloudConfigJson
import com.atom.sgwregistry.model.MobDevCloudConfigResponse
import com.atom.sgwregistry.model.RegistryContainer
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.util.instantToIsoString
import com.atom.sgwregistry.verifier.SignatureVerifier

object CloudConfigCms {
    fun parseMobDevResponse(bytes: ByteArray): MobDevCloudConfigResponse =
        MobDevCloudConfigJson.parse(bytes)

    fun parseMobDevResponse(text: String): MobDevCloudConfigResponse =
        MobDevCloudConfigJson.parse(text)

    fun parsePem(pemOrDer: ByteArray): CloudConfigCmsContainer =
        fromRegistry(RegistryParser.parseCms(PemEncoding.decodePemOrDer(pemOrDer)))

    fun parsePem(pem: String): CloudConfigCmsContainer =
        parsePem(pem.encodeToByteArray())

    fun verify(container: CloudConfigCmsContainer) {
        SignatureVerifier.verifyContainer(container.toRegistryContainer())
    }

    fun verifyPem(pemOrDer: ByteArray) = verify(parsePem(pemOrDer))

    fun tryVerify(container: CloudConfigCmsContainer): Pair<Boolean, String?> = try {
        verify(container)
        true to null
    } catch (e: Exception) {
        false to (e.message ?: e::class.simpleName)
    }

    /**
     * Проверяет, что `cloud_config_json` совпадает с eContent внутри CMS.
     */
    fun verifyJsonMatchesEContent(container: CloudConfigCmsContainer, expectedJson: String) {
        val eContent = container.eContentBytes
            ?: throw IllegalStateException("CMS eContent is absent")
        val expected = expectedJson.encodeToByteArray()
        require(eContent.contentEquals(expected)) {
            "cloud_config_json does not match CMS eContent (expected ${expected.size} bytes, got ${eContent.size})"
        }
    }

    fun verifyCloudConfiguration(dto: CloudConfigurationDto) {
        val container = parsePem(dto.cloudConfigPem)
        verifyJsonMatchesEContent(container, dto.cloudConfigJson)
        verify(container)
    }

    /** Сравнение `vin` / `owner_id` с ожидаемыми значениями приложения. */
    fun matchesIdentity(dto: CloudConfigurationDto, expectedVin: String, expectedOwnerId: String): Boolean =
        dto.vin == expectedVin && dto.ownerId == expectedOwnerId

    fun requireIdentity(dto: CloudConfigurationDto, expectedVin: String, expectedOwnerId: String) {
        require(dto.vin == expectedVin) {
            "vin mismatch: expected=$expectedVin, got=${dto.vin}"
        }
        require(dto.ownerId == expectedOwnerId) {
            "owner_id mismatch: expected=$expectedOwnerId, got=${dto.ownerId}"
        }
    }

    /**
     * Проверяет, что UID в subject сертификата подписанта совпадает с `owner_id`
     * (типичная привязка ATOM Ownership leaf).
     */
    fun requireOwnerIdInSigner(dto: CloudConfigurationDto) {
        val container = parsePem(dto.cloudConfigPem)
        val der = container.signerCertDer
            ?: throw IllegalStateException("Signer certificate not resolved in cloud_config_pem")
        val cert = PlatformCrypto.parseCertificate(der)
        val ok = cert.subject.contains(dto.ownerId, ignoreCase = false) ||
            cert.subject.contains("UID=${dto.ownerId}", ignoreCase = true)
        require(ok) {
            "owner_id ${dto.ownerId} not found in signer subject: ${cert.subject}"
        }
    }

    fun resign(request: CloudConfigResignRequest): ByteArray =
        CloudConfigCmsBuilder.resign(request)

    fun resignToPem(request: CloudConfigResignRequest): String =
        CloudConfigCmsBuilder.resignToPem(request)

    /**
     * Переподписывает существующий CMS без пересборки eContent из JSON.
     * Байты payload берутся из уже разобранного `cloud_config_pem`.
     */
    fun resignOnly(container: CloudConfigCmsContainer, request: CloudConfigResignOnlyRequest): ByteArray =
        CloudConfigCmsBuilder.resignOnly(container, request)

    fun resignOnly(pemOrDer: ByteArray, request: CloudConfigResignOnlyRequest): ByteArray =
        resignOnly(parsePem(pemOrDer), request)

    fun resignOnly(pem: String, request: CloudConfigResignOnlyRequest): ByteArray =
        resignOnly(parsePem(pem), request)

    fun resignOnlyToPem(container: CloudConfigCmsContainer, request: CloudConfigResignOnlyRequest): String =
        CloudConfigCmsBuilder.resignOnlyToPem(container, request)

    fun resignOnlyToPem(pem: String, request: CloudConfigResignOnlyRequest): String =
        resignOnlyToPem(parsePem(pem), request)

    fun resignConfiguration(
        dto: CloudConfigurationDto,
        signerCertDer: ByteArray,
        signerKey: com.atom.sgwregistry.crypto.SigningKey,
    ): CloudConfigurationDto {
        val pem = resignToPem(
            CloudConfigResignRequest(
                jsonPayload = dto.cloudConfigJson,
                signerCertDer = signerCertDer,
                signerKey = signerKey,
            ),
        )
        return dto.copy(cloudConfigPem = pem)
    }

    /**
     * Переподписывает только `cloud_config_pem`; `cloud_config_json` не меняется.
     * eContent берётся из текущего CMS, без повторной сериализации JSON.
     */
    fun resignConfigurationOnly(
        dto: CloudConfigurationDto,
        signerCertDer: ByteArray,
        signerKey: com.atom.sgwregistry.crypto.SigningKey,
    ): CloudConfigurationDto {
        val container = parsePem(dto.cloudConfigPem)
        verifyJsonMatchesEContent(container, dto.cloudConfigJson)
        val pem = resignOnlyToPem(
            container,
            CloudConfigResignOnlyRequest(
                signerCertDer = signerCertDer,
                signerKey = signerKey,
            ),
        )
        return dto.copy(cloudConfigPem = pem)
    }

    fun toText(container: CloudConfigCmsContainer): String = buildString {
        val cache = CertificateCache()
        appendLine("=== Cloud config CMS ===")
        appendLine("signerCertResolved: ${container.signerCertResolved}")
        container.eContentBytes?.let { appendLine("eContent: ${it.size} bytes") }
        container.encryptedDigest?.let { appendLine("encryptedDigest: ${it.size} bytes (DER)") }
        container.signerCertDer?.let { der ->
            val cert = cache.load(der)
            appendLine("Signer subject: ${cert.subject}")
            appendLine("Signer issuer:  ${cert.issuer}")
            appendLine("Signer serial:  ${cert.serialHex}")
            appendLine("Signer valid:   ${instantToIsoString(cert.notBefore)} — ${instantToIsoString(cert.notAfter)}")
            appendLine("Signer SKID:    ${PemEncoding.skidToHex(PlatformCrypto.getSubjectKeyId(cert))}")
        }
        val attrs = AttributeDecoder.parseAuthenticatedAttributes(container.authenticatedAttributesSetBytes)
        if (attrs.isNotEmpty()) {
            appendLine()
            appendLine("=== Authenticated attributes ===")
            for ((name, value) in attrs) appendLine("  $name: $value")
        }
        container.eContentBytes?.let { eContent ->
            val digestAttr = attrs.firstOrNull { it.first == "messageDigest" }?.second
            val computed = PlatformCrypto.sha256(eContent).let(::bytesToHex)
            appendLine("messageDigest check: ${if (digestAttr.equals(computed, true)) "OK" else "MISMATCH"}")
        }
        append("signature check: ")
        appendLine(tryVerify(container).let { (ok, err) -> if (ok) "OK" else "FAIL — $err" })
        val preview = container.eContentBytes?.decodeToString()?.take(200)
        if (preview != null) {
            appendLine()
            appendLine("=== eContent preview ===")
            appendLine(preview + if ((container.eContentBytes?.size ?: 0) > 200) "…" else "")
        }
    }

    fun toText(dto: CloudConfigurationDto): String = buildString {
        appendLine("=== Mob-dev cloud_configuration ===")
        appendLine("id:         ${dto.id}")
        appendLine("vin:        ${dto.vin}")
        appendLine("owner_id:   ${dto.ownerId}")
        appendLine("version:    ${dto.version}")
        appendLine("base_domain:${dto.baseDomain}")
        appendLine("root_cas:   ${dto.rootCas.size}")
        appendLine("json bytes: ${dto.cloudConfigJson.encodeToByteArray().size}")
        appendLine()
        append(toText(parsePem(dto.cloudConfigPem)))
    }

    private fun fromRegistry(c: RegistryContainer): CloudConfigCmsContainer =
        CloudConfigCmsContainer.immutable(
            CloudConfigCmsContainer(
                contentType = c.contentType,
                certificatesDer = c.certificatesDer,
                signerCertDer = c.signerCertDer,
                eContentBytes = c.eContentBytes,
                authenticatedAttributesSetBytes = c.authenticatedAttributesSetBytes,
                encryptedDigest = c.encryptedDigest,
                digestAlgorithmOid = c.digestAlgorithmOid,
                signatureAlgorithmOid = c.signatureAlgorithmOid,
                firstSignerSidTag = c.firstSignerSidTag,
                signerCertResolved = c.signerCertResolved,
                parseWarnings = c.parseWarnings,
            ),
        )
}
