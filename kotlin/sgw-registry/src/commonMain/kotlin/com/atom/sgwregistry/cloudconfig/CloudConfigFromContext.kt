/**
 * Сборка подписанного `cloud_configuration` из invitation / resp-context.
 */
package com.atom.sgwregistry.cloudconfig

import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.crypto.SigningKey
import com.atom.sgwregistry.model.CloudBrokerConfigBody
import com.atom.sgwregistry.model.CloudBrokerConfigPayload
import com.atom.sgwregistry.model.CloudBrokerEndpointPayload
import com.atom.sgwregistry.model.CloudConfigResignRequest
import com.atom.sgwregistry.model.CloudConfigurationDto
import com.atom.sgwregistry.model.InvitationContextJson
import com.atom.sgwregistry.model.InvitationContextResponse
import com.atom.sgwregistry.model.MobDevCloudConfigResponse
import com.atom.sgwregistry.model.VehicleCloudConfigurationDraft
import com.atom.sgwregistry.parser.RegistryParser
import kotlinx.serialization.json.Json

object CloudConfigFromContext {
    private val payloadJson = Json {
        encodeDefaults = true
        explicitNulls = false
    }

    fun parseInvitationResponse(bytes: ByteArray): InvitationContextResponse =
        InvitationContextJson.parse(bytes)

    fun parseInvitationResponse(text: String): InvitationContextResponse =
        InvitationContextJson.parse(text)

    /**
     * UID листового сертификата из `context.ownership_registry`.
     *
     * На практике invitation отдаёт **PFX v3** (`-----BEGIN CMS-----` с INTEGER 3 + SignedData),
     * а не standalone ContentInfo как у `cloud_config_pem`.
     */
    fun extractOwnerIdFromOwnershipCms(ownershipRegistryPem: String): String {
        require(ownershipRegistryPem.isNotBlank()) { "ownership_registry is empty" }
        val der = PemEncoding.decodePemOrDer(ownershipRegistryPem.encodeToByteArray())
        val candidates = ArrayList<ByteArray>()
        try {
            val container = if (looksLikePfx(der)) {
                RegistryParser.parse(der)
            } else {
                CloudConfigCms.parsePem(der).toRegistryContainer()
            }
            container.signerCertDer?.let { candidates.add(it) }
            candidates.addAll(container.certificatesDer)
        } catch (_: Exception) {
            // fallback ниже
        }
        for (certDer in candidates) {
            extractUidFromSubject(PlatformCrypto.parseCertificate(certDer).subject)?.let { return it }
        }
        for (certDer in scanCertificates(der)) {
            extractUidFromSubject(PlatformCrypto.parseCertificate(certDer).subject)?.let { return it }
        }
        throw IllegalStateException("UID not found in ownership_registry leaf certificate")
    }

    fun extractUidFromSubject(subject: String): String? {
        val match = UID_IN_SUBJECT.find(subject) ?: return null
        return match.groupValues[1].trim().takeIf { it.isNotEmpty() }
    }

    /**
     * snake_case draft → компактный camelCase `cloud_config_json`.
     *
     * При [vin] + [fqdnIdentityId] и `fqdnConstrAlg=1` поле `endpoint.baseDomain`
     * становится полным FQDN по CES §5:
     * `hashB(VIN)-{id}.{domainSuffix}` (см. [CloudBrokerFqdn]).
     *
     * @param payloadVersion если задан — поле `v`; иначе `draft.currentVersion`
     * @param fqdnIdentityId CES ownerID (UID) или invitation `tenant_id`
     */
    fun buildCloudConfigJson(
        draft: VehicleCloudConfigurationDraft,
        payloadVersion: Int? = null,
        vin: String? = null,
        fqdnIdentityId: String? = null,
    ): String {
        val rootCas = draft.cloudBroker.rootCas
        require(rootCas.isNotEmpty()) { "vehicle_cloud_configuration.cloud_broker.root_cas is empty" }
        require(rootCas.all { looksLikePemCertificate(it) }) {
            "root_cas must contain PEM certificates (got placeholder or invalid value)"
        }
        val rawDomain = draft.cloudBroker.endpoint.baseDomain
        require(rawDomain.isNotBlank()) { "endpoint.base_domain is blank" }
        val alg = draft.cloudBroker.endpoint.fqdnConstrAlg
        val baseDomain = if (
            !vin.isNullOrBlank() &&
            !fqdnIdentityId.isNullOrBlank() &&
            alg == CloudBrokerFqdn.ALG_HASH_B_VIN_OWNER
        ) {
            CloudBrokerFqdn.resolveBaseDomain(vin, fqdnIdentityId, rawDomain, alg)
        } else {
            rawDomain
        }
        val payload = CloudBrokerConfigPayload(
            v = payloadVersion ?: draft.currentVersion,
            cloudBroker = CloudBrokerConfigBody(
                rootCAs = rootCas,
                endpoint = CloudBrokerEndpointPayload(
                    fqdnConstrAlg = alg,
                    baseDomain = baseDomain,
                ),
            ),
        )
        return payloadJson.encodeToString(CloudBrokerConfigPayload.serializer(), payload)
    }

    /**
     * DTO без подписи (`cloud_config_pem` пустой).
     *
     * FQDN при alg=1: `hashB(vin)-{id}.{mqtt…}`; [id] из [fqdnIdentityId] или [fqdnIdentitySource]
     * (`owner_id` / `tenant_id` / fallback-цепочка).
     */
    fun buildUnsignedConfiguration(
        response: InvitationContextResponse,
        payloadVersion: Int? = null,
        configurationId: String? = null,
        ownerId: String? = null,
        fqdnIdentityId: String? = null,
        fqdnIdentitySource: CloudConfigFqdnIdentitySource = CloudConfigFqdnIdentitySource.OwnerId,
    ): CloudConfigurationDto {
        val draft = response.context.vehicleCloudConfiguration
        val resolvedOwnerId = ownerId
            ?: extractOwnerIdFromOwnershipCms(response.context.ownershipRegistry)
        val resolvedFqdnId = resolveFqdnIdentityId(
            response = response,
            resolvedOwnerId = resolvedOwnerId,
            fqdnIdentityId = fqdnIdentityId,
            fqdnIdentitySource = fqdnIdentitySource,
        )
        val json = buildCloudConfigJson(
            draft = draft,
            payloadVersion = payloadVersion,
            vin = response.vin,
            fqdnIdentityId = resolvedFqdnId,
        )
        val resolvedBaseDomain = payloadJson.decodeFromString(
            CloudBrokerConfigPayload.serializer(),
            json,
        ).cloudBroker.endpoint.baseDomain
        return CloudConfigurationDto(
            rootCas = draft.cloudBroker.rootCas,
            id = configurationId ?: response.id,
            vin = response.vin,
            ownerId = resolvedOwnerId,
            version = (payloadVersion ?: draft.currentVersion).toString(),
            baseDomain = resolvedBaseDomain,
            cloudConfigJson = json,
            cloudConfigPem = "",
        )
    }

    /**
     * Сборка payload + CMS-подпись owner-ключом (`resign` с пересборкой eContent из JSON).
     *
     * Перед подписью (если [requireOwnerBinding]): `owner_id` должен совпадать с сегментом
     * FQDN и с SAN URI `atombus:/user/{owner_id}` сертификата подписанта
     * (и EKU Email Protection). Для FQDN из [CloudConfigFqdnIdentitySource.TenantId]
     * при tenant ≠ owner обычно ставьте `requireOwnerBinding = false`.
     *
     * @param alignOwnerIdWithSigner если true и в subject подписанта есть UID — `owner_id` берётся оттуда
     *   (нужно, когда signing cert ≠ leaf из ownership_registry).
     * @param fqdnIdentityId явный id после hashB(VIN)- в FQDN; перекрывает [fqdnIdentitySource]
     * @param fqdnIdentitySource `owner_id` / `tenant_id` / цепочка из двух полей
     * @param requireOwnerBinding проверка owner_id ↔ FQDN ↔ SAN URI (выкл. для demo-signer без SAN)
     */
    fun buildAndSign(
        response: InvitationContextResponse,
        signerCertDer: ByteArray,
        signerKey: SigningKey,
        payloadVersion: Int? = null,
        configurationId: String? = null,
        ownerId: String? = null,
        alignOwnerIdWithSigner: Boolean = false,
        fqdnIdentityId: String? = null,
        fqdnIdentitySource: CloudConfigFqdnIdentitySource = CloudConfigFqdnIdentitySource.OwnerId,
        requireOwnerBinding: Boolean = true,
    ): CloudConfigurationDto {
        val ownershipUid = ownerId
            ?: extractOwnerIdFromOwnershipCms(response.context.ownershipRegistry)
        val signerUid = if (alignOwnerIdWithSigner) {
            extractUidFromSubject(PlatformCrypto.parseCertificate(signerCertDer).subject)
        } else {
            null
        }
        val resolvedOwnerId = ownerId ?: signerUid ?: ownershipUid
        val resolvedFqdnId = resolveFqdnIdentityId(
            response = response,
            resolvedOwnerId = resolvedOwnerId,
            fqdnIdentityId = fqdnIdentityId,
            fqdnIdentitySource = fqdnIdentitySource,
        )
        val unsigned = buildUnsignedConfiguration(
            response = response,
            payloadVersion = payloadVersion,
            configurationId = configurationId,
            ownerId = resolvedOwnerId,
            fqdnIdentityId = resolvedFqdnId,
            fqdnIdentitySource = fqdnIdentitySource,
        )
        if (requireOwnerBinding) {
            CloudConfigCms.requireOwnerIdBinding(
                ownerId = resolvedOwnerId,
                baseDomain = unsigned.baseDomain,
                signerCertDer = signerCertDer,
            )
        }
        val pem = CloudConfigCms.resignToPem(
            CloudConfigResignRequest(
                jsonPayload = unsigned.cloudConfigJson,
                signerCertDer = signerCertDer,
                signerKey = signerKey,
            ),
        )
        return unsigned.copy(cloudConfigPem = pem)
    }

    /**
     * Identity-сегмент FQDN: явный [fqdnIdentityId] → иначе [fqdnIdentitySource]
     * (`owner_id` / `tenant_id` / fallback из двух полей).
     */
    fun resolveFqdnIdentityId(
        response: InvitationContextResponse,
        resolvedOwnerId: String,
        fqdnIdentityId: String? = null,
        fqdnIdentitySource: CloudConfigFqdnIdentitySource = CloudConfigFqdnIdentitySource.OwnerId,
    ): String {
        if (!fqdnIdentityId.isNullOrBlank()) return fqdnIdentityId
        val owner = resolvedOwnerId.trim()
        val tenant = response.tenantId.trim()
        return when (fqdnIdentitySource) {
            CloudConfigFqdnIdentitySource.OwnerId -> {
                require(owner.isNotEmpty()) { "owner_id is blank; cannot build FQDN from OwnerId" }
                owner
            }
            CloudConfigFqdnIdentitySource.TenantId -> {
                require(tenant.isNotEmpty()) { "tenant_id is blank; cannot build FQDN from TenantId" }
                tenant
            }
            CloudConfigFqdnIdentitySource.OwnerIdThenTenantId -> {
                owner.takeIf { it.isNotEmpty() }
                    ?: tenant.takeIf { it.isNotEmpty() }
                    ?: throw IllegalArgumentException(
                        "owner_id and tenant_id are blank; cannot build FQDN",
                    )
            }
            CloudConfigFqdnIdentitySource.TenantIdThenOwnerId -> {
                tenant.takeIf { it.isNotEmpty() }
                    ?: owner.takeIf { it.isNotEmpty() }
                    ?: throw IllegalArgumentException(
                        "tenant_id and owner_id are blank; cannot build FQDN",
                    )
            }
        }
    }

    fun toMobDevResponse(dto: CloudConfigurationDto): MobDevCloudConfigResponse =
        MobDevCloudConfigResponse(cloudConfiguration = dto)

    fun encodeMobDevResponse(dto: CloudConfigurationDto, pretty: Boolean = true): String {
        val json = Json {
            prettyPrint = pretty
            encodeDefaults = true
            explicitNulls = false
        }
        return json.encodeToString(
            MobDevCloudConfigResponse.serializer(),
            toMobDevResponse(dto),
        ) + "\n"
    }

    /**
     * Payload для TBOX: только camelCase `cloudBroker`-JSON
     * (`v` / `cloudBroker.rootCAs` / `endpoint`), без mob-dev envelope и без CMS PEM.
     *
     * Компактная строка в [CloudConfigurationDto.cloudConfigJson] — это eContent CMS;
     * [pretty] = true удобен для передачи/просмотра (байты ≠ eContent).
     */
    fun encodeTboxPayload(dto: CloudConfigurationDto, pretty: Boolean = true): String {
        require(dto.cloudConfigJson.isNotBlank()) { "cloud_config_json is empty" }
        val payload = payloadJson.decodeFromString(
            CloudBrokerConfigPayload.serializer(),
            dto.cloudConfigJson,
        )
        val json = Json {
            prettyPrint = pretty
            encodeDefaults = true
            explicitNulls = false
        }
        return json.encodeToString(CloudBrokerConfigPayload.serializer(), payload) + "\n"
    }

    /**
     * Подпись TBOX JSON (`v` + `cloudBroker`) → `cloud_config_pem` (CMS PEM).
     *
     * Pretty/compact вход нормализуется в компактный [CloudBrokerConfigPayload]
     * (те же байты, что eContent в CMS).
     *
     * Если заданы [vin] + identity ([fqdnIdentityId] ?: [ownerId]) и alg=1 — перед подписью
     * `endpoint.baseDomain` пересчитывается по CES §5 (hashB(VIN)-ownerId.suffix).
     *
     * При [requireOwnerBinding]: owner_id (явный / из SAN / из UID subject) должен
     * совпадать с FQDN и SAN URI `atombus:/user/{owner_id}`.
     *
     * @return Pair(compactJson, cmsPem)
     */
    fun signTboxPayload(
        tboxJson: String,
        signerCertDer: ByteArray,
        signerKey: SigningKey,
        vin: String? = null,
        fqdnIdentityId: String? = null,
        ownerId: String? = null,
        requireOwnerBinding: Boolean = true,
    ): Pair<String, String> {
        require(tboxJson.isNotBlank()) { "tbox JSON is empty" }
        var payload = payloadJson.decodeFromString(
            CloudBrokerConfigPayload.serializer(),
            tboxJson,
        )
        require(payload.cloudBroker.rootCAs.isNotEmpty()) { "cloudBroker.rootCAs is empty" }
        require(payload.cloudBroker.rootCAs.all { looksLikePemCertificate(it) }) {
            "rootCAs must contain PEM certificates"
        }
        require(payload.cloudBroker.endpoint.baseDomain.isNotBlank()) { "endpoint.baseDomain is blank" }

        val identityForFqdn = fqdnIdentityId?.takeIf { it.isNotBlank() }
            ?: ownerId?.takeIf { it.isNotBlank() }
        if (
            !vin.isNullOrBlank() &&
            !identityForFqdn.isNullOrBlank() &&
            payload.cloudBroker.endpoint.fqdnConstrAlg == CloudBrokerFqdn.ALG_HASH_B_VIN_OWNER
        ) {
            val resolved = CloudBrokerFqdn.resolveBaseDomain(
                vin = vin,
                identityId = identityForFqdn,
                domainOrFqdn = payload.cloudBroker.endpoint.baseDomain,
                fqdnConstrAlg = payload.cloudBroker.endpoint.fqdnConstrAlg,
            )
            payload = payload.copy(
                cloudBroker = payload.cloudBroker.copy(
                    endpoint = payload.cloudBroker.endpoint.copy(baseDomain = resolved),
                ),
            )
        }

        if (requireOwnerBinding) {
            val bindingOwnerId = resolveOwnerIdForBinding(ownerId, signerCertDer)
            CloudConfigCms.requireOwnerIdBinding(
                ownerId = bindingOwnerId,
                baseDomain = payload.cloudBroker.endpoint.baseDomain,
                signerCertDer = signerCertDer,
            )
        }

        val compactJson = payloadJson.encodeToString(CloudBrokerConfigPayload.serializer(), payload)
        val pem = CloudConfigCms.resignToPem(
            CloudConfigResignRequest(
                jsonPayload = compactJson,
                signerCertDer = signerCertDer,
                signerKey = signerKey,
            ),
        )
        return compactJson to pem
    }

    /**
     * owner_id для binding: явный → SAN `atombus:/user/…` → UID subject.
     * Если SAN и UID оба есть — должны совпадать.
     */
    fun resolveOwnerIdForBinding(explicitOwnerId: String?, signerCertDer: ByteArray): String {
        if (!explicitOwnerId.isNullOrBlank()) return explicitOwnerId
        val uris = CloudConfigCms.extractSanUris(signerCertDer)
        val fromSan = CloudConfigCms.extractOwnerIdFromSanUris(uris)
        val fromSubject = extractUidFromSubject(
            PlatformCrypto.parseCertificate(signerCertDer).subject,
        )
        if (fromSan != null && fromSubject != null &&
            !fromSan.equals(fromSubject, ignoreCase = true)
        ) {
            throw IllegalArgumentException(
                "signer UID=$fromSubject differs from SAN URI owner=$fromSan",
            )
        }
        return fromSan
            ?: fromSubject
            ?: throw IllegalArgumentException(
                "owner_id not provided and not found in signer SAN/UID",
            )
    }

    private fun looksLikePemCertificate(pem: String): Boolean {
        if (!pem.contains("BEGIN CERTIFICATE")) return false
        val body = pem.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("-----") }
            .joinToString("")
        return body.length >= 32 && body.none { it == '<' || it == '>' }
    }

    /** PFX: SEQUENCE { INTEGER version, ContentInfo ... }; CMS ContentInfo starts with OID. */
    private fun looksLikePfx(der: ByteArray): Boolean {
        if (der.size < 6 || der[0].toInt() and 0xFF != 0x30) return false
        val lenInfo = readDerLength(der, 1) ?: return false
        val contentStart = lenInfo.second
        return contentStart < der.size && (der[contentStart].toInt() and 0xFF) == 0x02
    }

    private fun scanCertificates(der: ByteArray): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        var i = 0
        while (i < der.size - 4) {
            if (der[i].toInt() and 0xFF != 0x30) {
                i++
                continue
            }
            val lenInfo = readDerLength(der, i + 1)
            if (lenInfo == null) {
                i++
                continue
            }
            val end = lenInfo.second + lenInfo.first
            if (lenInfo.first in 100..8192 && end <= der.size) {
                val candidate = der.copyOfRange(i, end)
                val parsed = try {
                    PlatformCrypto.parseCertificate(candidate)
                    true
                } catch (_: Exception) {
                    false
                }
                if (parsed) {
                    out.add(candidate)
                    i = end
                    continue
                }
            }
            i++
        }
        return out
    }

    /** @return Pair(contentLength, contentOffset) */
    private fun readDerLength(buf: ByteArray, offset: Int): Pair<Int, Int>? {
        if (offset >= buf.size) return null
        val b = buf[offset].toInt() and 0xFF
        if (b < 0x80) return b to (offset + 1)
        val n = b and 0x7F
        if (n == 0 || n > 3 || offset + 1 + n > buf.size) return null
        var len = 0
        for (k in 1..n) {
            len = (len shl 8) or (buf[offset + k].toInt() and 0xFF)
        }
        return len to (offset + 1 + n)
    }

    private val UID_IN_SUBJECT = Regex("""(?i)(?:^|,)\s*UID=([^,]+)""")
}
