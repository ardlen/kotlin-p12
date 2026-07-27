package com.atom.sgwregistry.model

import com.atom.sgwregistry.crypto.SigningKey
import com.atom.sgwregistry.internal.contentEqualsNullable
import com.atom.sgwregistry.internal.copyImmutable
import com.atom.sgwregistry.internal.copyImmutableList
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Разбор JSON ответа облачного сервиса mob-dev (поле `cloud_configuration`).
 * Пример: [mob-dev-cloud_config.json](../../../../../../mob-dev-cloud_config.json).
 */
@Serializable
data class MobDevCloudConfigResponse(
    @SerialName("cloud_configuration") val cloudConfiguration: CloudConfigurationDto,
)

@Serializable
data class CloudConfigurationDto(
    @SerialName("root_cas") val rootCas: List<String> = emptyList(),
    val id: String = "",
    val vin: String = "",
    @SerialName("owner_id") val ownerId: String = "",
    val version: String = "",
    @SerialName("base_domain") val baseDomain: String = "",
    @SerialName("cloud_config_json") val cloudConfigJson: String = "",
    @SerialName("cloud_config_pem") val cloudConfigPem: String = "",
    @SerialName("created_at") val createdAt: String = "",
    @SerialName("updated_at") val updatedAt: String = "",
)

/** Разобранный CMS из `cloud_config_pem` (SignedData, не PFX). */
data class CloudConfigCmsContainer(
    val contentType: String = "",
    val certificatesDer: List<ByteArray> = emptyList(),
    val signerCertDer: ByteArray? = null,
    val eContentBytes: ByteArray? = null,
    val authenticatedAttributesSetBytes: ByteArray? = null,
    val encryptedDigest: ByteArray? = null,
    val digestAlgorithmOid: IntArray? = null,
    val signatureAlgorithmOid: IntArray? = null,
    val firstSignerSidTag: Int = 0,
    val signerCertResolved: Boolean = false,
    val parseWarnings: List<String> = emptyList(),
) {
    fun toRegistryContainer(): RegistryContainer = RegistryContainer(
        pfxVersion = 0,
        contentType = contentType,
        certificatesDer = certificatesDer,
        safeBagInfos = emptyList(),
        signerCertDer = signerCertDer,
        eContentBytes = eContentBytes,
        authenticatedAttributesSetBytes = authenticatedAttributesSetBytes,
        encryptedDigest = encryptedDigest,
        digestAlgorithmOid = digestAlgorithmOid,
        signatureAlgorithmOid = signatureAlgorithmOid,
        firstSignerSidTag = firstSignerSidTag,
        signerCertResolved = signerCertResolved,
        parseWarnings = parseWarnings,
    )

    companion object {
        fun immutable(c: CloudConfigCmsContainer): CloudConfigCmsContainer = c.copy(
            certificatesDer = c.certificatesDer.copyImmutableList(),
            signerCertDer = c.signerCertDer.copyImmutable(),
            eContentBytes = c.eContentBytes.copyImmutable(),
            authenticatedAttributesSetBytes = c.authenticatedAttributesSetBytes.copyImmutable(),
            encryptedDigest = c.encryptedDigest.copyImmutable(),
            digestAlgorithmOid = c.digestAlgorithmOid?.copyOf(),
            signatureAlgorithmOid = c.signatureAlgorithmOid?.copyOf(),
            parseWarnings = c.parseWarnings.toList(),
        )
    }
}

data class CloudConfigResignOnlyRequest(
    val signerCertDer: ByteArray,
    val signerKey: SigningKey,
    val includeSigningTime: Boolean = true,
    val includeSigningCertificateV2: Boolean = true,
    /** Cloud CMS использует issuerAndSerial, не SKID. */
    val useIssuerAndSerialSid: Boolean = true,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CloudConfigResignOnlyRequest) return false
        return signerCertDer.contentEquals(other.signerCertDer) &&
            signerKey == other.signerKey &&
            includeSigningTime == other.includeSigningTime &&
            includeSigningCertificateV2 == other.includeSigningCertificateV2 &&
            useIssuerAndSerialSid == other.useIssuerAndSerialSid
    }

    override fun hashCode(): Int {
        var result = signerCertDer.contentHashCode()
        result = 31 * result + signerKey.hashCode()
        result = 31 * result + includeSigningTime.hashCode()
        result = 31 * result + includeSigningCertificateV2.hashCode()
        result = 31 * result + useIssuerAndSerialSid.hashCode()
        return result
    }
}

data class CloudConfigResignRequest(
    val jsonPayload: String,
    val signerCertDer: ByteArray,
    val signerKey: SigningKey,
    val includeSigningTime: Boolean = true,
    val includeSigningCertificateV2: Boolean = true,
    /** Cloud CMS использует issuerAndSerial, не SKID. */
    val useIssuerAndSerialSid: Boolean = true,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CloudConfigResignRequest) return false
        return jsonPayload == other.jsonPayload &&
            signerCertDer.contentEquals(other.signerCertDer) &&
            signerKey == other.signerKey &&
            includeSigningTime == other.includeSigningTime &&
            includeSigningCertificateV2 == other.includeSigningCertificateV2 &&
            useIssuerAndSerialSid == other.useIssuerAndSerialSid
    }

    override fun hashCode(): Int {
        var result = jsonPayload.hashCode()
        result = 31 * result + signerCertDer.contentHashCode()
        result = 31 * result + signerKey.hashCode()
        result = 31 * result + includeSigningTime.hashCode()
        result = 31 * result + includeSigningCertificateV2.hashCode()
        result = 31 * result + useIssuerAndSerialSid.hashCode()
        return result
    }
}

object MobDevCloudConfigJson {
    private val json = Json { ignoreUnknownKeys = true }

    fun parse(bytes: ByteArray): MobDevCloudConfigResponse =
        json.decodeFromString(MobDevCloudConfigResponse.serializer(), bytes.decodeToString())

    fun parse(text: String): MobDevCloudConfigResponse =
        json.decodeFromString(MobDevCloudConfigResponse.serializer(), text)
}

/**
 * Ответ B2B invitation / Virtual Device (`resp-context.json`):
 * `context.vehicle_cloud_configuration` + `ownership_registry` → signed `cloud_configuration`.
 */
@Serializable
data class InvitationContextResponse(
    val context: InvitationContextDto = InvitationContextDto(),
    val id: String = "",
    val status: String = "",
    @SerialName("tenant_id") val tenantId: String = "",
    val vin: String = "",
)

@Serializable
data class InvitationContextDto(
    @SerialName("ownership_registry") val ownershipRegistry: String = "",
    @SerialName("vehicle_cloud_configuration") val vehicleCloudConfiguration: VehicleCloudConfigurationDraft = VehicleCloudConfigurationDraft(),
    @SerialName("vehicle_mtls_cert_pem") val vehicleMtlsCertPem: String = "",
    @SerialName("vehicle_mtls_cert_sha256") val vehicleMtlsCertSha256: String = "",
)

@Serializable
data class VehicleCloudConfigurationDraft(
    @SerialName("cloud_broker") val cloudBroker: VehicleCloudBrokerDraft = VehicleCloudBrokerDraft(),
    @SerialName("current_version") val currentVersion: Int = 1,
)

@Serializable
data class VehicleCloudBrokerDraft(
    val endpoint: VehicleCloudEndpointDraft = VehicleCloudEndpointDraft(),
    @SerialName("root_cas") val rootCas: List<String> = emptyList(),
)

@Serializable
data class VehicleCloudEndpointDraft(
    @SerialName("base_domain") val baseDomain: String = "",
    @SerialName("fqdn_constr_alg") val fqdnConstrAlg: Int = 1,
    val url: String = "",
)

/** camelCase payload внутри `cloud_config_json` (eContent CMS). */
@Serializable
data class CloudBrokerConfigPayload(
    val v: Int,
    val cloudBroker: CloudBrokerConfigBody,
)

@Serializable
data class CloudBrokerConfigBody(
    val rootCAs: List<String>,
    val endpoint: CloudBrokerEndpointPayload,
)

@Serializable
data class CloudBrokerEndpointPayload(
    val fqdnConstrAlg: Int,
    val baseDomain: String,
)

object InvitationContextJson {
    private val json = Json { ignoreUnknownKeys = true }

    fun parse(bytes: ByteArray): InvitationContextResponse =
        json.decodeFromString(InvitationContextResponse.serializer(), bytes.decodeToString())

    fun parse(text: String): InvitationContextResponse =
        json.decodeFromString(InvitationContextResponse.serializer(), text)
}
