/**
 * Единая точка входа в библиотеку — фасад над object-реализациями.
 */
package com.atom.sgwregistry.api

import com.atom.sgwregistry.model.AddCertificateRequest
import com.atom.sgwregistry.model.BuildConfig
import com.atom.sgwregistry.model.RegistryContainer
import com.atom.sgwregistry.model.RemoveCertificateBySkidRequest

data class ParseOptions(
    val strict: Boolean = false,
)

interface RegistryParserService {
    fun parse(p12Der: ByteArray, options: ParseOptions = ParseOptions()): RegistryContainer
}

interface RegistryBuilderService {
    fun buildRegistry(cfg: BuildConfig): ByteArray
    fun buildSafeContents(safeBags: List<com.atom.sgwregistry.model.SafeBagInput>): ByteArray
    fun addCertificateAndResign(request: AddCertificateRequest): ByteArray
    fun addCertificateAndResign(container: RegistryContainer, request: AddCertificateRequest): ByteArray
    fun removeCertificateBySkidAndResign(request: RemoveCertificateBySkidRequest): ByteArray
    fun removeCertificateBySkidAndResign(container: RegistryContainer, request: RemoveCertificateBySkidRequest): ByteArray
}

interface SignatureVerifierService {
    fun verifyRegistry(p12Der: ByteArray)
    fun verifyContainer(c: RegistryContainer)
    fun tryVerifyRegistry(p12Der: ByteArray): Pair<Boolean, String?>
}

interface RegistryAnalyzerService {
    fun verifyRegistry(p12Der: ByteArray)
    fun toTextDetailed(c: RegistryContainer, useColor: Boolean = false, skipVerify: Boolean = false): String
    fun toJson(c: RegistryContainer): ByteArray
}

object SgwRegistry : RegistryParserService, RegistryBuilderService, SignatureVerifierService, RegistryAnalyzerService {
    override fun parse(p12Der: ByteArray, options: ParseOptions) =
        com.atom.sgwregistry.parser.RegistryParser.parse(p12Der, options)

    override fun buildRegistry(cfg: BuildConfig) =
        com.atom.sgwregistry.builder.RegistryBuilder.buildRegistry(cfg)

    override fun buildSafeContents(safeBags: List<com.atom.sgwregistry.model.SafeBagInput>) =
        com.atom.sgwregistry.builder.RegistryBuilder.buildSafeContents(safeBags)

    override fun addCertificateAndResign(request: AddCertificateRequest) =
        com.atom.sgwregistry.builder.RegistryBuilder.addCertificateAndResign(request)

    override fun addCertificateAndResign(container: RegistryContainer, request: AddCertificateRequest) =
        com.atom.sgwregistry.builder.RegistryBuilder.addCertificateAndResign(container, request)

    override fun removeCertificateBySkidAndResign(request: RemoveCertificateBySkidRequest) =
        com.atom.sgwregistry.builder.RegistryBuilder.removeCertificateBySkidAndResign(request)

    override fun removeCertificateBySkidAndResign(container: RegistryContainer, request: RemoveCertificateBySkidRequest) =
        com.atom.sgwregistry.builder.RegistryBuilder.removeCertificateBySkidAndResign(container, request)

    override fun verifyRegistry(p12Der: ByteArray) =
        com.atom.sgwregistry.verifier.SignatureVerifier.verifyRegistry(p12Der)

    override fun verifyContainer(c: RegistryContainer) =
        com.atom.sgwregistry.verifier.SignatureVerifier.verifyContainer(c)

    override fun tryVerifyRegistry(p12Der: ByteArray) =
        com.atom.sgwregistry.verifier.SignatureVerifier.tryVerifyRegistry(p12Der)

    override fun toTextDetailed(c: RegistryContainer, useColor: Boolean, skipVerify: Boolean) =
        com.atom.sgwregistry.analyzer.RegistryAnalyzer.toTextDetailed(c, useColor = useColor, skipVerify = skipVerify)

    override fun toJson(c: RegistryContainer) =
        com.atom.sgwregistry.analyzer.RegistryAnalyzer.toJson(c)

    // --- mob-dev cloud_configuration (cloud_config_pem CMS) ---

    fun parseMobDevCloudConfig(bytes: ByteArray) =
        com.atom.sgwregistry.cloudconfig.CloudConfigCms.parseMobDevResponse(bytes)

    fun parseMobDevCloudConfig(text: String) =
        com.atom.sgwregistry.cloudconfig.CloudConfigCms.parseMobDevResponse(text)

    fun parseCloudConfigPem(pemOrDer: ByteArray) =
        com.atom.sgwregistry.cloudconfig.CloudConfigCms.parsePem(pemOrDer)

    fun verifyCloudConfigPem(pemOrDer: ByteArray) =
        com.atom.sgwregistry.cloudconfig.CloudConfigCms.verifyPem(pemOrDer)

    fun verifyCloudConfiguration(dto: com.atom.sgwregistry.model.CloudConfigurationDto) =
        com.atom.sgwregistry.cloudconfig.CloudConfigCms.verifyCloudConfiguration(dto)

    fun requireCloudConfigIdentity(
        dto: com.atom.sgwregistry.model.CloudConfigurationDto,
        expectedVin: String,
        expectedOwnerId: String,
    ) = com.atom.sgwregistry.cloudconfig.CloudConfigCms.requireIdentity(dto, expectedVin, expectedOwnerId)

    fun requireCloudConfigOwnerIdInSigner(dto: com.atom.sgwregistry.model.CloudConfigurationDto) =
        com.atom.sgwregistry.cloudconfig.CloudConfigCms.requireOwnerIdInSigner(dto)

    fun resignCloudConfigPem(request: com.atom.sgwregistry.model.CloudConfigResignRequest) =
        com.atom.sgwregistry.cloudconfig.CloudConfigCms.resignToPem(request)

    fun resignCloudConfigOnly(
        container: com.atom.sgwregistry.model.CloudConfigCmsContainer,
        request: com.atom.sgwregistry.model.CloudConfigResignOnlyRequest,
    ) = com.atom.sgwregistry.cloudconfig.CloudConfigCms.resignOnlyToPem(container, request)

    fun resignCloudConfigurationOnly(
        dto: com.atom.sgwregistry.model.CloudConfigurationDto,
        signerCertDer: ByteArray,
        signerKey: com.atom.sgwregistry.crypto.SigningKey,
    ) = com.atom.sgwregistry.cloudconfig.CloudConfigCms.resignConfigurationOnly(dto, signerCertDer, signerKey)

    fun resignCloudConfiguration(
        dto: com.atom.sgwregistry.model.CloudConfigurationDto,
        signerCertDer: ByteArray,
        signerKey: com.atom.sgwregistry.crypto.SigningKey,
    ) = com.atom.sgwregistry.cloudconfig.CloudConfigCms.resignConfiguration(dto, signerCertDer, signerKey)

    fun cloudConfigToText(dto: com.atom.sgwregistry.model.CloudConfigurationDto) =
        com.atom.sgwregistry.cloudconfig.CloudConfigCms.toText(dto)

    fun parseInvitationContext(bytes: ByteArray) =
        com.atom.sgwregistry.cloudconfig.CloudConfigFromContext.parseInvitationResponse(bytes)

    fun parseInvitationContext(text: String) =
        com.atom.sgwregistry.cloudconfig.CloudConfigFromContext.parseInvitationResponse(text)

    fun buildCloudConfigurationFromContext(
        response: com.atom.sgwregistry.model.InvitationContextResponse,
        signerCertDer: ByteArray,
        signerKey: com.atom.sgwregistry.crypto.SigningKey,
        payloadVersion: Int? = null,
        configurationId: String? = null,
        ownerId: String? = null,
        alignOwnerIdWithSigner: Boolean = false,
        fqdnIdentityId: String? = null,
    ) = com.atom.sgwregistry.cloudconfig.CloudConfigFromContext.buildAndSign(
        response = response,
        signerCertDer = signerCertDer,
        signerKey = signerKey,
        payloadVersion = payloadVersion,
        configurationId = configurationId,
        ownerId = ownerId,
        alignOwnerIdWithSigner = alignOwnerIdWithSigner,
        fqdnIdentityId = fqdnIdentityId,
    )
}
