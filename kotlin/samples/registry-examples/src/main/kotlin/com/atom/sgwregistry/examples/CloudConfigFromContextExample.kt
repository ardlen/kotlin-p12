package com.atom.sgwregistry.examples

import com.atom.sgwregistry.cloudconfig.CloudConfigCms
import com.atom.sgwregistry.cloudconfig.CloudConfigFromContext
import com.atom.sgwregistry.config.ConfigLoader
import java.nio.file.Files
import java.nio.file.Path

/**
 * Invitation / resp-context → signed `cloud_configuration` → verify.
 *
 * ```
 * ./gradlew :samples:registry-examples:run --args="cloud-config-from-context resp-context.json config.json 5"
 * ```
 */
object CloudConfigFromContextExample {
    fun run(
        respContextPath: Path,
        configPath: Path,
        outputJsonPath: Path,
        payloadVersion: Int? = 5,
    ) {
        SampleSupport.section("CloudConfigFromContext — resp-context → signed cloud_configuration")

        val response = CloudConfigFromContext.parseInvitationResponse(SampleSupport.readBytes(respContextPath))
        val ownerFromCms = CloudConfigFromContext.extractOwnerIdFromOwnershipCms(
            response.context.ownershipRegistry,
        )
        println("invitation id:     ${response.id}")
        println("vin:               ${response.vin}")
        println("ownership UID:     $ownerFromCms")
        println("draft version:     ${response.context.vehicleCloudConfiguration.currentVersion}")
        println("payload v:         ${payloadVersion ?: response.context.vehicleCloudConfiguration.currentVersion}")
        println("root_cas (draft):  ${response.context.vehicleCloudConfiguration.cloudBroker.rootCas.size}")
        println()

        val configDir = configPath.parent?.toString() ?: "."
        val buildCfg = ConfigLoader.toBuildConfig(ConfigLoader.readConfig(configPath.toString()), configDir)
        val signerSubject = com.atom.sgwregistry.crypto.PlatformCrypto
            .parseCertificate(buildCfg.signerCertDer)
            .subject
        val signerUid = CloudConfigFromContext.extractUidFromSubject(signerSubject)
        println("signer subject:    $signerSubject")
        println("signer UID:        ${signerUid ?: "(none — demo signer)"}")
        println()

        // Demo config signer usually has no UID; keep owner_id from ownership_registry.
        // Production: sign with ownership leaf key → UID matches automatically.
        val signed = CloudConfigFromContext.buildAndSign(
            response = response,
            signerCertDer = buildCfg.signerCertDer,
            signerKey = buildCfg.signerKey,
            payloadVersion = payloadVersion,
            alignOwnerIdWithSigner = signerUid != null,
        )

        println(CloudConfigCms.toText(signed))
        println()
        println("=== verify signed cloud_configuration ===")
        CloudConfigCms.verifyCloudConfiguration(signed)
        println("verifyCloudConfiguration: OK (json ↔ eContent + CMS signature)")

        CloudConfigCms.requireIdentity(signed, response.vin, signed.ownerId)
        println("requireIdentity: OK (vin=${signed.vin}, owner_id=${signed.ownerId})")

        if (signerUid != null && signed.ownerId == signerUid) {
            CloudConfigCms.requireOwnerIdInSigner(signed)
            println("requireOwnerIdInSigner: OK")
        } else {
            println(
                "requireOwnerIdInSigner: skipped " +
                    "(demo signer UID≠ownership leaf; use ownership key in production)",
            )
        }

        Files.createDirectories(outputJsonPath.parent)
        Files.writeString(outputJsonPath, CloudConfigFromContext.encodeMobDevResponse(signed))
        println()
        println("written: $outputJsonPath")
        println()
        println("Re-check with trust CLI (identity + CMS; PKIX needs Ownership CA chain for stage leaf):")
        println(
            "  ./gradlew :samples:registry-examples:run --args=" +
                "\"cloud-config-trust ${outputJsonPath.fileName} ${signed.vin} ${signed.ownerId}\"",
        )
    }
}
