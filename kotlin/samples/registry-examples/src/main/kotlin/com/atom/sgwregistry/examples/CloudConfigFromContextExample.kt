package com.atom.sgwregistry.examples

import com.atom.sgwregistry.cloudconfig.CloudBrokerFqdn
import com.atom.sgwregistry.cloudconfig.CloudConfigCms
import com.atom.sgwregistry.cloudconfig.CloudConfigFromContext
import com.atom.sgwregistry.config.ConfigLoader
import com.atom.sgwregistry.crypto.PlatformCrypto
import java.nio.file.Files
import java.nio.file.Path

/**
 * JVM-пример: ответ invitation / B2B Virtual Device (`resp-context.json`)
 * → camelCase payload для TBOX → (demo) CMS-подпись и проверка.
 *
 * ## Выходной файл (TBOX)
 *
 * Пишется **только** payload:
 * ```json
 * {
 *   "v": 5,
 *   "cloudBroker": {
 *     "rootCAs": [ "...PEM..." ],
 *     "endpoint": { "fqdnConstrAlg": 1, "baseDomain": "mqtt.atom.auto" }
 *   }
 * }
 * ```
 * По умолчанию: `kotlin-out/cloud-config-tbox.json`.
 *
 * Рядом (опционально для локальной проверки) — `*.envelope.json` с mob-dev
 * `cloud_configuration` + `cloud_config_pem`.
 *
 * ## Запуск
 *
 * ```bash
 * cd kotlin
 * ./gradlew :samples:registry-examples:run \\
 *   --args="cloud-config-from-context resp-context.json config.json 5"
 * ```
 *
 * Аргументы CLI (см. [RegistryExamplesMain]):
 * 1. `resp-context.json` — invitation
 * 2. `config.json` — demo signer
 * 3. `v` — поле `v` в payload (по умолчанию 5)
 * 4. (optional) путь выходного TBOX JSON
 *
 * ## Важно про signer
 *
 * В **production** подписывают ключом ownership leaf из `ownership_registry`.
 * В **этом demo** — signer из `config.json` (без UID).
 */
object CloudConfigFromContextExample {

    /**
     * @param respContextPath путь к invitation JSON (`resp-context.json`)
     * @param configPath      `config.json` с путями к PEM signer (для demo-подписи)
     * @param outputJsonPath  куда записать TBOX payload (`v` + `cloudBroker`)
     * @param payloadVersion  значение поля `v` в payload; `null` → `current_version` из draft
     */
    fun run(
        respContextPath: Path,
        configPath: Path,
        outputJsonPath: Path,
        payloadVersion: Int? = 5,
    ) {
        SampleSupport.section("CloudConfigFromContext — resp-context → TBOX cloudBroker JSON")

        // ── 1. Parse invitation ──────────────────────────────────────────────
        val response = CloudConfigFromContext.parseInvitationResponse(
            SampleSupport.readBytes(respContextPath),
        )

        val ownerFromCms = CloudConfigFromContext.extractOwnerIdFromOwnershipCms(
            response.context.ownershipRegistry,
        )

        println("invitation id:     ${response.id}")
        println("vin:               ${response.vin}")
        println("tenant_id:         ${response.tenantId}")
        println("ownership UID:     $ownerFromCms")
        println("draft version:     ${response.context.vehicleCloudConfiguration.currentVersion}")
        println(
            "payload v:         ${
                payloadVersion ?: response.context.vehicleCloudConfiguration.currentVersion
            }",
        )
        println("root_cas (draft):  ${response.context.vehicleCloudConfiguration.cloudBroker.rootCas.size}")
        // CES §5: FQDN = hashB(VIN)-{tenant_id|ownerID}.{mqtt…} → endpoint.baseDomain
        val draftDomain = response.context.vehicleCloudConfiguration.cloudBroker.endpoint.baseDomain
        val fqdnId = response.tenantId.takeIf { it.isNotBlank() } ?: ownerFromCms
        val expectedFqdn = CloudBrokerFqdn.buildFqdn(
            vin = response.vin,
            identityId = fqdnId,
            domainSuffix = draftDomain,
            fqdnConstrAlg = response.context.vehicleCloudConfiguration.cloudBroker.endpoint.fqdnConstrAlg,
        )
        println("draft base_domain: $draftDomain")
        println("FQDN identity:     $fqdnId (tenant_id preferred, else ownership UID)")
        println("CES FQDN:          $expectedFqdn")
        println()

        // ── 2. Demo signer из config.json ────────────────────────────────────
        val configDir = configPath.parent?.toString() ?: "."
        val buildCfg = ConfigLoader.toBuildConfig(
            ConfigLoader.readConfig(configPath.toString()),
            configDir,
        )

        val signerSubject = PlatformCrypto
            .parseCertificate(buildCfg.signerCertDer)
            .subject
        val signerUid = CloudConfigFromContext.extractUidFromSubject(signerSubject)
        println("signer subject:    $signerSubject")
        println("signer UID:        ${signerUid ?: "(none — demo signer)"}")
        println()

        // ── 3. Draft → camelCase JSON → CMS (для локальной verify) ────────────
        // Demo signer без SAN: requireOwnerBinding=false.
        // Ownership leaf (URI atombus:/user/{owner_id}) — оставляйте true (default).
        val signed = CloudConfigFromContext.buildAndSign(
            response = response,
            signerCertDer = buildCfg.signerCertDer,
            signerKey = buildCfg.signerKey,
            payloadVersion = payloadVersion,
            alignOwnerIdWithSigner = signerUid != null,
            requireOwnerBinding = CloudConfigCms.extractSanUris(buildCfg.signerCertDer).isNotEmpty(),
        )

        println(CloudConfigCms.toText(signed))
        println()

        // ── 4. Проверки (envelope + CMS; TBOX-файл ниже — только payload) ────
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

        // ── 5. Запись TBOX payload (+ envelope рядом) ────────────────────────
        Files.createDirectories(outputJsonPath.parent)

        // Основной артефакт для TBOX: { "v", "cloudBroker": { rootCAs, endpoint } }
        val tboxJson = CloudConfigFromContext.encodeTboxPayload(signed, pretty = true)
        Files.write(outputJsonPath, tboxJson.encodeToByteArray())

        // Envelope с CMS — для cloud-config-trust / отладки (не формат TBOX).
        val envelopePath = outputJsonPath.resolveSibling(
            outputJsonPath.fileName.toString().removeSuffix(".json") + ".envelope.json",
        )
        Files.write(
            envelopePath,
            CloudConfigFromContext.encodeMobDevResponse(signed).encodeToByteArray(),
        )

        println()
        println("TBOX payload written: $outputJsonPath")
        println("envelope (CMS) written: $envelopePath")
        println()
        println("Re-check CMS via envelope:")
        println(
            "  ./gradlew :samples:registry-examples:run --args=" +
                "\"cloud-config-trust ${envelopePath.fileName} ${signed.vin} ${signed.ownerId}\"",
        )
    }
}
