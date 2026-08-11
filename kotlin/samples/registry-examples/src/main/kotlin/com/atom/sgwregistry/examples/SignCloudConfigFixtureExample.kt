package com.atom.sgwregistry.examples

import com.atom.sgwregistry.cloudconfig.CloudBrokerFqdn
import com.atom.sgwregistry.cloudconfig.CloudConfigCms
import com.atom.sgwregistry.cloudconfig.CloudConfigFromContext
import com.atom.sgwregistry.config.ConfigLoader
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.model.CloudBrokerConfigPayload
import com.atom.sgwregistry.model.MobDevCloudConfigJson
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.Json

/**
 * Подпись cloud config на **текущих фикстурах** репозитория.
 *
 * ## Фикстуры
 *
 * | Файл | Роль |
 * |------|------|
 * | `cloud-config.json` / `mob-dev-cloud_config.json` | OK: owner_id = FQDN = SAN, EKU Email Protection |
 * | `resp-context.json` | invitation → `buildAndSign` (FQDN из ownership UID) |
 * | `config.json` + `certs/signer*.pem` | demo signer (без SAN/EKU Ownership) |
 * | `a1-cloud-config-signed.json` | негатив: UID ≠ FQDN |
 *
 * ## Запуск
 *
 * ```bash
 * cd kotlin
 * ./gradlew :samples:registry-examples:runSign-cloud-config
 *
 * # свои пути:
 * ./gradlew :samples:registry-examples:run --args="sign-cloud-config \
 *   cloud-config.json resp-context.json config.json kotlin-out/cloud-config-signed-fixture"
 * ```
 *
 * ## Важно
 *
 * Production: Ownership leaf + ключ, `requireOwnerBinding=true` (default).
 * Demo `config.json` signer без SAN/Email Protection → binding выключается автоматически.
 */
object SignCloudConfigFixtureExample {
    private val payloadJson = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        explicitNulls = false
    }

    /**
     * @param goodMobDevPath  OK-фикстура (`cloud-config.json` / `mob-dev-cloud_config.json`)
     * @param respContextPath invitation (`resp-context.json`)
     * @param configPath      demo signer
     * @param outputPrefix    без расширения → `{prefix}.json` + `{prefix}.pem` + `{prefix}-from-context.*`
     * @param badMobDevPath   негатив для binding (default `a1-cloud-config-signed.json`), optional
     */
    fun run(
        goodMobDevPath: Path,
        respContextPath: Path,
        configPath: Path,
        outputPrefix: Path,
        badMobDevPath: Path? = null,
    ) {
        SampleSupport.section("sign-cloud-config — fixtures → CMS")

        val configDir = configPath.parent?.toString() ?: "."
        val buildCfg = ConfigLoader.toBuildConfig(
            ConfigLoader.readConfig(configPath.toString()),
            configDir,
        )
        val signerSubject = PlatformCrypto.parseCertificate(buildCfg.signerCertDer).subject
        val hasOwnershipSan = CloudConfigCms.extractSanUris(buildCfg.signerCertDer).isNotEmpty()
        val requireBinding = hasOwnershipSan
        println("demo signer:     $signerSubject")
        println("requireBinding:  $requireBinding (SAN present = Ownership leaf)")
        println()

        // ── 1. OK-фикстура: verify + binding/EKU ─────────────────────────────
        SampleSupport.section("1) OK fixture — verify + owner_id binding")
        val good = MobDevCloudConfigJson.parse(SampleSupport.readBytes(goodMobDevPath)).cloudConfiguration
        println("fixture:   $goodMobDevPath")
        println("vin:       ${good.vin}")
        println("owner_id:  ${good.ownerId}")
        val goodPayload = payloadJson.decodeFromString(
            CloudBrokerConfigPayload.serializer(),
            good.cloudConfigJson,
        )
        println("FQDN:      ${goodPayload.cloudBroker.endpoint.baseDomain}")
        CloudConfigCms.verifyCloudConfiguration(good)
        println("verifyCloudConfiguration: OK")
        CloudConfigCms.requireOwnerIdInSigner(good)
        CloudConfigCms.requireOwnerIdBinding(good)
        println("requireOwnerIdBinding: OK (FQDN + SAN + EKU Email Protection)")
        println()

        // ── 2. Пересборка FQDN из owner_id + resign (demo key) ───────────────
        SampleSupport.section("2) Resign fixture payload (FQDN = hashB(VIN)-owner_id.…)")
        val domainSuffix = stripOwnerFqdnPrefix(
            goodPayload.cloudBroker.endpoint.baseDomain,
            good.ownerId,
        )
        val resolvedFqdn = CloudBrokerFqdn.buildFqdn(
            vin = good.vin,
            identityId = good.ownerId,
            domainSuffix = domainSuffix,
        )
        val rebuiltPayload = goodPayload.copy(
            cloudBroker = goodPayload.cloudBroker.copy(
                endpoint = goodPayload.cloudBroker.endpoint.copy(baseDomain = resolvedFqdn),
            ),
        )
        val compactJson = payloadJson.encodeToString(
            CloudBrokerConfigPayload.serializer(),
            rebuiltPayload,
        )
        println("resolved FQDN: $resolvedFqdn")

        val (signedJson, cmsPem) = CloudConfigFromContext.signTboxPayload(
            tboxJson = compactJson,
            signerCertDer = buildCfg.signerCertDer,
            signerKey = buildCfg.signerKey,
            vin = good.vin,
            fqdnIdentityId = good.ownerId,
            ownerId = good.ownerId,
            requireOwnerBinding = requireBinding,
        )
        CloudConfigCms.verifyJsonMatchesEContent(
            CloudConfigCms.parsePem(cmsPem),
            signedJson,
        )
        CloudConfigCms.verify(CloudConfigCms.parsePem(cmsPem))
        println("signTboxPayload + CMS verify: OK")

        Files.createDirectories(outputPrefix.parent)
        val outPem = outputPrefix.resolveSibling(outputPrefix.fileName.toString() + ".pem")
        val outJson = outputPrefix.resolveSibling(outputPrefix.fileName.toString() + ".json")
        Files.writeString(outPem, cmsPem)
        val resignedDto = good.copy(
            baseDomain = resolvedFqdn,
            cloudConfigJson = signedJson,
            cloudConfigPem = cmsPem,
        )
        Files.writeString(
            outJson,
            CloudConfigFromContext.encodeMobDevResponse(resignedDto, pretty = true),
        )
        println("written: $outPem")
        println("written: $outJson")
        println()

        // ── 3. Invitation → buildAndSign (owner_id в FQDN) ───────────────────
        SampleSupport.section("3) resp-context → buildAndSign (owner_id FQDN)")
        val invitation = CloudConfigFromContext.parseInvitationResponse(
            SampleSupport.readBytes(respContextPath),
        )
        val ownershipUid = CloudConfigFromContext.extractOwnerIdFromOwnershipCms(
            invitation.context.ownershipRegistry,
        )
        val expectedFqdn = CloudBrokerFqdn.buildFqdn(
            vin = invitation.vin,
            identityId = ownershipUid,
            domainSuffix = invitation.context.vehicleCloudConfiguration.cloudBroker.endpoint.baseDomain,
        )
        println("fixture:       $respContextPath")
        println("vin:           ${invitation.vin}")
        println("tenant_id:     ${invitation.tenantId} (не для FQDN)")
        println("owner_id/UID:  $ownershipUid")
        println("CES FQDN:      $expectedFqdn")

        val fromContext = CloudConfigFromContext.buildAndSign(
            response = invitation,
            signerCertDer = buildCfg.signerCertDer,
            signerKey = buildCfg.signerKey,
            payloadVersion = 5,
            ownerId = ownershipUid,
            fqdnIdentityId = ownershipUid,
            requireOwnerBinding = requireBinding,
        )
        require(fromContext.baseDomain.contains(ownershipUid)) {
            "FQDN must embed owner_id=$ownershipUid, got ${fromContext.baseDomain}"
        }
        CloudConfigCms.verifyCloudConfiguration(fromContext)
        println("buildAndSign + verify: OK")
        println("signed baseDomain: ${fromContext.baseDomain}")

        val ctxPrefix = outputPrefix.resolveSibling(
            outputPrefix.fileName.toString() + "-from-context",
        )
        val ctxPem = ctxPrefix.resolveSibling(ctxPrefix.fileName.toString() + ".pem")
        val ctxJson = ctxPrefix.resolveSibling(ctxPrefix.fileName.toString() + ".json")
        val ctxTbox = ctxPrefix.resolveSibling(ctxPrefix.fileName.toString() + "-tbox.json")
        Files.writeString(ctxPem, fromContext.cloudConfigPem)
        Files.writeString(ctxJson, CloudConfigFromContext.encodeMobDevResponse(fromContext, pretty = true))
        Files.writeString(ctxTbox, CloudConfigFromContext.encodeTboxPayload(fromContext, pretty = true))
        println("written: $ctxPem")
        println("written: $ctxJson")
        println("written: $ctxTbox")
        println()

        // ── 4. Негатив: a1 — owner_id ≠ FQDN ────────────────────────────────
        val badPath = badMobDevPath?.takeIf { Files.isRegularFile(it) }
        if (badPath != null) {
            SampleSupport.section("4) Negative fixture — binding must FAIL")
            val bad = MobDevCloudConfigJson.parse(SampleSupport.readBytes(badPath)).cloudConfiguration
            println("fixture:  $badPath")
            println("owner_id: ${bad.ownerId}")
            val badFqdn = runCatching {
                payloadJson.decodeFromString(
                    CloudBrokerConfigPayload.serializer(),
                    bad.cloudConfigJson,
                ).cloudBroker.endpoint.baseDomain
            }.getOrDefault(bad.baseDomain)
            println("FQDN:     $badFqdn")
            try {
                CloudConfigCms.requireOwnerIdBinding(bad, requireEku = false)
                error("expected requireOwnerIdBinding to fail for $badPath")
            } catch (e: IllegalArgumentException) {
                println("requireOwnerIdBinding: FAIL as expected — ${e.message}")
            }
        } else {
            println("(negative fixture skipped)")
        }

        println()
        SampleSupport.section("done")
        println("good fixture:     ${goodMobDevPath.fileName}")
        println("owner_id:         ${good.ownerId}")
        println("resigned:         $outJson")
        println("from-context:     $ctxJson")
        println("requireBinding:   $requireBinding")
    }

    /** Если FQDN уже `hash-owner.suffix` — вернуть только suffix; иначе весь host как suffix. */
    private fun stripOwnerFqdnPrefix(fqdnOrSuffix: String, ownerId: String): String {
        val host = fqdnOrSuffix.trim().substringBefore(':')
        val label = host.substringBefore('.', missingDelimiterValue = "")
        val marker = "-$ownerId"
        if (label.endsWith(marker, ignoreCase = true) && host.contains('.')) {
            return host.substringAfter('.', missingDelimiterValue = host)
        }
        return host
    }
}
