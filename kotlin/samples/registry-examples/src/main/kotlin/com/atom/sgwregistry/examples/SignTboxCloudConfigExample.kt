package com.atom.sgwregistry.examples

import com.atom.sgwregistry.cloudconfig.CloudConfigCms
import com.atom.sgwregistry.cloudconfig.CloudConfigFromContext
import com.atom.sgwregistry.config.ConfigLoader
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.model.CloudBrokerConfigPayload
import com.atom.sgwregistry.model.CloudConfigurationDto
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.Json

/**
 * JVM-пример: подпись TBOX payload → аналог поля `cloud_config_pem`.
 *
 * ## Зачем
 *
 * После `cloud-config-from-context` на диске лежит **только JSON для TBOX**:
 * ```json
 * {
 *   "v": 5,
 *   "cloudBroker": {
 *     "rootCAs": [ "...PEM..." ],
 *     "endpoint": { "fqdnConstrAlg": 1, "baseDomain": "mqtt.atom.auto" }
 *   }
 * }
 * ```
 *
 * Для mob-dev / trust / хранения рядом нужен ещё CMS SignedData —
 * то же, что в envelope поле `cloud_config_pem` (`-----BEGIN CMS-----`).
 * Этот пример берёт TBOX JSON и подписывает его owner/demo-ключом.
 *
 * ## Связь полей
 *
 * | Артефакт | Смысл |
 * |----------|--------|
 * | вход `cloud-config-tbox.json` | pretty (или compact) payload |
 * | eContent CMS | **компактный** UTF-8 того же payload (= `cloud_config_json`) |
 * | выход `.pem` | CMS PEM (= `cloud_config_pem`) |
 * | выход `.envelope.json` | mob-dev обёртка для `cloud-config-trust` |
 *
 * Pretty и compact — один и тот же объект; в подпись идёт **компактная**
 * сериализация (как в `CloudConfigFromContext.buildCloudConfigJson`).
 *
 * ## Запуск
 *
 * ```bash
 * cd kotlin
 * # минимально (только PEM + envelope без vin/owner_id):
 * ./gradlew :samples:registry-examples:run --args="sign-tbox kotlin-out/cloud-config-tbox.json config.json"
 *
 * # с vin + tenant_id (FQDN по CES §5) + owner_id для trust:
 * ./gradlew :samples:registry-examples:run --args="sign-tbox kotlin-out/cloud-config-tbox.json config.json kotlin-out/cloud-config-tbox-signed EAY1F1C56T2000014 2281305f-4b16-4a49-989a-9abeeac2df20 9c1dc2f4-a015-46b7-b88f-a9e30d0a9f86"
 * ```
 *
 * Аргументы CLI (см. [RegistryExamplesMain] `sign-tbox`):
 * 1. TBOX JSON
 * 2. `config.json` — signerCert / signerKey
 * 3. prefix выхода (default `kotlin-out/cloud-config-tbox-signed`)
 * 4. (optional) `vin` — для hashB и envelope
 * 5. (optional) `fqdnId` — tenant_id или owner UID → `hashB(VIN)-fqdnId.…`
 * 6. (optional) `owner_id` — для envelope / trust
 *
 * ## Production vs demo
 *
 * Demo подписывает `certs/signer.pem` из config (часто без UID).
 * В production — ключ ownership leaf, `owner_id` = UID subject.
 */
object SignTboxCloudConfigExample {

    /** Один экземпляр Json: парсим compact eContent обратно в модель для envelope. */
    private val json = Json { ignoreUnknownKeys = true }

    /**
     * @param tboxJsonPath  путь к `{ "v", "cloudBroker": ... }`
     * @param configPath    signer для CMS
     * @param outputPrefix  без расширения → `{prefix}.pem` и `{prefix}.envelope.json`
     * @param vin             VIN для envelope / hashB (CES §5)
     * @param fqdnIdentityId  id после hashB(VIN)- в FQDN (tenant_id или owner UID)
     * @param ownerId         owner_id в envelope; если пусто — UID из subject signer
     */
    fun run(
        tboxJsonPath: Path,
        configPath: Path,
        outputPrefix: Path,
        vin: String = "",
        fqdnIdentityId: String = "",
        ownerId: String = "",
    ) {
        SampleSupport.section("sign-tbox — TBOX JSON → cloud_config_pem")

        // ── 1. Вход: TBOX JSON + demo signer ─────────────────────────────────
        // tboxText может быть pretty-printed — signTboxPayload нормализует в compact.
        val tboxText = SampleSupport.readBytes(tboxJsonPath).decodeToString()

        // ConfigLoader резолвит PEM относительно каталога config.json.
        val configDir = configPath.parent?.toString() ?: "."
        val buildCfg = ConfigLoader.toBuildConfig(
            ConfigLoader.readConfig(configPath.toString()),
            configDir,
        )

        val signerSubject = PlatformCrypto.parseCertificate(buildCfg.signerCertDer).subject
        println("input:  $tboxJsonPath")
        println("signer: $signerSubject")
        if (vin.isNotBlank() && fqdnIdentityId.isNotBlank()) {
            println("CES FQDN inputs: vin=$vin, identityId=$fqdnIdentityId")
        }
        println()

        // ── 2. Подпись: TBOX → (compactJson, cmsPem) ─────────────────────────
        // CloudConfigFromContext.signTboxPayload:
        //   a) decode CloudBrokerConfigPayload (pretty или compact)
        //   b) при vin+fqdnIdentityId и alg=1 — CES FQDN в endpoint.baseDomain
        //   c) encode compact → eContent
        //   d) CloudConfigCms.resignToPem → BEGIN CMS
        // Demo signer.pem без SAN — binding выкл.; Ownership leaf с atombus:/user/{id} → вкл.
        val requireBinding = CloudConfigCms.extractSanUris(buildCfg.signerCertDer).isNotEmpty()
        val (compactJson, cmsPem) = CloudConfigFromContext.signTboxPayload(
            tboxJson = tboxText,
            signerCertDer = buildCfg.signerCertDer,
            signerKey = buildCfg.signerKey,
            vin = vin.takeIf { it.isNotBlank() },
            fqdnIdentityId = fqdnIdentityId.takeIf { it.isNotBlank() },
            ownerId = ownerId.takeIf { it.isNotBlank() },
            requireOwnerBinding = requireBinding,
        )
        println("endpoint.baseDomain (after CES resolve): see compact JSON / envelope")
        println()

        // ── 3. Локальная проверка CMS ────────────────────────────────────────
        // (3a) байты eContent == UTF-8 compactJson (без pretty-пробелов)
        CloudConfigCms.verifyJsonMatchesEContent(
            CloudConfigCms.parsePem(cmsPem),
            compactJson,
        )
        // (3b) ECDSA-подпись SignerInfo валидна относительно leaf в CMS
        CloudConfigCms.verifyPem(cmsPem.encodeToByteArray())
        println("verify CMS: OK (eContent ↔ compact JSON)")

        // ── 4. Запись артефактов ─────────────────────────────────────────────
        // .pem  — чистый аналог cloud_config_pem (то, что часто кладут в TBOX/API отдельно)
        // .envelope.json — полный mob-dev JSON для CLI trust / отладки
        val pemPath = Path.of(outputPrefix.toString() + ".pem")
        val envelopePath = Path.of(outputPrefix.toString() + ".envelope.json")
        Files.createDirectories(outputPrefix.parent)

        Files.write(pemPath, cmsPem.encodeToByteArray())

        // Собираем CloudConfigurationDto: json + pem + метаданные из payload / CLI.
        val payload = json.decodeFromString<CloudBrokerConfigPayload>(compactJson)
        val dto = CloudConfigurationDto(
            rootCas = payload.cloudBroker.rootCAs,
            vin = vin,
            // owner_id: явный CLI → иначе UID из subject demo signer (часто пусто)
            ownerId = ownerId.ifBlank {
                CloudConfigFromContext.extractUidFromSubject(signerSubject).orEmpty()
            },
            version = payload.v.toString(),
            baseDomain = payload.cloudBroker.endpoint.baseDomain,
            cloudConfigJson = compactJson,
            cloudConfigPem = cmsPem,
        )
        Files.write(
            envelopePath,
            CloudConfigFromContext.encodeMobDevResponse(dto).encodeToByteArray(),
        )

        println()
        println("cloud_config_pem → $pemPath")
        println("envelope       → $envelopePath")
        println("compact json bytes (eContent): ${compactJson.encodeToByteArray().size}")

        // Подсказка trust имеет смысл только если заданы vin + owner_id
        // (иначе step 1 identity у cloud-config-trust упадёт).
        if (dto.ownerId.isNotBlank() && dto.vin.isNotBlank()) {
            println()
            println("Trust (if vin/owner_id set):")
            println(
                "  ./gradlew :samples:registry-examples:run --args=" +
                    "\"cloud-config-trust ${envelopePath.fileName} ${dto.vin} ${dto.ownerId}\"",
            )
        }
    }
}
