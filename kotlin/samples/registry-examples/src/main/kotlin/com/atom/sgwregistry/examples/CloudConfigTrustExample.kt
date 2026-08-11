package com.atom.sgwregistry.examples

import com.atom.sgwregistry.cloudconfig.CloudConfigCms
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.model.CloudConfigCmsContainer
import com.atom.sgwregistry.model.CloudConfigurationDto
import com.atom.sgwregistry.model.MobDevCloudConfigJson
import java.nio.file.Files
import java.nio.file.Path
import java.security.cert.X509Certificate
import java.util.Date

/**
 * Пошаговая проверка **доверия** к полученному от сервиса B2B Virtual Device
 * payload  `cloud_configuration`. ( проверку цепочки доверия к CMS-leaf можно пропустить, см. `continueCmsOnTrustFail`)
 *------------------------------------------------------------------------------------------------
 * Это  JSON:
 * - `cloud_config_json` + `cloud_config_pem` — CMS SignedData (подписанная конфигурация брокера);
 * - `vin` / `owner_id` — идентичность владельца/ТС;
 * - `root_cas` — CA для **TLS MQTT-брокера** (обычно ATOM ROOT + Tenant).
 *
 * В `cloud_config_pem` обычно только **leaf владельца** (подписант CMS).
 * Отдельного клиентского MQTT mTLS-сертификата в этом JSON **нет** — его выдаёт enrollment.
 *
 * ## Шаги сценария
 *
 * | # | Проверка | Смысл | API |
 * |---|----------|--------|-----|
 * | 1 | Identity | поля JSON = ожидания приложения | [CloudConfigCms.requireIdentity] |
 * | 2a | Owner ↔ leaf | `owner_id` в UID subject подписанта | [CloudConfigCms.requireOwnerIdInSigner] |
 * | 2b | PKIX | leaf доверен через Ownership → ROOT ext | [JvmCertificateTrust.verifyChain] |
 * | 3 | CMS | json == eContent + ECDSA-подпись leaf | [CloudConfigCms.verify] |
 *
 * ## Две разные ветки PKI (частая путаница)
 *
 * **MQTT TLS** (проверить сервер брокера):
 * ```
 * trust store = root_cas  (== cloudBroker.rootCAs)
 * ```
 *
 * **Подпись cloud_config_pem** (доверить leaf, которым подписан CMS):
 * ```
 * leaf (UID=owner_id, issuer=ATOM Ownership CA)
 *   → ATOM Ownership CA     ← certs/ATOM Ownership CA.pem   (intermediate)
 *     → ATOM ROOT ext CA    ← certs/ATOM ROOT ext CA.pem    (trust anchor, self-signed)
 * ```
 * `root_cas` к CMS-leaf **сами по себе не ведут** (Tenant/ROOT — другая ветка).
 *
 * ## Запуск
 * ```bash
 * ./gradlew :samples:registry-examples:runCloud-config-trust
 * ./gradlew :samples:registry-examples:run --args="cloud-config-trust mob-dev-cloud_config.json VIN OWNER_ID [ownership-ca.pem]"
 * ```
 *
 * PKIX — только JVM ([JvmCertificateTrust]). Parse/verify CMS — commonMain ([CloudConfigCms]).
 *
 * @see CloudConfigCms
 * @see JvmCertificateTrust
 * @see kotlin/README.md раздел «Cloud configuration (mob-dev)»
 */
object CloudConfigTrustExample {

    /**
     * Промежуточный CA подписанта CMS.
     *
     * Subject должен быть `CN=ATOM Ownership CA` и совпадать с issuer leaf
     * (SKID CA = AKID leaf). Путь относительно корня репозитория
     * (Gradle `workingDir` = parent of `kotlin/`).
     */
    private const val OWNERSHIP_CA_REL = "certs/ATOM Ownership CA.pem"

    /**
     * Trust anchor ветки Ownership.
     *
     * Self-signed `CN=ATOM ROOT ext CA`, issuer Ownership CA.
     * Без этого PEM PKIX не замыкает путь leaf → Ownership → ?, даже при верном Ownership CA.
     * Не путать с `root_cas[0]` (ATOM ROOT CA) — это другой корневой сертификат.
     */
    private const val ROOT_EXT_CA_REL = "certs/ATOM ROOT ext CA.pem"

    /**
     * Точка входа CLI (`cloud-config-trust`).
     *
     * @param mobDevJsonPath JSON с `cloud_configuration`
     *   (fixture `mob-dev-cloud_config.json` или `kotlin-out/…-resigned.json`)
     * @param expectedVin VIN, который приложение считает «своим»
     * @param expectedOwnerId owner_id; должен совпасть с UID в subject leaf
     * @param intermediateCaPemPath явный PEM Ownership CA; `null` → [OWNERSHIP_CA_REL]
     * @param continueCmsOnTrustFail при FAIL шага 2b всё равно выполнить шаг 3
     *   (показать, что подпись и trust — разные проверки)
     */
    fun run(
        mobDevJsonPath: Path,
        expectedVin: String,
        expectedOwnerId: String,
        intermediateCaPemPath: Path? = null,
        continueCmsOnTrustFail: Boolean = true,
    ) {
        SampleSupport.section("Cloud config trust — step-by-step")

        // Линейный сценарий: каждый шаг — отдельный метод проверки CMS
        val dto = parseDto(mobDevJsonPath)
        checkIdentity(dto, expectedVin, expectedOwnerId)

        val (container, signerDer) = checkOwnerInSigner(dto)
        val trustOk = checkPkix(dto, signerDer, intermediateCaPemPath)
        checkCmsSignature(dto, container, trustOk, continueCmsOnTrustFail)

        println()
        println("=== summary ===")
        println("Step 1 identity:           OK")
        println("Step 2a owner↔signer UID:  OK")
        println("Step 2b PKIX → anchors:    ${if (trustOk) "OK" else "FAIL"}")
        println("Step 3 CMS signature:      OK")
    }

    // ── steps ────────────────────────────────────────────────────────────────

    /**
     * Step 0 — разбор JSON ответа облака.
     *
     * [MobDevCloudConfigJson] → [CloudConfigurationDto]:
     * vin, owner_id, root_cas, cloud_config_json, cloud_config_pem, …
     * Сети нет: читаем локальный файл.
     */
    private fun parseDto(path: Path): CloudConfigurationDto {
        val dto = MobDevCloudConfigJson.parse(SampleSupport.readBytes(path)).cloudConfiguration
        println("file:      $path")
        println("id:        ${dto.id}")
        println("vin:       ${dto.vin}")
        println("owner_id:  ${dto.ownerId}")
        // root_cas == cloudBroker.rootCAs — trust store TLS MQTT, не цепочка CMS-leaf
        println("root_cas:  ${dto.rootCas.size}  (MQTT TLS trust, not CMS chain)")
        println()
        return dto
    }

    /**
     * Step 1 — идентичность конфигурации.
     *
     * Early-reject до крипты: JSON должен относиться к ожидаемому VIN/владельцу.
     * Несовпадение → [IllegalArgumentException] из [CloudConfigCms.requireIdentity].
     */
    private fun checkIdentity(dto: CloudConfigurationDto, vin: String, ownerId: String) {
        SampleSupport.section("Step 1 — identity (vin / owner_id)")
        println("expected vin:      $vin")
        println("expected owner_id: $ownerId")
        CloudConfigCms.requireIdentity(dto, vin, ownerId)
        println("identity: OK")
    }

    /**
     * Step 2a — привязка owner_id к сертификату подписанта CMS.
     *
     * 1. Парсим `cloud_config_pem` (standalone CMS SignedData, **не** PFX).
     * 2. Достаём leaf (обычно единственный cert в CMS; issuer = Ownership CA).
     * 3. Проверяем, что `owner_id` присутствует в UID subject leaf
     *    ([CloudConfigCms.requireOwnerIdInSigner]).
     *
     * @return контейнер CMS (для шага 3) и DER leaf (для PKIX)
     */
    private fun checkOwnerInSigner(dto: CloudConfigurationDto): Pair<CloudConfigCmsContainer, ByteArray> {
        SampleSupport.section("Step 2a — owner_id in signer subject")
        val container = CloudConfigCms.parsePem(dto.cloudConfigPem)
        val signerDer = requireNotNull(container.signerCertDer.takeIf { container.signerCertResolved }) {
            "signer certificate not resolved from cloud_config_pem"
        }
        val signer = PlatformCrypto.parseCertificate(signerDer)
        println("signer subject: ${signer.subject}")
        println("signer issuer:  ${signer.issuer}")
        CloudConfigCms.requireOwnerIdInSigner(dto)
        println("owner_id ↔ signer UID: OK")
        // CES: owner_id ↔ FQDN (baseDomain) ↔ SAN URI; EKU = Email Protection (не Client Auth)
        CloudConfigCms.requireOwnerIdBinding(dto)
        println("owner_id ↔ FQDN ↔ SAN URI ↔ EKU Email Protection: OK")
        return container to signerDer
    }

    /**
     * Step 2b — PKIX: доверен ли leaf как сертификат.
     *
     * Собираем:
     * - **intermediate** = Ownership CA (issuer leaf);
     * - **trust anchors** = `root_cas` (MQTT) **+** ROOT ext CA (якорь ветки Ownership).
     *
     * JVM [CertPathValidator] примет путь к *любому* якорю; для CMS-leaf фактически
     * сходится путь на ROOT ext. `root_cas` добавляем, потому что они есть в ответе mob-dev,
     *  без ROOT ext шаг  всегда FAIL.
     *
     * @return `true`, если цепочка валидна на выбранную [pkixDateFor]
     */
    private fun checkPkix(
        dto: CloudConfigurationDto,
        signerDer: ByteArray,
        intermediateCaPemPath: Path?,
    ): Boolean {
        SampleSupport.section("Step 2b — PKIX (Ownership + ROOT ext)")

        // Лог MQTT trust store из ответа (для наглядности; к CMS-leaf не цепляется)
        dto.rootCas.forEachIndexed { i, pem ->
            val ca = JvmCertificateTrust.loadX509(pem)
            println("root_cas[$i]: ${ca.subjectX500Principal.name}")
        }

        // Ownership CA: CLI-путь или файл по умолчанию из certs/
        val ownershipPem = loadPemOrNull(
            path = intermediateCaPemPath?.takeIf { Files.isRegularFile(it) }
                ?: resolveUnderRepo(OWNERSHIP_CA_REL),
            label = "intermediate Ownership CA",
        )
        // ROOT ext — обязательный якорь ветки Ownership
        val rootExtPem = loadPemOrNull(
            path = resolveUnderRepo(ROOT_EXT_CA_REL),
            label = "trust anchor ROOT ext CA",
        )

        // Частая ошибка: в Ownership-файл положили ROOT ext / Tenant
        ownershipPem?.let { warnIfWrongOwnershipCa(signerDer, it) }

        val intermediates = listOfNotNull(ownershipPem)
        val trustAnchors = dto.rootCas + listOfNotNull(rootExtPem)
        val leaf = JvmCertificateTrust.loadX509(signerDer)
        // Fixture leaf часто уже «протух» по wall-clock → см. pkixDateFor
        val pkixDate = pkixDateFor(leaf)

        val (ok, detail) = JvmCertificateTrust.verifyChain(
            leafDer = signerDer,
            trustAnchorPems = trustAnchors,
            intermediatePems = intermediates,
            validationDate = pkixDate,
        )
        if (ok) {
            println("trust chain: OK — $detail")
        } else {
            println("trust chain: FAIL — $detail")
            println(
                "Нужны: $OWNERSHIP_CA_REL (intermediate) и $ROOT_EXT_CA_REL (trust anchor). " +
                    "root_cas = MQTT (ROOT/Tenant), не цепочка CMS-leaf.",
            )
        }
        return ok
    }

    /**
     * Step 3 — криптографическая проверка CMS (независимо от «доверен ли leaf»).
     *
     * 1. [CloudConfigCms.verifyJsonMatchesEContent] — UTF-8(`cloud_config_json`) == eContent.
     * 2. [CloudConfigCms.verify] — ECDSA-подпись сходится с публичным ключом leaf.
     *
     * Итог «подпись OK» ≠ «leaf из доверенной PKI» (это шаг 2b).
     * Если PKIX упал и [continueOnTrustFail]=false — останавливаемся до CMS.
     */
    private fun checkCmsSignature(
        dto: CloudConfigurationDto,
        container: CloudConfigCmsContainer,
        trustOk: Boolean,
        continueOnTrustFail: Boolean,
    ) {
        SampleSupport.section("Step 3 — CMS signature")
        if (!trustOk && !continueOnTrustFail) {
            error("Stopped after trust failure (continueCmsOnTrustFail=false)")
        }
        if (!trustOk) {
            println("(PKIX FAIL — CMS всё равно для демо шага 3)")
        }
        CloudConfigCms.verifyJsonMatchesEContent(container, dto.cloudConfigJson)
        println("json ↔ eContent: OK")
        CloudConfigCms.verify(container)
        println("CMS signature: OK")
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /** Путь относительно корня репозитория (`SampleSupport.repoRoot`). */
    private fun resolveUnderRepo(relative: String): Path =
        SampleSupport.repoRoot.resolve(relative)

    /**
     * Читает PEM с диска и печатает subject/issuer.
     * @return текст PEM или `null`, если файла нет
     */
    private fun loadPemOrNull(path: Path?, label: String): String? {
        if (path == null || !Files.isRegularFile(path)) {
            println("$label: (not found)")
            return null
        }
        val pem = Files.readAllBytes(path).decodeToString()
        val cert = JvmCertificateTrust.loadX509(pem)
        println("$label: $path")
        println("  subject: ${cert.subjectX500Principal.name}")
        println("  issuer:  ${cert.issuerX500Principal.name}")
        return pem
    }

    /**
     * Страховка от неверного PEM в слоте Ownership CA.
     * Сравнивает CN subject загруженного CA с CN issuer leaf.
     * Если не совпали (например, лежит ROOT ext) — WARNING в консоль, PKIX скорее FAIL.
     */
    private fun warnIfWrongOwnershipCa(signerDer: ByteArray, ownershipPem: String) {
        val leafIssuerCn = cnOf(PlatformCrypto.parseCertificate(signerDer).issuer)
        val caCn = cnOf(JvmCertificateTrust.loadX509(ownershipPem).subjectX500Principal.name)
        if (leafIssuerCn.isNotEmpty() && !caCn.equals(leafIssuerCn, ignoreCase = true)) {
            println(
                "WARNING: CA CN='$caCn' != leaf issuer CN='$leafIssuerCn'. " +
                    "Нужен ATOM Ownership CA, не ROOT ext / Tenant.",
            )
        }
    }

    /**
     * Дата для PKIX-проверки срока действия.
     * Stage-leaf в `mob-dev-cloud_config.json` часто живёт ~1 час.
     * Если «сейчас» вне `notBefore..notAfter`, валидатор вернёт *validity check failed*.
     * Для демо тогда берём [X509Certificate.getNotBefore] (проверка цепочки, не «сейчас по UTC»).
     */
    private fun pkixDateFor(leaf: X509Certificate): Date {
        val now = Date()
        if (!now.before(leaf.notBefore) && !now.after(leaf.notAfter)) return now
        println(
            "NOTE: leaf ${leaf.notBefore} .. ${leaf.notAfter}; now=$now — " +
                "PKIX date = leaf.notBefore",
        )
        return leaf.notBefore
    }

    /** Извлечение `CN=…` из DN-строки (до следующей запятой). */
    private fun cnOf(dn: String): String =
        dn.substringAfter("CN=", "").substringBefore(',').trim()
}
