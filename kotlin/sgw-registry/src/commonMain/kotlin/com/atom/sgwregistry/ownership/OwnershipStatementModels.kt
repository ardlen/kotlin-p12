/**
 * Модели ownership statement ledger — цепочка подписанных записей о владении автомобилем.
 *
 * ## Контекст
 *
 * Облачный invitation / ownership-сервис должен отдавать `context.ownership_registry` как
 * **массив** PEM CMS (`-----BEGIN CMS-----`), а не один PFX v3 (как в старом `resp-context.json`).
 *
 * Каждый элемент массива — standalone CMS SignedData, у которого eContent = JSON
 * [OwnershipStatement] (поля `VIN`, `owner_dn`, `v`, `p_hash`).
 *
 * ## Связность цепочки
 *------------------------------
 * CMS[0]  eContent { v=1, p_hash="" , VIN, owner_dn=UID=A… }
 * ------------------------------
 * CMS[1]  eContent { v=2, p_hash=hex(sig CMS[0]), VIN, owner_dn=UID=B… }
 * ------------------------------
 * …
 * ------------------------------
 * CMS[n]  eContent { v=n+1, p_hash=hex(sig CMS[n-1]), … }
 * ------------------------------
 *
 * - `p_hash` 1 запись = genesis пустой (всегда это первый statement);
 * - `p_hash` следующего statement = lowercase hex DER ECDSA-подписи предыдущего CMS
 *   (`SignerInfo.signature` / `encryptedDigest`);
 * - все statements всегда относятся к **одному** автомобилю → одинаковый `VIN`;
 *
 * Текущий владелец = UID всегда из `owner_dn` последнего statement.
 *
 * Fixture: корневой  как иссточник данных`ownership-resp.json (струкутра invitation context от ручки).
 * Проверка: [OwnershipRegistryVerifier] (всегда валидирует по `VIN` и `owner_dn` последнего statement).
 */
package com.atom.sgwregistry.ownership

import com.atom.sgwregistry.model.VehicleCloudConfigurationDraft
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * JSON eContent одного ownership statement (полезная нагрузка CMS).
 *
 * Пример genesis (`v = 1`):
 * ```json
 * {
 *   "VIN": "AAABBBCCC3",
 *   "owner_dn": "UID=00000000-0000-7000-8000-000057751751,OU=EnhancedAuth+OU=Customers,O=ATOM",
 *   "v": 1,
 *   "p_hash": ""
 * }
 * ```
 *
 * Пример передачи владения (`v = 2`): тот же `VIN`, новый `owner_dn`,
 * `p_hash` = hex-подпись CMS предыдущего statement.
 *
 * Поля: [vin] (`VIN`), [ownerDn] (`owner_dn`), [v], [previousHash] (`p_hash`).
 */
@Serializable
data class OwnershipStatement(
    @SerialName("VIN") val vin: String = "",
    @SerialName("owner_dn") val ownerDn: String = "",
    val v: Int = 0,
    @SerialName("p_hash") val previousHash: String = "",
)

/**
 * Результат проверки цепочки [OwnershipRegistryVerifier.tryVerify].
 *
 * При `ok == false` в [reason] — причина отказа
 * (пустой список, битая подпись, разорванный `p_hash`, mismatch VIN/ownerId).
 */
data class OwnershipVerifyResult(
    val ok: Boolean,
    val reason: String? = null,
    val statementCount: Int = 0,
    val vin: String? = null,
    val ownerId: String? = null,
)

/**
 * Корневой JSON ответа ownership / invitation ledger (`ownership-resp.json`).
 *
 * Та же envelope-структура, что [com.atom.sgwregistry.model.InvitationContextResponse]
 * (`id` / `status` / `tenant_id` / `vin` / `context`), но
 * `context.ownership_registry` — **массив** standalone CMS statements (не одна строка PFX).
 *
 * Fixture: корневой `ownership-resp.json`.
 */
@Serializable
data class OwnershipLedgerResponse(
    val context: OwnershipLedgerContext = OwnershipLedgerContext(),
    val id: String = "",
    val status: String = "",
    @SerialName("tenant_id") val tenantId: String = "",
    val vin: String = "",
)

/**
 * `context` из `ownership-resp.json` — зеркало [com.atom.sgwregistry.model.InvitationContextDto],
 * с [ownershipRegistry] как `List<String>` PEM CMS (индекс 0 = genesis).
 *
 * Поля `vehicle_cloud_configuration` / mTLS для ledger-verify не используются,
 * но сохраняются в модели, чтобы разбор совпадал со структурой ответа сервиса.
 */
@Serializable
data class OwnershipLedgerContext(
    @SerialName("ownership_registry") val ownershipRegistry: List<String> = emptyList(),
    @SerialName("vehicle_cloud_configuration")
    val vehicleCloudConfiguration: VehicleCloudConfigurationDraft = VehicleCloudConfigurationDraft(),
    @SerialName("vehicle_mtls_cert_pem") val vehicleMtlsCertPem: String = "",
    @SerialName("vehicle_mtls_cert_sha256") val vehicleMtlsCertSha256: String = "",
)

/**
 * Разбор envelope `ownership-resp.json` → [OwnershipLedgerResponse].
 *
 * `ignoreUnknownKeys` — в JSON могут быть дополнительные поля
 * (`vehicle_cloud_configuration`, mTLS и т.д.), для ledger-verify они не нужны.
 */
object OwnershipLedgerJson {
    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = true
    }

    /** UTF-8 байты JSON-файла / ответа API. */
    fun parse(bytes: ByteArray): OwnershipLedgerResponse =
        json.decodeFromString(OwnershipLedgerResponse.serializer(), bytes.decodeToString())

    /** JSON-строка целиком. */
    fun parse(text: String): OwnershipLedgerResponse =
        json.decodeFromString(OwnershipLedgerResponse.serializer(), text)
}
