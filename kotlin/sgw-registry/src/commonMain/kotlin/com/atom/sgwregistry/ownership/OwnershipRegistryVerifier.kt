/**
 * Верификатор цепочки ownership statements (ledger CMS).
 *
 * См. модели и формат: [OwnershipStatement], [OwnershipLedgerResponse].
 */
package com.atom.sgwregistry.ownership

import com.atom.sgwregistry.cloudconfig.CloudConfigCms
import com.atom.sgwregistry.cloudconfig.CloudConfigFromContext
import com.atom.sgwregistry.internal.bytesToHex
import com.atom.sgwregistry.model.CloudConfigCmsContainer
import kotlinx.serialization.json.Json

/**
 * Проверка массива CMS из `context.ownership_registry[]`.
 *
 * ## Алгоритм [tryVerify]
 *
 * Для каждого CMS по порядку `[0 … n-1]`:
 * 1. **Parse** — standalone SignedData через [CloudConfigCms.parsePem]
 *    (не PFX: внутри ContentInfo + SignedData, eContent = JSON statement).
 * 2. **Signature** — [CloudConfigCms.tryVerify] по embedded leaf
 *    (ECDSA-SHA256 над authenticatedAttributes / content).
 * 3. **Statement** — eContent → [OwnershipStatement].
 * 4. **VIN** — `statement.VIN` не пустой, равен аргументу [vin] и совпадает
 *    с VIN первого statement (один автомобиль на всю цепочку).
 * 5. **p_hash**:
 *    - индекс `0` (genesis): `p_hash` обязан быть пустым;
 *    - индекс `i > 0`: `p_hash` == hex(`encryptedDigest` CMS `[i-1]`),
 *      сравнение без учёта регистра.
 * 6. Запомнить hex текущей подписи и UID из `owner_dn` для следующего шага.
 *
 * После успешного прохода всех CMS:
 * - UID из `owner_dn` **последнего** statement должен совпасть с [ownerId]
 *   (trim, case-insensitive для UUID).
 *
 * ## Важно
 *
 * - Подписант CMS (subject leaf) **не обязан** совпадать с `owner_dn` текущего
 *   statement: при передаче владения предыдущий владелец подписывает запись
 *   с новым `owner_dn`.
 * - PKIX к ATOM Ownership CA сюда не входит — только CMS-подпись и ledger-правила.
 * - Пустой список / пустой `ownerId` / пустой `vin` → отказ.
 *
 * ## Пример (fixture `ownership-resp.json`)
 *
 * ```kotlin
 * val ledger = OwnershipLedgerJson.parse(bytes)
 * val ok = OwnershipRegistryVerifier.verify(
 *     ownershipRegistryCms = ledger.context.ownershipRegistry,
 *     ownerId = "7f9fc821-a09e-4f96-badc-643daca070c6", // UID последнего owner_dn
 *     vin = "AAABBBCCC3",
 * )
 * ```
 *
 * Фасад: [com.atom.sgwregistry.api.SgwRegistry.verifyOwnershipRegistry].
 * CLI: `ownership-verify` / `runOwnership-verify`.
 */
object OwnershipRegistryVerifier {
    /** JSON-парсер eContent statement (`ignoreUnknownKeys` на случай доп. полей). */
    private val statementJson = Json {
        ignoreUnknownKeys = true
        isLenient = true
    }

    /**
     * Извлечение `UID=…` из `owner_dn`.
     *
     * Поддерживает RFC-2253-подобный вид:
     * `UID=uuid,OU=EnhancedAuth+OU=Customers,O=ATOM`
     * (многозначный OU через `+` не мешает — UID берётся до первой запятой).
     */
    private val uidInOwnerDn = Regex("""(?i)(?:^|,)\s*UID=([^,]+)""")

    /**
     * Упрощённая проверка: `true` только при полной валидности цепочки.
     *
     * ownershipRegistryCms упорядоченный список PEM CMS (как в JSON-массиве)
     * ownerId ожидаемый UID текущего владельца (последний `owner_dn`)
     * vin ожидаемый VIN автомобиля (должен быть во всех statements)
     */
    fun verify(
        ownershipRegistryCms: List<String>,
        ownerId: String,
        vin: String,
    ): Boolean = tryVerify(ownershipRegistryCms, ownerId, vin).ok

    /**
     * Полная проверка с диагностикой.
     *
     * return [OwnershipVerifyResult] — при ошибке [OwnershipVerifyResult.reason]
     * описывает первый отказавший шаг; [OwnershipVerifyResult.ownerId] /
     * [OwnershipVerifyResult.vin] заполняются по мере разбора цепочки.
     */
    fun tryVerify(
        ownershipRegistryCms: List<String>,
        ownerId: String,
        vin: String,
    ): OwnershipVerifyResult {
        val expectedOwner = ownerId.trim()
        val expectedVin = vin.trim()
        if (ownershipRegistryCms.isEmpty()) {
            return fail("ownership_registry is empty")
        }
        if (expectedOwner.isEmpty()) {
            return fail("ownerId is blank")
        }
        if (expectedVin.isEmpty()) {
            return fail("vin is blank")
        }

        // hex(encryptedDigest) предыдущего CMS — эталон для следующего p_hash
        var prevSignatureHex: String? = null
        // UID из owner_dn последнего успешно разобранного statement
        var lastOwnerId: String? = null
        // VIN первого statement — эталон единообразия цепочки
        var chainVin: String? = null

        for ((index, cmsPem) in ownershipRegistryCms.withIndex()) {
            if (cmsPem.isBlank()) {
                return fail("ownership_registry[$index] is blank")
            }

            // 1–2. CMS parse + криптопроверка подписи embedded leaf
            val container = try {
                CloudConfigCms.parsePem(cmsPem)
            } catch (e: Exception) {
                return fail("ownership_registry[$index] CMS parse failed: ${e.message}")
            }
            val verifyPair = CloudConfigCms.tryVerify(container)
            if (!verifyPair.first) {
                return fail("ownership_registry[$index] signature invalid: ${verifyPair.second}")
            }

            // 3. eContent → OwnershipStatement
            val statement = try {
                parseStatement(container)
            } catch (e: Exception) {
                return fail("ownership_registry[$index] statement JSON invalid: ${e.message}")
            }

            // 4. VIN: аргумент + единообразие внутри цепочки
            val stmtVin = statement.vin.trim()
            if (stmtVin.isEmpty()) {
                return fail("ownership_registry[$index] VIN is blank")
            }
            if (stmtVin != expectedVin) {
                return fail(
                    "ownership_registry[$index] VIN mismatch: expected=$expectedVin, got=$stmtVin",
                )
            }
            if (chainVin == null) {
                chainVin = stmtVin
            } else if (stmtVin != chainVin) {
                return fail(
                    "ownership_registry[$index] VIN differs within chain: first=$chainVin, got=$stmtVin",
                )
            }

            // 5. p_hash ↔ подпись предыдущего CMS
            val pHash = statement.previousHash.trim()
            if (index == 0) {
                // genesis: ссылки на предыдущую запись быть не должно
                if (pHash.isNotEmpty()) {
                    return fail("ownership_registry[0] p_hash must be empty (genesis), got len=${pHash.length}")
                }
            } else {
                val expectedHash = prevSignatureHex
                    ?: return fail("ownership_registry[$index] missing previous signature")
                if (!pHash.equals(expectedHash, ignoreCase = true)) {
                    return fail(
                        "ownership_registry[$index] p_hash does not match previous CMS signature",
                    )
                }
            }

            // Подпись текущего CMS станет p_hash для следующего statement
            val sig = container.encryptedDigest
                ?: return fail("ownership_registry[$index] encryptedDigest absent")
            prevSignatureHex = bytesToHex(sig)

            // Текущий заявленный владелец (для финального сравнения — берётся последний)
            val uid = extractUidFromOwnerDn(statement.ownerDn)
                ?: return fail("ownership_registry[$index] owner_dn has no UID: ${statement.ownerDn}")
            lastOwnerId = uid
        }

        // 6. Текущий владелец = UID последнего statement
        if (!expectedOwner.equals(lastOwnerId, ignoreCase = true)) {
            return OwnershipVerifyResult(
                ok = false,
                reason = "ownerId mismatch: expected=$expectedOwner, last owner_dn UID=$lastOwnerId",
                statementCount = ownershipRegistryCms.size,
                vin = chainVin,
                ownerId = lastOwnerId,
            )
        }

        return OwnershipVerifyResult(
            ok = true,
            reason = null,
            statementCount = ownershipRegistryCms.size,
            vin = chainVin,
            ownerId = lastOwnerId,
        )
    }

    /**
     * Как [tryVerify], но при отказе бросает [IllegalArgumentException]
     * с текстом [OwnershipVerifyResult.reason].
     */
    fun requireVerify(
        ownershipRegistryCms: List<String>,
        ownerId: String,
        vin: String,
    ) {
        val result = tryVerify(ownershipRegistryCms, ownerId, vin)
        require(result.ok) { result.reason ?: "ownership registry verification failed" }
    }

    /**
     * Разбор eContent уже распарсенного CMS → [OwnershipStatement].
     *
     * throws IllegalStateException если в CMS нет eContent
     */
    fun parseStatement(container: CloudConfigCmsContainer): OwnershipStatement {
        val eContent = container.eContentBytes
            ?: throw IllegalStateException("CMS eContent is absent")
        return parseStatement(eContent)
    }

    /** UTF-8 байты JSON eContent → [OwnershipStatement]. */
    fun parseStatement(eContent: ByteArray): OwnershipStatement =
        statementJson.decodeFromString(OwnershipStatement.serializer(), eContent.decodeToString())

    /** JSON-строка statement → [OwnershipStatement]. */
    fun parseStatement(json: String): OwnershipStatement =
        statementJson.decodeFromString(OwnershipStatement.serializer(), json)

    /**
     * UID владельца из поля `owner_dn`.
     *
     * ownerDn например
     *   `UID=7f9fc821-a09e-4f96-badc-643daca070c6,OU=EnhancedAuth+OU=Customers,O=ATOM`
     * return UUID / строка UID или `null`, если атрибут отсутствует
     */
    fun extractUidFromOwnerDn(ownerDn: String): String? {
        val match = uidInOwnerDn.find(ownerDn.trim()) ?: return null
        return match.groupValues[1].trim().takeIf { it.isNotEmpty() }
    }

    /**
     * Проверка цепочки из уже разобранного envelope [OwnershipLedgerResponse].
     *
     *  vin по умолчанию берётся `response.vin` (поле верхнего уровня JSON)
     */
    fun verifyLedger(
        response: OwnershipLedgerResponse,
        ownerId: String,
        vin: String = response.vin,
    ): Boolean = verify(response.context.ownershipRegistry, ownerId, vin)

    /**
     * Как [verifyLedger], но с [OwnershipVerifyResult] для диагностики.
     */
    fun tryVerifyLedger(
        response: OwnershipLedgerResponse,
        ownerId: String,
        vin: String = response.vin,
    ): OwnershipVerifyResult = tryVerify(response.context.ownershipRegistry, ownerId, vin)

    /**
     * UID из X.509 subject сертификата (`UID=…` в DN).
     *
     * Делегирует [CloudConfigFromContext.extractUidFromSubject] —
     * удобно сопоставить leaf подписанта CMS с `owner_dn` (опциональный аудит).
     */
    fun extractUidFromSubject(subject: String): String? =
        CloudConfigFromContext.extractUidFromSubject(subject)

    /** Короткий отказ без заполнения vin/ownerId. */
    private fun fail(reason: String) = OwnershipVerifyResult(ok = false, reason = reason)
}
