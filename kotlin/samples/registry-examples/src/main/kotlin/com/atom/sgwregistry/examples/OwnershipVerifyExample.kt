package com.atom.sgwregistry.examples

import com.atom.sgwregistry.api.SgwRegistry
import com.atom.sgwregistry.ownership.OwnershipLedgerJson
import com.atom.sgwregistry.ownership.OwnershipLedgerResponse
import com.atom.sgwregistry.ownership.OwnershipRegistryVerifier
import java.nio.file.Files
import java.nio.file.Path

/**
 * Два независимых примера ownership ledger verify - 1 парсит JSON invitation, 2 парсит массив PEM сертификатов.
 *
 * | CLI | Вход | API |
 * |-----|------|-----|
 * | `ownership-verify` | структура `ownership-resp.json` | [verifyLedger] |
 * | `ownership-verify-list` | готовая `List<String>` CMS PEM | [verify] |
 *----------------------------------------------------------------------
 * ## Запуск CLI-хелперов тестовых примеров
 *
 * ```bash
 * cd kotlin
 * ./gradlew :samples:registry-examples:runOwnership-verify (кормим сразу JSON invitation, как аргумент CLI)
 * ./gradlew :samples:registry-examples:runOwnership-verify-list (передаём только List<String> CMS PEM, как аргумент CLI)
 *
 * ./gradlew :samples:registry-examples:run --args="ownership-verify-list \
 *   7f9fc821-a09e-4f96-badc-643daca070c6 AAABBBCCC3 \
 *   kotlin-out/ownership-stmt-0.pem kotlin-out/ownership-stmt-1.pem"
 * ```
 * -------------------------------------------------------------------------------------------------
 */
object OwnershipVerifyExample {
    /** ownerId из последнего statement в `ownership-resp.json`. */
    const val FIXTURE_OWNER_ID = "7f9fc821-a09e-4f96-badc-643daca070c6"

    /** VIN envelope / всех statements в `ownership-resp.json`. */
    const val FIXTURE_VIN = "AAABBBCCC3"

    /**
     * CLI `ownership-verify`: структура `ownership-resp.json` → [OwnershipLedgerResponse] → verifyLedger.
     *
     * ## Подготовка
     *----------------------------------------------------------------------
     * Парсится envelope: `id`, `status=INVITATION_STATUS_CREATED`, `vin=AAABBBCCC3`,
     * в `context.ownership_registry` — 2 CMS (genesis → передача владения),
     * плюс draft `vehicle_cloud_configuration` (для verify не нужен).
     *
     * Аргументы API: [OwnershipLedgerResponse] + `ownerId=7f9fc821-…`
     * (UID последнего `owner_dn`) + `vin` из JSON.
     *----------------------------------------------------------------------
     * ledgerJsonPath JSON invitation / ownership ledger (fixture: `ownership-resp.json`)
     * ownerId UID текущего владельца (последний `owner_dn`)
     * vin ожидаемый VIN; `null` → берётся `response.vin` из JSON
     */
    fun run(
        ledgerJsonPath: Path,
        ownerId: String,
        vin: String? = null,
    ) {
        SampleSupport.section("ownership-verify — OwnershipLedgerResponse (ownership-resp.json)")

        //----------------------------------------------------------------------
        // Подготовка: envelope ownership-resp.json → OwnershipLedgerResponse
        //----------------------------------------------------------------------
        // 1) Читаем invitation JSON из файла >ownership-resp.json<. 
        val ledgerBytes = SampleSupport.readBytes(
            SampleSupport.requireExists(ledgerJsonPath, "ownership ledger JSON"),
        )

        // 2) Разбор invitation / ownership envelope в типизированную модель.
        //    OwnershipLedgerJson игнорирует неизвестные поля; из JSON берём:
        //   - id / status / tenant_id / vin  (верхний уровень)
        //   - context.ownership_registry[]   (упорядоченный список CMS PEM)
        //   - context.vehicle_cloud_configuration (draft брокера; для verify не нужен)
        val ledger: OwnershipLedgerResponse = OwnershipLedgerJson.parse(ledgerBytes)

        // 3) VIN для API: явный CLI-аргумент, иначе поле vin из JSON (fixture: AAABBBCCC3).
        //    ownerId сюда не подставляем из statements — его всегда передаёт вызывающий
        //    (ожидаемый текущий владелец = UID последнего owner_dn).
        val expectedVin = vin?.takeIf { it.isNotBlank() } ?: ledger.vin

        // 4) Лог разобранного envelope — визуальная сверка с ownership-resp.json.
        println("парсим блок ownership из ownership-resp.json: $ledgerJsonPath")
        println("id:      ${ledger.id}")
        println("status:  ${ledger.status}") // INVITATION_STATUS_CREATED
        println("vin:     ${ledger.vin}")
        println("tenant:  ${ledger.tenantId.ifBlank { "(empty)" }}")
        // N CMS: [0] genesis (p_hash=""), [1…] передача владения (p_hash = sig предыдущего)
        println("ownership_registry: ${ledger.context.ownershipRegistry.size} CMS")
        println(
            "vehicle_cloud_configuration.current_version: " +
                ledger.context.vehicleCloudConfiguration.currentVersion,
        )
        println()
        println("Подготовка:")
        println("  envelope: id / status / vin; ownership_registry = N CMS (genesis → передача)")
        println("  vehicle_cloud_configuration — draft, для verify не нужен")
        println("  API: OwnershipLedgerResponse + ownerId (UID последнего owner_dn) + vin из JSON")
        println()

        // 5) Дальше — кейсы 1–5: tryVerifyLedger / verifyLedger / фасад / негативы.
        //    response = весь ledger; vin = expectedVin; ownerId — аргумент CLI.
        runFromLedger(
            response = ledger,
            ownerId = ownerId,
            vin = expectedVin,
        )
    }

    /**----------------------------------------------------------------------
      Выполняем проверку по уже разобранной структуре [OwnershipLedgerResponse]
      (как после `OwnershipLedgerJson.parse` / `SgwRegistry.parseOwnershipLedger`).
     ----------------------------------------------------------------------
      ## Кейсы анализа (структура invitation / ownership ledger из `ownership-resp.json`)
     
      1. [tryVerifyLedger] — полная проверка с диагностикой: подписи обоих CMS statements,
         связка `p_hash` (genesis пустой, далее hex(sig предыдущего CMS)), единый VIN, UID последнего владельца.
         Ожидание: `ok=true`, `statementCount=2`, `resolvedOwnerId` совпал с ожидаемым.
     
      2. [verifyLedger] — то же, но только `Boolean` → `true`. 
         (проверка только на валидность, без деталей ошибки)
         
      3. [SgwRegistry.verifyOwnershipLedger] — фасад над тем же `verifyLedger` → `true`. (проверка только на валидность, без деталей ошибки)
         Так же вызывают из приложения. (проверка только на валидность, без деталей ошибки)
     
      4. negative — wrong ownerId: тот же ledger, но чужой UID.
         Ожидаемо `ok=false`: цепочка валидна, но последний владелец не тот
         (`ownerId mismatch`).
     
      5. negative — wrong vin: тот же ledger, VIN `1000VIN000VIN0001`.
         Ожидаемо `ok=false` уже на genesis (`ownership_registry[0] VIN mismatch`) —
         в statements VIN `AAABBBCCC3`.
     
     **  Итог:** позитивный кейс (1–3) подтверждает валидную цепочку владения;
     негативные кейсы (4–5) — что API отвергает неверный текущий owner и неверный VIN.
    ----------------------------------------------------------------------  
     */
    fun runFromLedger(
        response: OwnershipLedgerResponse,
        ownerId: String,
        vin: String = response.vin,
    ) {
        //----------------------------------------------------------------------
        // verifyLedger: уже разобранный OwnershipLedgerResponse + ownerId + vin
        //----------------------------------------------------------------------
        // Вход: response - разобранный OwnershipLedgerResponse (context.ownership_registry[] + vin / id / status …)
        //   response — envelope (context.ownership_registry[] + vin / id / status …)
        //   ownerId  — ожидаемый UID текущего владельца (последний owner_dn)
        //   vin      — ожидаемый VIN; default = response.vin из JSON
        //
        // Что проверяет OwnershipRegistryVerifier внутри:
        //   • подпись каждого CMS (embedded leaf)
        //   • p_hash: genesis пустой; далее hex(sig предыдущего CMS)
        //   • один VIN во всех statements == аргумент vin
        //   • UID из owner_dn последнего statement == аргумент ownerId
        //----------------------------------------------------------------------

        SampleSupport.section("verifyLedger(OwnershipLedgerResponse, ownerId, vin)")
        println("API arguments:")
        println("  response: OwnershipLedgerResponse (vin=${response.vin}, cms=${response.context.ownershipRegistry.size})")
        println("  ownerId:  $ownerId")
        println("  vin:      $vin")
        println()

        //----------------------------------------------------------------------
        // 1) tryVerifyLedger — полная проверка с диагностикой
        //----------------------------------------------------------------------
        // Возвращает OwnershipVerifyResult: ok / reason / statementCount /
        // resolvedVin / resolvedOwnerId — удобно для UI и логов.
        // На fixture ownership-resp.json ожидаем:
        //   ok=true, statementCount=2, resolvedOwnerId == ownerId, resolvedVin == vin.
        SampleSupport.section("1) OwnershipRegistryVerifier.tryVerifyLedger")
        val detailed = OwnershipRegistryVerifier.tryVerifyLedger(
            response = response,
            ownerId = ownerId,
            vin = vin,
        )
        println("ok:              ${SampleSupport.colorBool(detailed.ok)}")
        println("statementCount:  ${detailed.statementCount}")
        println("resolvedVin:     ${detailed.vin}")
        println("resolvedOwnerId: ${detailed.ownerId}")
        if (detailed.reason != null) {
            println("reason:          ${detailed.reason}")
        }
        // Падаем с ошибкой, если позитивный кейс неожиданно провалился (битая структура вложенных сертификатов).
        // check(detailed.ok) фиксирует ожидаемый отказ.
        check(detailed.ok) { "tryVerifyLedger FAILED: ${detailed.reason}" }
        println("→ ${SampleSupport.colorOkLabel()}")

        //----------------------------------------------------------------------
        // 2) verifyLedger — тот же алгоритм, результат Boolean
        //----------------------------------------------------------------------
        // Без OwnershipVerifyResult: true / false. Для приложения, которому
        // достаточно «прошла / не прошла», без текста причины.
        SampleSupport.section("2) OwnershipRegistryVerifier.verifyLedger")
        val ok = OwnershipRegistryVerifier.verifyLedger(
            response = response,
            ownerId = ownerId,
            vin = vin,
        )
        println("verifyLedger(...) = ${SampleSupport.colorBool(ok)}")
        check(ok) { "verifyLedger returned false" }

        //----------------------------------------------------------------------
        // 3) SgwRegistry.verifyOwnershipLedger — фасад библиотеки
        //----------------------------------------------------------------------
        // Тонкая обёртка над OwnershipRegistryVerifier.verifyLedger.
        // Типичный вызов из Android / iOS / JVM-приложения через единый SgwRegistry.
        SampleSupport.section("3) SgwRegistry.verifyOwnershipLedger")
        val viaFacade = SgwRegistry.verifyOwnershipLedger(
            response = response,
            ownerId = ownerId,
            vin = vin,
        )
        println("SgwRegistry.verifyOwnershipLedger(...) = ${SampleSupport.colorBool(viaFacade)}")
        check(viaFacade) { "facade returned false" }

        //----------------------------------------------------------------------
        // 4) negative — wrong ownerId
        //----------------------------------------------------------------------
        // Тот же валидный ledger, но подставляем чужой UID.
        // Цепочка CMS / p_hash / VIN в порядке; отказ только на сравнении
        // последнего owner_dn с аргументом ownerId → ok=false, reason содержит
        // "ownerId mismatch". check(!ok) фиксирует ожидаемый отказ.
        SampleSupport.section("4) negative — wrong ownerId")
        val wrongOwner = OwnershipRegistryVerifier.tryVerifyLedger(
            response = response,
            ownerId = "aa9f5c8d-246a-429b-926a-22f1fc57d314",
            vin = vin,
        )
        println("ok=${SampleSupport.colorBool(wrongOwner.ok)}, reason=${wrongOwner.reason}")
        check(!wrongOwner.ok)

        //----------------------------------------------------------------------
        // 5) negative — wrong vin
        //----------------------------------------------------------------------
        // Тот же ledger, VIN заведомо не из statements (1000VIN000VIN0001).
        // Отказ уже на ownership_registry[0]: VIN в eContent genesis = AAABBBCCC3
        // → "ownership_registry[0] VIN mismatch". Дальнейшие statements не доходят.
        SampleSupport.section("5) negative — wrong vin")
        val wrongVin = OwnershipRegistryVerifier.tryVerifyLedger(
            response = response,
            ownerId = ownerId,
            vin = "1000VIN000VIN0001",
        )
        println("ok=${SampleSupport.colorBool(wrongVin.ok)}, reason=${wrongVin.reason}")
        check(!wrongVin.ok)

        //----------------------------------------------------------------------
        // Итог
        //----------------------------------------------------------------------
        // 1–3: позитив — валидная цепочка владения принимается API.
        // 4–5: негатив — API отвергает неверный текущий owner и неверный VIN.
        println()
        println("runFromLedger: ${SampleSupport.colorOkLabel()}")
        println("  verifyLedger(OwnershipLedgerResponse, ownerId=\"$ownerId\", vin=\"$vin\")")
        println(
            "  итог: 1–3 ${SampleSupport.colorOkLabel()} (цепочка); " +
                "4–5 ${SampleSupport.colorFailLabel()} как ожидалось (owner / VIN)",
        )
    }

    /**
     * -------------------------------------------------------------------------------------------------
     * CLI `ownership-verify-list`: готовая `List<String>` CMS PEM → [verify].
     *
     * ## Можем вытщить CMS PEM из переданного envelope  List<String>
     *----------------------------------------------------------------------
     * Без парсинга invitation JSON — вход уже в форме аргумента API:
     *
     * val ownershipRegistryCms: List<String> = listOf(cmsPem0, cmsPem1)
     * OwnershipRegistryVerifier.verify(
     *     ownershipRegistryCms = ownershipRegistryCms,
     *     ownerId = "…",
     *     vin = "…",
     * )
     *
     * ownershipRegistryCms упорядоченный список `-----BEGIN CMS-----` … (genesis первым)
     * ownerId ожидаемый UID последнего `owner_dn`
     * vin ожидаемый VIN (единый для всей цепочки)
     */
    fun runFromCmsList(
        ownershipRegistryCms: List<String>,
        ownerId: String,
        vin: String,
    ) {
        //----------------------------------------------------------------------
        // ownership-verify-list: готовая List<String> CMS PEM → verify
        //----------------------------------------------------------------------
        // В отличие от runFromLedger, здесь нет OwnershipLedgerResponse / JSON.
        // Переданный параметр ownershipRegistryCms уже держит упорядоченный массив PEM 
        // и передаёт его напрямую в OwnershipRegistryVerifier.verify.
        //
        // Вход:
        //   ownershipRegistryCms — List<String>, каждый элемент = -----BEGIN CMS----- …
        //                          индекс 0 = genesis (p_hash=""), далее цепочка
        //   ownerId              — ожидаемый UID последнего owner_dn
        //   vin                  — ожидаемый VIN (единый для всей цепочки)
        //
        // Алгоритм verify тот же, что у verifyLedger (внутри ledger просто
        // берётся response.context.ownershipRegistry + response.vin).
        SampleSupport.section("ownership-verify-list — List<String> CMS PEM → verify")

        require(ownershipRegistryCms.isNotEmpty()) { "ownershipRegistryCms is empty" }

        // Лог массива PEM сертификатов — до вызова verify.
        println("массив PEM сертификатов:")
        println("ownershipRegistryCms: List<String> size=${ownershipRegistryCms.size}")
        ownershipRegistryCms.forEachIndexed { i, pem ->
            val head = pem.lineSequence().firstOrNull()?.trim().orEmpty()
            val bytes = pem.encodeToByteArray().size
            println(" если пустой head [$i] $head … ($bytes bytes)")
        }
        println("  ownerId: $ownerId")
        println("  vin:     $vin")
        println()

        //----------------------------------------------------------------------
        // 1) tryVerify — полная проверка с диагностикой
        //----------------------------------------------------------------------
        // OwnershipVerifyResult: ok / reason / statementCount / resolvedVin /
        // resolvedOwnerId. На валидной List (2 CMS из fixture) ожидаем ok=true.
        SampleSupport.section("1) OwnershipRegistryVerifier.tryVerify(List<String>, ownerId, vin)")
        val detailed = OwnershipRegistryVerifier.tryVerify(
            ownershipRegistryCms = ownershipRegistryCms,
            ownerId = ownerId,
            vin = vin,
        )
        println("ok:              ${SampleSupport.colorBool(detailed.ok)}")
        println("statementCount:  ${detailed.statementCount}")
        println("resolvedVin:     ${detailed.vin}")
        println("resolvedOwnerId: ${detailed.ownerId}")
        if (detailed.reason != null) {
            println("reason:          ${detailed.reason}")
        }
        check(detailed.ok) { "OwnershipRegistryVerifier.tryVerify FAILED: ${detailed.reason}" }
        println("→ ${SampleSupport.colorOkLabel()}")

        //----------------------------------------------------------------------
        // 2) verify — тот же алгоритм, результат Boolean
        //----------------------------------------------------------------------
        // Без детального OwnershipVerifyResult: true / false.
        SampleSupport.section("2) OwnershipRegistryVerifier.verify(List<String>, ownerId, vin)")
        val ok = OwnershipRegistryVerifier.verify(
            ownershipRegistryCms = ownershipRegistryCms,
            ownerId = ownerId,
            vin = vin,
        )
        println("OwnershipRegistryVerifier.verify(...) = ${SampleSupport.colorBool(ok)}")
        check(ok) { "OwnershipRegistryVerifier.verify returned false" }

        //----------------------------------------------------------------------
        // 3) SgwRegistry.verifyOwnershipRegistry — фасад
        //----------------------------------------------------------------------
        // Обёртка над OwnershipRegistryVerifier.verify для вызова из приложения
        // через единый SgwRegistry (Android / iOS / JVM).
        SampleSupport.section("3) SgwRegistry.verifyOwnershipRegistry(List<String>, ownerId, vin)")
        val viaFacade = SgwRegistry.verifyOwnershipRegistry(
            ownershipRegistryCms = ownershipRegistryCms,
            ownerId = ownerId,
            vin = vin,
        )
        println("SgwRegistry.verifyOwnershipRegistry(...) = ${SampleSupport.colorBool(viaFacade)}")
        check(viaFacade) { "facade returned false" }

        //----------------------------------------------------------------------
        // 4) negative — wrong ownerId
        //----------------------------------------------------------------------
        // Та же List<String>, чужой UID. Подписи / p_hash / VIN в порядке;
        // отказ только на последнем owner_dn → ok=false, "ownerId mismatch".
        SampleSupport.section("4) Негативный кейс: wrong ownerId")
        val wrongOwner = OwnershipRegistryVerifier.tryVerify(
            ownershipRegistryCms = ownershipRegistryCms,
            ownerId = "aa9f5c8d-246a-429b-926a-22f1fc57d314",
            vin = vin,
        )
        println("ok=${SampleSupport.colorBool(wrongOwner.ok)}, reason=${wrongOwner.reason}")
        check(!wrongOwner.ok)

        //----------------------------------------------------------------------
        // 5) negative — wrong vin
        //----------------------------------------------------------------------
        // Та же List, VIN 1000VIN000VIN0001. Отказ уже на [0]:
        // eContent genesis содержит AAABBBCCC3 → "ownership_registry[0] VIN mismatch".
        SampleSupport.section("5) Негативный кейс: wrong vin")
        val wrongVin = OwnershipRegistryVerifier.tryVerify(
            ownershipRegistryCms = ownershipRegistryCms,
            ownerId = ownerId,
            vin = "1000VIN000VIN0001",
        )
        println("ok=${SampleSupport.colorBool(wrongVin.ok)}, reason=${wrongVin.reason}")
        check(!wrongVin.ok)

        //----------------------------------------------------------------------
        // Итог: Базовая проверка 1–3 принимают валидную List; 4–5 отвергают bad owner / VIN
        //----------------------------------------------------------------------
        println()
        println(
            "Шаги базовой проверки с 1 по 3 прошли ${SampleSupport.colorOkLabel()}; " +
                "итог: 4–5 ${SampleSupport.colorFailLabel()} как ожидалось (owner / VIN)",
        )
        println(
            "  OwnershipRegistryVerifier.verify(ownershipRegistryCms: List<String>(${ownershipRegistryCms.size}), " +
                "ownerId=\"$ownerId\", vin=\"$vin\")",
        )
    }

    /**
     * CLI-хелпер: PEM-файлы на диске в каталоге kotlin/samples/build-registry-example/ownership-stmt-*.pem → готовая [List]<[String]> → [runFromCmsList].
     *
     * Порядок файлов = порядок statements (genesis первым).
     */
    fun runFromPemFiles(
        pemPaths: List<Path>,
        ownerId: String,
        vin: String,
    ) {
        //----------------------------------------------------------------------
        // CLI-хелпер: PEM-файлы на диске → готовая List<String> → runFromCmsList
        //----------------------------------------------------------------------
        // Точка входа для команды ownership-verify-list:
        //   args = [ownerId, vin, cms0.pem, cms1.pem, …]
        //
        // Здесь только сборка аргумента API #1 (List<String>). Сама проверка —
        // в runFromCmsList / OwnershipRegistryVerifier.verify.
        //
        // Порядок путей = порядок statements в цепочке:
        //   [0] genesis (p_hash=""), [1] следующая передача, …
        // Перепутанный порядок → FAIL на связке p_hash.
        SampleSupport.section("ownership-verify-list — PEM files → List<String>")
        require(pemPaths.isNotEmpty()) { "из готового List<String> CMS PEM files" }

        // Читаем каждый PEM как строку (включая -----BEGIN/END CMS-----).
        // requireExists — явная ошибка, если файл отсутствует (неверный путь /
        // не созданы kotlin-out/ownership-stmt-*.pem).
        val ownershipRegistryCms: List<String> = pemPaths.map { path ->
            val p = SampleSupport.requireExists(path, "CMS PEM")
            Files.readString(p)
        }

        // Лог источников — удобно сверить, какие файлы попали в List и в каком порядке.
        println("собрана List<String> из ${pemPaths.size} PEM:")
        pemPaths.forEachIndexed { i, p -> println("  [$i] $p") }
        println()

        // Дальше — те же кейсы 1–5, что у готовой List (tryVerify / verify / фасад / негативы).
        runFromCmsList(
            ownershipRegistryCms = ownershipRegistryCms,
            ownerId = ownerId,
            vin = vin,
        )
    }
}
