/**
 * Точка входа для JVM-примеров всех публичных API библиотеки sgw-registry.
 *
 * ## Запуск из Gradle
 *
 * Рабочий каталог — **корень монорепозитория** (родитель `kotlin/`), см. [build.gradle.kts].
 * Пути в аргументах — относительные от корня репо или абсолютные.
 *
 * ```bash
 * cd kotlin
 *
 * # Полный набор аргументов (рекомендуется для кастомных путей/SKID):
 * ./gradlew :samples:registry-examples:run --args="remove-cert in.p12 config.json out.p12 019c9eff..."
 *
 * # Сокращённые задачи — в main попадает только имя команды, остальное по умолчанию:
 * ./gradlew :samples:registry-examples:runRemove-cert
 * ./gradlew :samples:registry-examples:runParse
 * ```
 *
 * Задачи `runParse`, `runRemove-cert` и т.д. регистрируются в [build.gradle.kts] с `args(cmd)` —
 * без дополнительных `--args` используются пути по умолчанию из этого файла.
 *
 * ## Формат argv
 *
 * | Индекс | Содержимое |
 * |--------|------------|
 * | `args[0]` | Имя команды: `parse`, `verify`, `analyze`, `build`, `config`, `add-cert`, `remove-cert`, `update-registry`, `cloud-config`, `cloud-config-trust`, `cloud-config-from-context`, `sign-tbox`, `sign-cloud-config`, `gen-ownership-csr`, `ownership-verify`, `ownership-verify-list`, `empty-owner`, `empty-owner-unsigned`, `all` |
 * | `args[1…]` | Позиционные аргументы команды (см. ветки [main] и [printUsage]) |
 *
 * Разрешение путей: [argPath] → [SampleSupport.resolveInputPath] (относительные от [SampleSupport.repoRoot]).
 *
 * ## Файлы по умолчанию
 *
 * - `demo-original-container.p12` — демо-реестр PKCS#12 (~4 safeBags: driver, passenger, IVI, driver-mobile)
 * - `config.json` — VIN, VER, signer, список `safeBags` с путями к PEM в `certs/`
 * - `kotlin-out/…` — артефакты примеров (создаются при записи)
 *
 * См. также [printUsage] и раздел в README: «Не путать remove-cert и update-registry».
 */
package com.atom.sgwregistry.examples

import com.atom.sgwregistry.ownership.OwnershipLedgerJson
import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    if (args.isEmpty() || args[0] in setOf("-h", "--help")) {
        printUsage()
        return
    }

    val command = args[0].lowercase()
    when (command) {
        // ── parse [file.p12] ─────────────────────────────────────────────────
        // args[1] → Path к .p12 (default: demo-original-container.p12)
        // → ParseExample.run(p12Path): читает байты, RegistryParser.parse, печатает структуру контейнера
        "parse" -> {
            val p12 = argPath(args, 1, SampleSupport.defaultP12())
            ParseExample.run(SampleSupport.requireExists(p12, "P12"))
        }

        // ── verify [file.p12] ─────────────────────────────────────────────────
        // args[1] → Path к .p12 (default: demo-original-container.p12)
        // → VerifyExample.run(p12Path): SignatureVerifier.verifyRegistry / verifyContainer / tryVerifyRegistry
        "verify" -> {
            val p12 = argPath(args, 1, SampleSupport.defaultP12())
            VerifyExample.run(SampleSupport.requireExists(p12, "P12"))
        }

        // ── analyze [file.p12] [out-dir] ──────────────────────────────────────
        // args[1] → Path к .p12 (default: demo-original-container.p12)
        // args[2] → каталог экспорта (default: kotlin-out/examples-export)
        // → AnalyzeExample.run(p12Path, outDir): RegistryAnalyzer.toText/toJson/toPem, export*
        "analyze" -> {
            val p12 = argPath(args, 1, SampleSupport.defaultP12())
            val out = argPath(args, 2, SampleSupport.repoRoot.resolve("kotlin-out/examples-export"))
            AnalyzeExample.run(SampleSupport.requireExists(p12, "P12"), out)
        }

        // ── build [config.json] [out.p12] ───────────────────────────────────
        // args[1] → config.json (default: config.json в корне репо)
        // args[2] → выходной .p12 (default: kotlin-out/built-from-config.p12)
        // → BuildExample.run(configPath, outputPath): ConfigLoader → BuildConfig → RegistryBuilder.buildRegistry
        "build" -> {
            val config = argPath(args, 1, SampleSupport.defaultConfig())
            val output = argPath(args, 2, SampleSupport.repoRoot.resolve("kotlin-out/built-from-config.p12"))
            Files.createDirectories(output.parent)
            BuildExample.run(SampleSupport.requireExists(config, "config.json"), output)
        }

        // ── empty-owner [owner-empty-config.json] [out.p12] [vin] [uid] [verTs] [verN]
        // → EmptyOwnerP12Example: пустой SafeContents + произвольные VIN/UID/VER
        "empty-owner" -> {
            val config = argPath(args, 1, SampleSupport.repoRoot.resolve("owner-empty-config.json"))
            val output = argPath(args, 2, SampleSupport.repoRoot.resolve("kotlin-out/owner.p12"))
            val vin = if (args.size > 3) args[3] else null
            val uid = if (args.size > 4) args[4] else null
            val verTs = if (args.size > 5) args[5] else null
            val verN = if (args.size > 6) args[6].toIntOrNull() else null
            Files.createDirectories(output.parent)
            EmptyOwnerP12Example.run(
                SampleSupport.requireExists(config, "owner-empty-config.json"),
                output,
                vinOverride = vin,
                uidOverride = uid,
                verTimestampOverride = verTs,
                verVersionOverride = verN,
            )
        }

        // ── empty-owner-unsigned [outPrefix] [vin] [uid] [verTs] [verN]
        // → EmptyOwnerUnsignedExample: SafeContents + header draft, без CMS / signer
        "empty-owner-unsigned" -> {
            val outPrefix = argPath(args, 1, SampleSupport.repoRoot.resolve("kotlin-out/owner-unsigned"))
            val vin = if (args.size > 2) args[2] else "DRAFT-VIN"
            val uid = if (args.size > 3) args[3] else "CN=Draft Owner"
            val verTs = if (args.size > 4) args[4] else "2026-01-01T00:00:00Z"
            val verN = if (args.size > 5) args[5].toIntOrNull() ?: 1 else 1
            Files.createDirectories(outPrefix.parent)
            EmptyOwnerUnsignedExample.run(
                outPrefix = outPrefix,
                vin = vin,
                uid = uid,
                verTimestamp = verTs,
                verVersion = verN,
            )
        }

        // ── add-cert [file.p12] [config.json] [out.p12] [bagIndex] ────────────
        // args[1] → исходный .p12 (default: demo-original-container.p12)
        // args[2] → config.json — signer + safeBags; PEM резолвятся относительно каталога config
        // args[3] → выходной .p12 с добавленным сертификатом (default: kotlin-out/registry-with-added-cert.p12)
        // args[4] → индекс safeBag в config.safeBags (default: 0); если cert уже в реестре — ищется следующий
        // → AddCertificateExample.run(p12, config, output, bagIndex):
        //    первый cert из config, которого нет в реестре → RegistryBuilder.addCertificateAndResign, VER Vn→V{n+1}
        "add-cert" -> {
            val p12 = argPath(args, 1, SampleSupport.defaultP12())
            val config = argPath(args, 2, SampleSupport.defaultConfig())
            val output = argPath(args, 3, SampleSupport.repoRoot.resolve("kotlin-out/registry-with-added-cert.p12"))
            val bagIndex = if (args.size > 4) args[4].toIntOrNull() ?: 0 else 0
            Files.createDirectories(output.parent)
            AddCertificateExample.run(
                SampleSupport.requireExists(p12, "P12"),
                SampleSupport.requireExists(config, "config.json"),
                output,
                bagIndex,
            )
        }

        // ── remove-cert [file.p12] [config.json] [out.p12] [skidHex] ────────
        // args[1] → .p12 для удаления (default: kotlin-out/registry-with-added-cert.p12 — результат add-cert)
        // args[2] → config.json — нужен для signerCertDer/signerKey при переподписи
        // args[3] → выходной .p12 (default: kotlin-out/registry-after-remove.p12)
        // args[4] → SKID в hex без дефисов (optional); пример passenger: 019c9eff384f727db0ad9743d5e59418
        //           если не задан — первый safeBag из config, SKID которого уже есть в реестре (обычно driver:
        //           019c9eff384f76abaf6163d38b3f384b, certs/driver.pem)
        // → RemoveCertificateExample.run(p12, config, output, subjectKeyIdHex):
        //    RegistryBuilder.removeCertificateBySkidAndResign, VER Vn→V{n+1}
        //
        // Не путать с update-registry: здесь удаляется явно указанный (или auto-первый из config) bag.
        // update-registry удаляет только сертификат, добавленный на шаге add внутри того же сценария.
        "remove-cert" -> {
            val p12 = argPath(args, 1, SampleSupport.repoRoot.resolve("kotlin-out/registry-with-added-cert.p12"))
            val config = argPath(args, 2, SampleSupport.defaultConfig())
            val output = argPath(args, 3, SampleSupport.repoRoot.resolve("kotlin-out/registry-after-remove.p12"))
            val skidHex = if (args.size > 4) args[4] else null
            Files.createDirectories(output.parent)
            RemoveCertificateExample.run(
                SampleSupport.requireExists(p12, "P12"),
                SampleSupport.requireExists(config, "config.json"),
                output,
                skidHex,
            )
        }

        // ── update-registry [in.p12] [config.json] [added.p12] [final.p12] ──
        // args[1] → исходный .p12 (default: demo-original-container.p12)
        // args[2] → config.json
        // args[3] → промежуточный файл после add (default: kotlin-out/registry-with-added-cert.p12)
        // args[4] → финальный файл после remove (default: kotlin-out/registry-update-final.p12)
        // → UpdateRegistryExample.run(p12, config, addedPath, finalPath):
        //    1) add — cert из config, отсутствующий в реестре
        //    2) verify
        //    3) remove — тот же SKID, что только что добавили (round-trip)
        //    4) SgwRegistry add/remove для демо фасада
        "update-registry" -> {
            val p12 = argPath(args, 1, SampleSupport.defaultP12())
            val config = argPath(args, 2, SampleSupport.defaultConfig())
            val added = argPath(args, 3, SampleSupport.repoRoot.resolve("kotlin-out/registry-with-added-cert.p12"))
            val final = argPath(args, 4, SampleSupport.repoRoot.resolve("kotlin-out/registry-update-final.p12"))
            Files.createDirectories(added.parent)
            UpdateRegistryExample.run(
                SampleSupport.requireExists(p12, "P12"),
                SampleSupport.requireExists(config, "config.json"),
                added,
                final,
            )
        }

        // ── config [config.json] ──────────────────────────────────────────────
        // args[1] → config.json (default: config.json)
        // → ConfigExample.run(configPath): ConfigLoader.readConfig/toBuildConfig, PemUtils.getSubjectKeyId
        "config" -> {
            val config = argPath(args, 1, SampleSupport.defaultConfig())
            ConfigExample.run(SampleSupport.requireExists(config, "config.json"))
        }

        // ── cloud-config [mob-dev-cloud_config.json] [config.json] [out.json] ─
        // → CloudConfigExample: parse/verify cloud_config_pem; optional resign with config signer
        "cloud-config" -> {
            val mobDev = argPath(args, 1, SampleSupport.repoRoot.resolve("mob-dev-cloud_config.json"))
            val config = if (args.size > 2) argPath(args, 2, SampleSupport.defaultConfig()) else null
            val output = if (args.size > 3) {
                argPath(args, 3, SampleSupport.repoRoot.resolve("kotlin-out/mob-dev-cloud_config-resigned.json"))
            } else {
                SampleSupport.repoRoot.resolve("kotlin-out/mob-dev-cloud_config-resigned.json")
            }
            CloudConfigExample.run(
                SampleSupport.requireExists(mobDev, "mob-dev-cloud_config.json"),
                config?.takeIf { Files.exists(it) },
                output,
            )
        }

        // ── cloud-config-trust [mob.json] [vin] [owner_id] [ownership-ca.pem] ─
        // → CloudConfigTrustExample: identity → PKIX(root_cas) → CMS signature
        "cloud-config-trust" -> {
            val mobDev = argPath(args, 1, SampleSupport.repoRoot.resolve("mob-dev-cloud_config.json"))
            val expectedVin = if (args.size > 2) args[2] else "79079999999"
            val expectedOwnerId = if (args.size > 3) {
                args[3]
            } else {
                "d231b684-82b4-4fdc-83dd-fc9a1861c293"
            }
            val intermediate = if (args.size > 4) {
                SampleSupport.requireExists(argPath(args, 4, SampleSupport.repoRoot.resolve(args[4])), "intermediate CA")
            } else {
                null // CloudConfigTrustExample auto-discovers certs/ATOM Ownership CA.pem
            }
            CloudConfigTrustExample.run(
                SampleSupport.requireExists(mobDev, "mob-dev-cloud_config.json"),
                expectedVin,
                expectedOwnerId,
                intermediate,
            )
        }

        // ── cloud-config-from-context [resp-context.json] [config.json] [v] [out.json]
        // → CloudConfigFromContextExample: invitation draft → TBOX JSON (+ envelope)
        "cloud-config-from-context" -> {
            val resp = argPath(args, 1, SampleSupport.repoRoot.resolve("resp-context.json"))
            val config = argPath(args, 2, SampleSupport.defaultConfig())
            val payloadVersion = if (args.size > 3) args[3].toIntOrNull() else 5
            val output = if (args.size > 4) {
                argPath(args, 4, SampleSupport.repoRoot.resolve("kotlin-out/cloud-config-tbox.json"))
            } else {
                SampleSupport.repoRoot.resolve("kotlin-out/cloud-config-tbox.json")
            }
            Files.createDirectories(output.parent)
            CloudConfigFromContextExample.run(
                SampleSupport.requireExists(resp, "resp-context.json"),
                SampleSupport.requireExists(config, "config.json"),
                output,
                payloadVersion,
            )
        }

        // ── sign-tbox [tbox.json] [config.json] [outPrefix] [vin] [fqdnId] [owner_id]
        // → SignTboxCloudConfigExample: TBOX → cloud_config_pem; FQDN=hashB(vin)-fqdnId.domain
        "sign-tbox" -> {
            val tbox = argPath(args, 1, SampleSupport.repoRoot.resolve("kotlin-out/cloud-config-tbox.json"))
            val config = argPath(args, 2, SampleSupport.defaultConfig())
            val outPrefix = argPath(args, 3, SampleSupport.repoRoot.resolve("kotlin-out/cloud-config-tbox-signed"))
            val vin = if (args.size > 4) args[4] else ""
            val fqdnId = if (args.size > 5) args[5] else ""
            val ownerId = if (args.size > 6) args[6] else ""
            Files.createDirectories(outPrefix.parent)
            SignTboxCloudConfigExample.run(
                SampleSupport.requireExists(tbox, "tbox JSON"),
                SampleSupport.requireExists(config, "config.json"),
                outPrefix,
                vin = vin,
                fqdnIdentityId = fqdnId,
                ownerId = ownerId,
            )
        }

        // ── sign-cloud-config [good.json] [resp-context.json] [config.json] [outPrefix] [bad.json]
        // → SignCloudConfigFixtureExample: OK fixture binding + resign + from-context + negative a1
        "sign-cloud-config" -> {
            val good = argPath(args, 1, SampleSupport.repoRoot.resolve("cloud-config.json"))
            val resp = argPath(args, 2, SampleSupport.repoRoot.resolve("resp-context.json"))
            val config = argPath(args, 3, SampleSupport.defaultConfig())
            val outPrefix = argPath(
                args,
                4,
                SampleSupport.repoRoot.resolve("kotlin-out/cloud-config-signed-fixture"),
            )
            val badDefault = SampleSupport.repoRoot.resolve("a1-cloud-config-signed.json")
            val bad = when {
                args.size > 5 -> argPath(args, 5, badDefault)
                Files.isRegularFile(badDefault) -> badDefault
                else -> null
            }
            Files.createDirectories(outPrefix.parent)
            SignCloudConfigFixtureExample.run(
                goodMobDevPath = SampleSupport.requireExists(good, "cloud-config.json / mob-dev"),
                respContextPath = SampleSupport.requireExists(resp, "resp-context.json"),
                configPath = SampleSupport.requireExists(config, "config.json"),
                outputPrefix = outPrefix,
                badMobDevPath = bad,
            )
        }

        // ── gen-ownership-csr [ownerId] [key.pem] [out.csr.pem]
        // → OwnershipCsr: PKCS#10 + EKU Email Protection + SAN atombus:/user/{ownerId}
        "gen-ownership-csr" -> {
            val ownerId = if (args.size > 1) args[1] else "d231b684-82b4-4fdc-83dd-fc9a1861c293"
            val key = argPath(args, 2, SampleSupport.repoRoot.resolve("certs/signer-key.pem"))
            val out = argPath(args, 3, SampleSupport.repoRoot.resolve("kotlin-out/ownership.csr.pem"))
            GenOwnershipCsrExample.run(
                ownerId = ownerId,
                ecPrivateKeyPath = key,
                outputCsrPemPath = out,
            )
        }

        // ── ownership-verify [ownership-resp.json] [ownerId] [vin?]
        // → OwnershipLedgerResponse → verifyLedger(response, ownerId, vin=response.vin)
        "ownership-verify" -> {
            val ledger = argPath(args, 1, SampleSupport.repoRoot.resolve("ownership-resp.json"))
            val ownerId = if (args.size > 2) args[2] else OwnershipVerifyExample.FIXTURE_OWNER_ID
            // vin optional: если не задан — берётся response.vin из JSON
            val vin = if (args.size > 3) args[3] else null
            OwnershipVerifyExample.run(
                ledgerJsonPath = ledger,
                ownerId = ownerId,
                vin = vin,
            )
        }

        // ── ownership-verify-list [ownerId] [vin] [cms0.pem] [cms1.pem ...]
        // → только готовая List<String> CMS PEM (без JSON)
        "ownership-verify-list" -> {
            val ownerId = if (args.size > 1) args[1] else OwnershipVerifyExample.FIXTURE_OWNER_ID
            val vin = if (args.size > 2) args[2] else OwnershipVerifyExample.FIXTURE_VIN
            val pemArgs = if (args.size > 3) {
                args.drop(3).map { SampleSupport.resolveInputPath(it) }
            } else {
                // defaults: export из ownership-resp.json при отсутствии файлов
                ensureFixtureOwnershipPemFiles()
            }
            OwnershipVerifyExample.runFromPemFiles(
                pemPaths = pemArgs,
                ownerId = ownerId,
                vin = vin,
            )
        }

        // ── all [file.p12] ────────────────────────────────────────────────────
        // args[1] → .p12 для parse/verify/analyze/update (default: demo-original-container.p12)
        // → runAll: parse → verify → analyze → (если есть config) config → build → verify → update-registry
        "all" -> runAll(args)

        else -> {
            System.err.println("Unknown command: $command")
            printUsage()
            kotlin.system.exitProcess(1)
        }
    }
}

/**
 * Последовательный запуск всех примеров.
 *
 * Использует [args] только для `args[1]` (путь к .p12); config и kotlin-out — фиксированные от [SampleSupport.repoRoot].
 * Если `config.json` отсутствует — build/config/update-registry пропускаются.
 */
private fun runAll(args: Array<String>) {
    val p12 = argPath(args, 1, SampleSupport.defaultP12())
    val config = SampleSupport.defaultConfig()
    val built = SampleSupport.repoRoot.resolve("kotlin-out/built-from-config.p12")
    val export = SampleSupport.repoRoot.resolve("kotlin-out/examples-export")

    ParseExample.run(SampleSupport.requireExists(p12, "P12"))
    VerifyExample.run(p12)
    AnalyzeExample.run(p12, export)

    if (Files.exists(config)) {
        Files.createDirectories(built.parent)
        ConfigExample.run(config)
        BuildExample.run(config, built)
        VerifyExample.run(built)
        val added = SampleSupport.repoRoot.resolve("kotlin-out/registry-with-added-cert.p12")
        val final = SampleSupport.repoRoot.resolve("kotlin-out/registry-update-final.p12")
        UpdateRegistryExample.run(p12, config, added, final)
    } else {
        println()
        println("=== build / config skipped (no ${config.fileName}) ===")
    }
}

/**
 * Позиционный аргумент CLI → [Path].
 *
 * @param index индекс в [args] (1 = первый аргумент после имени команды)
 * @param default если `index >= args.size`, возвращается этот путь без чтения argv
 */
private fun argPath(args: Array<String>, index: Int, default: Path): Path =
    if (index < args.size) SampleSupport.resolveInputPath(args[index]) else default

/**
 * Пишет CMS из `ownership-resp.json` в `kotlin-out/ownership-stmt-*.pem`
 * (для CLI `ownership-verify-list` без явных путей).
 */
private fun ensureFixtureOwnershipPemFiles(): List<Path> {
    val outDir = SampleSupport.repoRoot.resolve("kotlin-out")
    Files.createDirectories(outDir)
    val defaults = listOf(
        outDir.resolve("ownership-stmt-0.pem"),
        outDir.resolve("ownership-stmt-1.pem"),
    )
    if (defaults.all { Files.isRegularFile(it) }) return defaults

    val ledgerPath = SampleSupport.requireExists(
        SampleSupport.repoRoot.resolve("ownership-resp.json"),
        "ownership-resp.json",
    )
    val cms = OwnershipLedgerJson.parse(SampleSupport.readBytes(ledgerPath))
        .context.ownershipRegistry
    check(cms.isNotEmpty()) { "ownership_registry empty in ownership-resp.json" }
    return cms.mapIndexed { i, pem ->
        val p = outDir.resolve("ownership-stmt-$i.pem")
        Files.writeString(p, pem)
        p
    }
}

private fun printUsage() {
    println(
        """
        |Usage: registry-examples <command> [args...]
        |
        |Gradle:
        |  ./gradlew :samples:registry-examples:run --args="<command> [args...]"
        |  ./gradlew :samples:registry-examples:runRemove-cert
        |  ./gradlew :samples:registry-examples:runRemove-cert --args="in.p12 config.json out.p12 [skidHex]"
        |
        |Commands (API coverage):
        |  parse  [file.p12]              RegistryParser.parse
        |  verify [file.p12]              SignatureVerifier.*
        |  analyze [file.p12] [out-dir]   RegistryAnalyzer.*
        |  build  [config.json] [out.p12] RegistryBuilder.* + ConfigLoader.toBuildConfig
        |  empty-owner [owner-empty-config.json] [out.p12] [vin] [uid] [verTs] [verN]
        |                                 пустой SafeContents + VIN/UID/VER в заголовке (CMS)
        |  empty-owner-unsigned [outPrefix] [vin] [uid] [verTs] [verN]
        |                                 без подписи: SafeContents.der + header.json
        |  add-cert [file.p12] [config.json] [out.p12] [bagIndex]
        |                                 RegistryBuilder.addCertificateAndResign
        |  remove-cert [file.p12] [config.json] [out.p12] [skidHex]
        |                                 RegistryBuilder.removeCertificateBySkidAndResign
        |                                 skidHex optional; default SKID = first config bag in registry (driver)
        |  update-registry [in.p12] [config.json] [added.p12] [final.p12]
        |                                 add + remove (same SKID as added) + SgwRegistry
        |  add-cert / remove-cert / update-registry — VER auto Vn→V{n+1} on .p12 change
        |  config [config.json]          ConfigLoader.* + PemUtils (verTimestamp, verVersion → VER)
        |  cloud-config [mob-dev.json] [config.json] [out.json]
        |                                 CloudConfigCms parse/verify/resign cloud_config_pem
        |  cloud-config-trust [mob.json] [vin] [owner_id] [ownership-ca.pem]
        |                                 identity → PKIX(root_cas) → CMS signature
        |  cloud-config-from-context [resp-context.json] [config.json] [v] [out.json]
        |                                 invitation → TBOX cloudBroker JSON (+ envelope)
        |  sign-tbox [tbox.json] [config.json] [outPrefix] [vin] [fqdnId] [owner_id]
        |                                 TBOX JSON → cloud_config_pem; FQDN=hashB(vin)-fqdnId.…
        |  sign-cloud-config [good.json] [resp-context.json] [config.json] [outPrefix] [bad.json]
        |                                 fixtures: OK binding+resign, from-context, negative a1
        |  gen-ownership-csr [ownerId] [key.pem] [out.csr.pem]
        |                                 Ownership PKCS#10 CSR (EKU Email Protection + SAN)
        |  ownership-verify [ownership-resp.json] [ownerId] [vin?]
        |                                 OwnershipLedgerResponse → verifyLedger (vin из JSON)
        |  ownership-verify-list [ownerId] [vin] [cms0.pem] [cms1.pem…]
        |                                 только готовая List<String> CMS PEM (без JSON)
        |  all    [file.p12]              all of the above
        |
        |Defaults (cwd = repo root via Gradle workingDir):
        |  p12    demo-original-container.p12
        |  config config.json
        |  export kotlin-out/examples-export
        |  mob-dev JSON / vin / owner_id — из fixture mob-dev-cloud_config.json
        |  sign-cloud-config → cloud-config.json + resp-context.json → kotlin-out/cloud-config-signed-fixture.*
        |  gen-ownership-csr → certs/signer-key.pem → kotlin-out/ownership.csr.pem
        |  ownership-verify → ownership-resp.json
        |                     ownerId=7f9fc821-a09e-4f96-badc-643daca070c6
        |                     vin=response.vin (из JSON)
        |  ownership-verify-list → kotlin-out/ownership-stmt-0.pem + ownership-stmt-1.pem
        |  remove input  kotlin-out/registry-with-added-cert.p12
        |  remove output kotlin-out/registry-after-remove.p12
        """.trimMargin(),
    )
}
