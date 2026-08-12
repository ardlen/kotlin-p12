# Kotlin — библиотека SgwRegistry (Kotlin Multiplatform)

Нативная реализация **ATOM-PKCS12-REGISTRY** для **JVM**, **Android** и **iOS** (аналог SgwRegistry для .NET и Go `api`).

Версия: **2.6.0**. Полный справочник публичного API: [kotlin/API.md](kotlin/API.md).  
Подробный README модуля: [kotlin/README.md](kotlin/README.md).

## Оглавление

1. [Платформы](#платформы) — jvm / android / ios
2. [Kotlin Multiplatform](#kotlin-multiplatform--как-подключать-и-использовать) — архитектура, Maven, commonMain
3. [Структура](#структура) · [Требования](#требования)
4. [Сборка библиотеки](#сборка-библиотеки-для-других-проектов) — публикация и подключение
5. [Реестр PKCS#12](#реестр-pkcs12) — [VER](#ver-при-изменении-реестра-p12) · [add](#добавить-сертификат-в-существующий-реестр) · [remove](#удалить-сертификат-по-skid)
6. [Cloud configuration](#cloud-configuration-mob-dev) — CMS · invitation → TBOX · CES FQDN · [Ownership CSR](#ownership-csr-pkcs10) · [Ownership ledger](#ownership-ledger-ownership-verify)
7. [Сборка и тесты](#сборка-и-тесты)
8. [Запуск примеров](#запуск-примеров) — `registry-examples` CLI
   - [Быстрый старт](#быстрый-старт) · [`from-context`](#invitation--tbox--fqdn-cloud-config-from-context) · [`sign-tbox`](#подпись-tbox-sign-tbox) · [`gen-ownership-csr`](#ownership-csr-gen-ownership-csr) · [`ownership-verify`](#ownership-ledger-ownership-verify) · [`empty-owner`](#empty-ownerp12-empty-owner--empty-owner-unsigned)
9. [API](#api) — краткая сводка → [API.md](kotlin/API.md)
10. [Зависимости](#зависимости) · [Статус](#статус)

---

## Платформы

| Target | Криптография | Доступный API |
|--------|--------------|---------------|
| **jvm** | JCA (`java.security`) | **commonMain** + `ConfigLoader`, `PemUtils`, `RegistryAnalyzerJvm`, JVM-обёртки (`buildConfigFromJvm`, …) |
| **android** | JCA (Android) | **commonMain** — parse/build/verify/analyze; загрузка PEM/конфига — средствами приложения |
| **iosArm64 / iosSimulatorArm64** | Security.framework (`kSecKeyAlgorithmECDSASignatureDigestX962SHA256`) | **commonMain** — parse/build/verify/analyze; NONEwithECDSA над готовым SHA-256 digest |

Ядро (parse, build, verify, analyze, **CloudConfigCms** / **CloudConfigFromContext** / **CloudBrokerFqdn**, **OwnershipCsr**, **OwnershipRegistryVerifier**) — в **commonMain**.  
`ConfigLoader`, `PemUtils`, `RegistryAnalyzerJvm` — только **jvmMain** (desktop/CLI). На Android и iOS используйте **`BuildConfigFactory`** + `PemEncoding` + `PlatformCrypto`. Cloud config: раздел [Cloud configuration (mob-dev)](#cloud-configuration-mob-dev).

## Kotlin Multiplatform — как подключать и использовать

### Архитектура

```
commonMain/          ← стабильный API: SgwRegistry, RegistryParser, RegistryBuilder,
                       SignatureVerifier, RegistryAnalyzer,
                       CloudConfigCms / CloudConfigFromContext / CloudBrokerFqdn,
                       OwnershipCsr, OwnershipRegistryVerifier,
                       PemEncoding, BuildConfig, SigningKey
    │
    ├── jvmMain/     ← ConfigLoader, PemUtils, RegistryAnalyzerJvm, JvmCompat
    ├── androidMain/ ← PlatformCrypto (JCA)
    └── iosMain/     ← PlatformCrypto (Security.framework), readMainBundleResource
```

| Класс / пакет | commonMain | JVM | Android | iOS |
|---------------|:----------:|:---:|:-------:|:---:|
| `RegistryParser`, `RegistryBuilder`, `SignatureVerifier`, `RegistryAnalyzer` | ✓ | ✓ | ✓ | ✓ |
| `SgwRegistry`, `PemEncoding`, `VerAttribute`, `BuildConfig`, `SigningKey` | ✓ | ✓ | ✓ | ✓ |
| `BuildConfigFactory`, `RegistryConfig` | ✓ | ✓ | ✓ | ✓ |
| `CloudConfigCms`, `CloudConfigFromContext`, `CloudBrokerFqdn` | ✓ | ✓ | ✓ | ✓ |
| `OwnershipCsr`, `EcSpkiEncoding` | ✓ | ✓ | ✓ | ✓ |
| `OwnershipRegistryVerifier`, `OwnershipLedgerJson` | ✓ | ✓ | ✓ | ✓ |
| `ConfigLoader`, `PemUtils`, `RegistryAnalyzerJvm` | — | ✓ | — | — |
| `buildConfigFromJvm`, `addCertificateRequestFromJvm`, … | — | ✓ | — | — |

**Модели запросов** (`BuildConfig`, `AddCertificateRequest`, …) на всех платформах используют `signerCertDer: ByteArray` и `signingKey: SigningKey`, а не `X509Certificate` / `PrivateKey`.

> **`BuildConfig`** — доменная модель в `commonMain`, **не** Android Gradle `BuildConfig`.  
> Создаётся через **`BuildConfigFactory`** (mobile) или **`ConfigLoader`** (JVM).  
> Подробнее: [API.md — BuildConfig](kotlin/API.md#buildconfig), [API.md — BuildConfigFactory](kotlin/API.md#config--buildconfigfactory-commonmain-и-configloader-jvm).

### Публикация Maven (KMP)

```bash
cd kotlin
./gradlew :sgw-registry:publishLibrary
```

| Maven-координата | Содержимое |
|------------------|------------|
| `com.atom:sgw-registry:2.6.0` | корневой `.module` + Kotlin metadata (common API) |
| `com.atom:sgw-registry-jvm:2.6.0` | JVM JAR |
| `com.atom:sgw-registry-android:2.6.0` | AAR (нужен Android SDK при публикации) |
| `com.atom:sgw-registry-iosarm64:2.6.0` | `.klib` (устройство) |
| `com.atom:sgw-registry-iossimulatorarm64:2.6.0` | `.klib` (симулятор) |

Репозиторий для примеров в этом проекте: **`kotlin/dist/maven/`** (см. `settings.gradle.kts` — без `mavenLocal()`).  
Внешние потребители могут также использовать `mavenLocal()` после `publishToMavenLocal`.

Плоские JAR в `kotlin/dist/sgw-registry-2.6.0.jar` — **только JVM** (удобство для desktop); полный KMP-набор — в `kotlin/dist/maven/`.

После публикации запустите [интеграционные примеры](#интеграционные-примеры-с-опубликованным-kmp-пакетом) (`samples/`) для проверки артефакта.

### Подключение в KMP-проекте

```kotlin
// build.gradle.kts потребителя
plugins {
    kotlin("multiplatform")
    id("com.android.library") // или application
}

kotlin {
    androidTarget()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            implementation("com.atom:sgw-registry:2.6.0")
        }
    }
}

repositories {
    mavenLocal()
    // или: maven { url = uri("/path/to/kotlin/dist/maven") }
}
```

Gradle автоматически выберет variant: JVM / Android / iOS.

### Пример commonMain (Android + iOS + JVM)

Работает на **всех** таргетах — только `ByteArray`, без `java.nio.file` и `ConfigLoader`:

```kotlin
import com.atom.sgwregistry.analyzer.RegistryAnalyzer
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.model.BuildConfig
import com.atom.sgwregistry.model.SafeBagInput
import com.atom.sgwregistry.model.SignerAttrs
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.verifier.SignatureVerifier
import kotlinx.datetime.Instant

// p12Der, signerCertPem, signerKeyPem, roleCertPem — ByteArray из assets / bundle / сети
fun parseAndVerify(p12Der: ByteArray) {
    val container = RegistryParser.parse(p12Der)
    SignatureVerifier.verifyRegistry(p12Der)
    println(RegistryAnalyzer.toTextDetailed(container))
}

fun buildRegistryFromPem(
    signerCertPem: ByteArray,
    signerKeyPem: ByteArray,
    roleCertPem: ByteArray,
    vin: String,
    uid: String,
    verTimestamp: Instant,
    verVersion: Int,
): ByteArray {
    val signerCertDer = PemEncoding.decodePemOrDer(signerCertPem)
    val signerKey = PlatformCrypto.parseEcPrivateKey(signerKeyPem)
    val cfg = BuildConfig(
        signerCertDer = signerCertDer,
        signerKey = signerKey,
        vin = vin,
        verTimestamp = verTimestamp,
        verVersion = verVersion,
        uid = uid,
        safeBags = listOf(
            SafeBagInput(
                certDer = PemEncoding.decodePemOrDer(roleCertPem),
                roleName = "driver",
                roleNotBefore = Instant.parse("2024-01-01T00:00:00Z"),
                roleNotAfter = Instant.parse("2030-01-01T00:00:00Z"),
            ),
        ),
    )
    val built = RegistryBuilder.buildRegistry(cfg)
    SignatureVerifier.verifyRegistry(built)
    return built
}

// SKID (hex) — в commonMain через PemEncoding, не PemUtils
val skid = PemEncoding.decodeSkidHex("019c9eff384f76abaf6163d38b3f384b")
```

### Сборка реестра на мобильных (без ConfigLoader)

На Android/iOS нет `ConfigLoader` и `java.nio.file`. **`BuildConfigFactory`** уже реализован в **commonMain** — на платформе нужно только отдать `ByteArray` (JSON, PEM) и функцию `loadPem`.

```
config.json / API  →  BuildConfigFactory.parseConfig + toBuildConfig(loadPem)
                              │
                              ▼
                        BuildConfig  →  RegistryBuilder.buildRegistry / add / remove
```

| Вариант | API | Источник данных |
|---------|-----|-----------------|
| 1. JSON + пути | `toBuildConfig(cfg, loadPem)` | assets / bundle / Documents |
| 2. Inline PEM | `toBuildConfigFromInlinePem(cfg)` | ответ backend |
| 3. Без JSON | `toBuildConfig(vin, uid, …, safeBags)` | байты в памяти |
| 4. Вручную | `BuildConfig(...)` | `PemEncoding` + `PlatformCrypto` |

**Структура ресурсов** (зеркало `config.json` + `certs/` в корне репозитория):

```
config.json
certs/
  signer.pem
  signer-key.pem
  driver.pem
  ...
```

На Android — те же пути в `assets/`. На iOS — в app bundle (`certs/` как **Folder Reference** в Xcode).

```kotlin
import com.atom.sgwregistry.config.BuildConfigFactory
import com.atom.sgwregistry.builder.RegistryBuilder

// Android
fun loadBuildConfig(context: Context): BuildConfig {
    val configJson = context.assets.open("config.json").use { it.readBytes() }
    val cfg = BuildConfigFactory.parseConfig(configJson.decodeToString())
    return BuildConfigFactory.toBuildConfig(cfg) { path ->
        context.assets.open(path).use { it.readBytes() }
    }
}

// iOS — com.atom.sgwregistry.util.readMainBundleResource (iosMain библиотеки)
fun loadBuildConfigFromBundle(): BuildConfig {
    val cfg = BuildConfigFactory.parseConfig(
        readMainBundleResource("config.json").decodeToString(),
    )
    return BuildConfigFactory.toBuildConfig(cfg, ::readMainBundleResource)
}

val p12 = RegistryBuilder.buildRegistry(loadBuildConfigFromBundle())
```

**Inline PEM** (ответ API без файлов в bundle):

```kotlin
val buildConfig = BuildConfigFactory.toBuildConfigFromInlinePem(
    BuildConfigFactory.parseConfig(apiJson),
)
```

Полный справочник: [API.md — мобильные платформы](kotlin/API.md#примеры-для-мобильных-платформ-android--ios--commonmain).  
**iOS (4 варианта, add/remove, Keychain):** [API.md — iOS BuildConfigFactory](kotlin/API.md#ios--buildconfigfactory-и-загрузка-ресурсов).

JVM-аналоги тех же сценариев — `samples/registry-examples/` (`./gradlew :samples:registry-examples:runAll`).

**Прямая сборка из PEM** (ответ API / secure storage):

```kotlin
import com.atom.sgwregistry.config.BuildConfigFactory
import com.atom.sgwregistry.config.SafeBagPemInput
import com.atom.sgwregistry.builder.RegistryBuilder

val cfg = BuildConfigFactory.toBuildConfig(
    vin = "EAY2AT0MPS2013376",
    uid = "client@example.com",
    verTimestamp = Instant.parse("2024-01-01T00:00:00Z"),
    verVersion = 100,
    signerCertPem = signerCertBytes,
    signerKeyPem = signerKeyBytes,
    safeBags = listOf(
        SafeBagPemInput(
            certPem = driverCertBytes,
            roleName = "dast-agent",
            roleNotBefore = Instant.parse("2026-01-15T17:40:20Z"),
            roleNotAfter = Instant.parse("2027-01-15T17:40:20Z"),
        ),
    ),
)
val p12 = RegistryBuilder.buildRegistry(cfg)
```

Сертификаты — те же, что в `certs/` и `config.json`: подписант реестра + сертификаты ролей (выдаёт PKI/бэкенд).

### Add/Remove на Android/iOS

Методы **`addCertificateAndResign`** и **`removeCertificateBySkidAndResign`** работают на мобильных так же, как на JVM: вся криптография и CMS — в `commonMain`. Отличия только в том, **откуда** берутся байты (assets, bundle, API, secure storage) и **куда** сохраняется результат.

**Вход:** `existingP12: ByteArray` + `BuildConfig` (signer cert/key + safeBags из config)  
**Выход:** новый `ByteArray` — обновлённый `.p12` с переподписью и **VER+1**  
**Не нужны:** `ConfigLoader`, `java.nio.file`, `RegistryAnalyzerJvm`

#### Общая схема (commonMain)

```kotlin
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.config.BuildConfigFactory
import com.atom.sgwregistry.model.AddCertificateRequest
import com.atom.sgwregistry.model.RemoveCertificateBySkidRequest
import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.verifier.SignatureVerifier

val buildConfig = BuildConfigFactory.toBuildConfig(cfg) { path -> loadPem(path) }
val existingP12: ByteArray = ... // assets, bundle, API, filesDir

// --- Добавить SafeBag из config (первый сертификат, которого ещё нет в реестре) ---
val newBag = buildConfig.safeBags.first { bag ->
    RegistryParser.parse(existingP12).safeBagInfos
        .mapNotNull { it.certValueDer }
        .none { it.contentEquals(bag.certDer) }
}
val withAdded = RegistryBuilder.addCertificateAndResign(
    AddCertificateRequest(
        existingP12 = existingP12,
        newBag = newBag,
        signerCertDer = buildConfig.signerCertDer,
        signerKey = buildConfig.signerKey,
    ),
)
SignatureVerifier.verifyRegistry(withAdded)

// --- Удалить SafeBag по SKID (hex, без 0x) ---
val skidHex = "019c9eff384f76abaf6163d38b3f384b"
val withRemoved = RegistryBuilder.removeCertificateBySkidAndResign(
    RemoveCertificateBySkidRequest(
        existingP12 = withAdded,
        subjectKeyId = PemEncoding.decodeSkidHex(skidHex),
        signerCertDer = buildConfig.signerCertDer,
        signerKey = buildConfig.signerKey,
    ),
)
SignatureVerifier.verifyRegistry(withRemoved)
```

Для add нужен **приватный ключ подписанта** (`signer-key.pem` в демо; в проде — **Android Keystore** / Keychain).  
Для remove нужен **SKID** удаляемого SafeBag (`localKeyID` из config или `PemEncoding.skidToHex(...)`).

#### Android — Cloud PKI + Keystore (прод)

Типичный сценарий:

1. В **Android Keystore** создаётся EC P-256 ключ (`PURPOSE_SIGN`).
2. `OwnershipCsr.build(request, key, publicKeySpki)` → Cloud PKI → Ownership leaf (EKU Email Protection + SAN).
3. **Один и тот же** ключ подписывает реестр `.p12` и `cloud_config_pem`.
4. Сертификат от PKI кладётся **и** как `signerCertDer`, **и** в SafeBag (роль, напр. `owner`).
5. После enroll: `requireSignerEkuForCms` / `requireOwnerIdBinding`.

```kotlin
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.crypto.signingKeyFromAndroidKeyStore
import com.atom.sgwregistry.csr.OwnershipCsr
import com.atom.sgwregistry.csr.OwnershipCsrRequest
import com.atom.sgwregistry.model.AddCertificateRequest
import com.atom.sgwregistry.model.SafeBagInput
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.verifier.SignatureVerifier
import kotlinx.datetime.Instant

// CSR до enroll (SPKI — из Keystore public key):
// OwnershipCsr.build(OwnershipCsrRequest(ownerId), signingKeyFromAndroidKeyStore(alias), publicKeySpkiDer)

/** alias — тот же, что при генерации CSR в Keystore */
fun addPkiCertAndResignRegistry(
    existingP12: ByteArray,
    pkiSignerCertDer: ByteArray,
    keystoreAlias: String,
    roleName: String = "owner",
    roleNotBefore: Instant,
    roleNotAfter: Instant,
): ByteArray {
    val signerKey = signingKeyFromAndroidKeyStore(keystoreAlias)

    val ownerBag = SafeBagInput(
        certDer = pkiSignerCertDer,
        roleName = roleName,
        roleNotBefore = roleNotBefore,
        roleNotAfter = roleNotAfter,
    )

    val updated = RegistryBuilder.addCertificateAndResign(
        AddCertificateRequest(
            existingP12 = existingP12,
            newBag = ownerBag,
            signerCertDer = pkiSignerCertDer, // тот же DER, что в SafeBag
            signerKey = signerKey,
        ),
    )
    SignatureVerifier.verifyRegistry(updated)
    return updated
}
```

| Правило | Зачем |
|---------|--------|
| `signerCertDer` = сертификат от PKI | Попадает в CMS `certificates`; по нему `verifyRegistry` |
| `signerKey` = Keystore alias от CSR | Пара к публичному ключу сертификата |
| Тот же DER в `SafeBag` | Роль (owner) внутри реестра |
| Не использовать `parseEcPrivateKey` для Keystore | Ключ non-exportable; нужен `signingKeyFromAndroidKeyStore` |

API: `com.atom.sgwregistry.crypto.signingKeyFromPrivateKey(PrivateKey)` — если ключ уже получен из `KeyStore`.

Полный пример с комментариями:  
`sgw-registry/src/androidMain/.../android/example/AndroidRegistryKeystoreExample.kt`

#### Android — демо из assets

Положите в `assets/` структуру как в корне репозитория: `config.json`, `certs/*`.

```kotlin
import android.content.Context
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.config.BuildConfigFactory
import com.atom.sgwregistry.model.AddCertificateRequest
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.verifier.SignatureVerifier
import java.io.File

fun loadBuildConfig(context: Context) =
    BuildConfigFactory.toBuildConfig(
        BuildConfigFactory.parseConfig(
            context.assets.open("config.json").use { it.readBytes() }.decodeToString(),
        ),
    ) { path -> context.assets.open(path).use { it.readBytes() } }

fun updateRegistryOnAndroid(context: Context) {
    val buildConfig = loadBuildConfig(context)

    // 1. Исходный .p12 — из assets, internal storage или ответа API
    val existingP12 = context.assets.open("demo-original-container.p12").use { it.readBytes() }
    // val existingP12 = File(context.filesDir, "registry.p12").readBytes()

    // 2. Добавить сертификат роли (из config.json / certs/) и переподписать
    val newBag = buildConfig.safeBags.first { bag ->
        RegistryParser.parse(existingP12).safeBagInfos
            .mapNotNull { it.certValueDer }
            .none { it.contentEquals(bag.certDer) }
    }
    val updated = RegistryBuilder.addCertificateAndResign(
        AddCertificateRequest(
            existingP12 = existingP12,
            newBag = newBag,
            signerCertDer = buildConfig.signerCertDer,
            signerKey = buildConfig.signerKey,
        ),
    )
    SignatureVerifier.verifyRegistry(updated)

    // 3. Сохранить обновлённый .p12 во внутреннее хранилище приложения
    File(context.filesDir, "registry-updated.p12").writeBytes(updated)
}
```

#### iOS — полный пример

Та же структура файлов в app bundle; каталог `certs/` — **Folder Reference** (синяя папка в Xcode).  
В проде ключ подписанта (`signer-key.pem`) часто хранят в **Keychain** — в `loadPem` для `cfg.signerKey` читайте из Keychain.

См. также [API.md — iOS BuildConfigFactory](kotlin/API.md#ios--buildconfigfactory-и-загрузка-ресурсов) (варианты 1–4, обёртка `RegistryConfigLoader`).

```kotlin
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.config.BuildConfigFactory
import com.atom.sgwregistry.model.AddCertificateRequest
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.util.readMainBundleResource
import com.atom.sgwregistry.verifier.SignatureVerifier
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.Foundation.NSData
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSSearchPathForDirectoriesInDomains
import platform.Foundation.NSUserDomainMask

@OptIn(ExperimentalForeignApi::class)
fun updateRegistryOnIos(): ByteArray {
    val buildConfig = BuildConfigFactory.toBuildConfig(
        BuildConfigFactory.parseConfig(readMainBundleResource("config.json").decodeToString()),
        ::readMainBundleResource,
    )

    // 1. Исходный .p12 из bundle (или из Documents / ответа API)
    val existingP12 = readMainBundleResource("demo-original-container.p12")

    // 2. Добавить сертификат и переподписать (VER автоматически +1)
    val newBag = buildConfig.safeBags.first { bag ->
        RegistryParser.parse(existingP12).safeBagInfos
            .mapNotNull { it.certValueDer }
            .none { it.contentEquals(bag.certDer) }
    }
    val updated = RegistryBuilder.addCertificateAndResign(
        AddCertificateRequest(
            existingP12 = existingP12,
            newBag = newBag,
            signerCertDer = buildConfig.signerCertDer,
            signerKey = buildConfig.signerKey,
        ),
    )
    SignatureVerifier.verifyRegistry(updated)

    // 3. Сохранить в Documents
    val documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, true,
    ).first() as String
    val path = "$documents/registry-updated.p12"
    updated.usePinned { pinned ->
        NSData.create(bytes = pinned.addressOf(0), length = updated.size.convert())
            ?.writeToFile(path, true)
            ?: error("Failed to write $path")
    }

    return updated
}
```

#### Проверка на JVM

Те же сценарии add/remove на desktop — через `samples/registry-examples/`:

```bash
cd kotlin
./gradlew :samples:registry-examples:runAdd-cert
./gradlew :samples:registry-examples:runRemove-cert
./gradlew :samples:registry-examples:runUpdate-registry

# кастомные пути и SKID (имя команды подставляется автоматически):
./gradlew :samples:registry-examples:runRemove-cert --args="kotlin-out/registry-with-added-cert.p12 config.json kotlin-out/after-remove.p12 019c9eff384f727db0ad9743d5e59418"
```

`runUpdate-registry` — полный цикл: add → remove (только что добавленный) → `SgwRegistry`.  
Не путать с `remove-cert`: см. раздел [Все методы API (`registry-examples`)](#все-методы-api-registry-examples).

#### Типичные ошибки

| Ситуация | Причина |
|----------|---------|
| `No safeBag in config that is not already in registry` | Все сертификаты из `config.json` уже есть в `.p12` — выберите другой `bagIndex` или другой PEM |
| `VER attribute required in registry` | Исходный `.p12` без атрибута VER — нужен контейнер ATOM-PKCS12-REGISTRY |
| `Signature verification failed` | Неверный ключ подписанта или повреждённые байты |
| SafeBag не удалился | Неверный SKID — проверьте hex (`localKeyID` в config, без дефисов) |

Подробнее о VER при изменении: раздел [VER при изменении реестра](#ver-при-изменении-реестра-p12) ниже.  
Справочник API: [API.md — Update](kotlin/API.md#update--добавить--удалить-сертификат).

### Загрузка файлов по платформам

| Платформа | Как получить `ByteArray` |
|-----------|--------------------------|
| **JVM / CLI** | `Files.readAllBytes`, `ConfigLoader.readConfig` + `toBuildConfig` |
| **Android** | `context.assets.open("certs/signer.pem").readBytes()`, **Keystore** → `signingKeyFromAndroidKeyStore(alias)` |
| **iOS** | `readMainBundleResource(path)` (`com.atom.sgwregistry.util`), Keychain, Documents, API |

После чтения байтов — единый common API (`PemEncoding`, `PlatformCrypto`, `RegistryBuilder`, `CloudConfigCms`, …).

### JVM-only удобства

На desktop/CLI доступны обёртки поверх JCA:

```kotlin
import com.atom.sgwregistry.config.ConfigLoader
import com.atom.sgwregistry.crypto.PemUtils
import com.atom.sgwregistry.model.buildConfigFromJvm
import java.nio.file.Files
import java.nio.file.Path
```

См. раздел [Пример использования (JVM)](#пример-использования-jvm) ниже.

## Структура

Gradle-модуль расположен в каталоге `kotlin/`. Тесты и примеры запускаются с **рабочим каталогом на уровень выше** — в корне проекта, где лежат `config.json`, `certs/` и демо-файлы `.p12`.

```
<корень проекта>/
├── config.json                  # сборка / resign / sign-tbox (demo signer)
├── owner-empty-config.json      # empty-owner (`safeBags: []`)
├── certs/                       # PEM реестра + CA для cloud-config trust
│   ├── signer.pem / signer-key.pem
│   ├── ATOM Ownership CA.pem
│   └── ATOM ROOT ext CA.pem
├── mob-dev-cloud_config.json    # fixture mob-dev envelope + CMS
├── resp-context.json            # invitation → TBOX (snake_case draft)
├── ownership-resp.json          # ownership ledger (`ownership_registry[]` CMS)
├── demo-original-container.p12  # демо-реестр parse/verify/update
├── spas-delegate.p12            # неподписанный контейнер (тесты)
├── kotlin-out/                  # артефакты примеров
│   ├── cloud-config-tbox.json / .envelope.json
│   ├── cloud-config-tbox-signed.pem
│   └── mob-dev-cloud_config-resigned.json
└── kotlin/
    ├── sgw-registry/            # библиотека: .p12 + cloudconfig
    ├── samples/
    │   ├── build-registry-example/   # CLI: config.json → .p12
    │   └── registry-examples/        # все методы API (JVM)
    ├── API.md                   # справочник API
    ├── dist/                    # Maven + плоский JVM JAR
    └── gradlew
```

| Путь | Описание |
|------|----------|
| `config.json` + `certs/` | Сборка реестра, resign, sign-tbox |
| `resp-context.json` | Invitation draft → `cloud-config-from-context` |
| `mob-dev-cloud_config.json` | Fixture mob-dev (`cloud_config_json` + `cloud_config_pem`) |
| `owner-empty-config.json` | Пустой `owner.p12` |
| `sgw-registry/` | Библиотека: PKCS#12 + CloudConfigCms / FromContext / Fqdn + OwnershipCsr |
| `samples/registry-examples/` | JVM CLI: `.p12` + `cloud-config*` / `sign-tbox` / `gen-ownership-csr` / `ownership-verify*` / `empty-owner*` |
| `ownership-resp.json` | fixture ownership ledger (`ownership_registry[]` CMS) |
| `samples/build-registry-example/` | CLI: config.json → .p12 |
| [kotlin/API.md](kotlin/API.md) | Справочник публичного API |

Каталог `.NET8` **не требуется** — `config.json` и сертификаты лежат в корне проекта.

## Требования

| Компонент | Для чего |
|-----------|----------|
| JDK 21+ | JVM-сборка, тесты, CLI-примеры |
| Gradle 8.x (или `./gradlew`) | Сборка модуля |
| Android SDK | Публикация `sgw-registry-android`, сборка Android-потребителя |
| Xcode + Command Line Tools | iOS-сборка, `iosSimulatorArm64Test` |

В `gradle.properties`: `kotlin.mpp.applyDefaultHierarchyTemplate=false` (явные iOS source sets), `android.suppressUnsupportedCompileSdk=35`.

## Сборка библиотеки для других проектов

```bash
cd kotlin
./gradlew :sgw-registry:publishLibrary
```

Публикует в `kotlin/dist/maven/` и `~/.m2/repository/`. Подробнее — [Публикация Maven (KMP)](#публикация-maven-kmp) выше.

Дополнительно копируется плоский JVM JAR (только desktop):

| Файл | Назначение |
|------|------------|
| `dist/sgw-registry-2.6.0.jar` | JVM JAR (без KMP metadata) |
| `dist/sgw-registry-2.6.0-sources.jar` | исходники JVM variant |

### Gradle — JVM-only проект

```kotlin
repositories {
    mavenLocal()
    maven { url = uri("/path/to/kotlin/dist/maven") }
}

dependencies {
    implementation("com.atom:sgw-registry:2.6.0")  // резолвится в -jvm variant
}
```

Требуется **JDK 21+**. Транзитивные зависимости: `kotlinx-serialization-json`, `kotlinx-datetime`.

### Maven (JVM)

```xml
<dependency>
  <groupId>com.atom</groupId>
  <artifactId>sgw-registry</artifactId>
  <version>2.6.0</version>
</dependency>
```

Добавьте `mavenLocal` или локальный репозиторий `kotlin/dist/maven` в `<repositories>`.

### Пример использования (JVM)

```kotlin
import com.atom.sgwregistry.analyzer.RegistryAnalyzer
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.config.ConfigLoader
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.verifier.SignatureVerifier
import java.nio.file.Files
import java.nio.file.Path

// --- Разбор и проверка готового .p12 ---
val p12 = Files.readAllBytes(Path.of("registry.p12"))
val container = RegistryParser.parse(p12)  // иммутабельные копии байтов

println("safeBags: ${container.safeBagInfos.size}")
println("signer resolved: ${container.signerCertResolved}")
container.parseWarnings.forEach { System.err.println("warn: $it") }

// ATOM authenticatedAttributes (VIN, UID, VER, messageDigest)
RegistryAnalyzer.parseAuthenticatedAttributes(container.authenticatedAttributesSetBytes)
    .forEach { (name, value) -> println("$name: $value") }

SignatureVerifier.verifyRegistry(p12)  // или verifyContainer(container)
println(RegistryAnalyzer.toTextDetailed(container))

// --- Сборка из config.json ---
val configPath = "config.json"
val configDir = Path.of(configPath).parent.toString()
val fileConfig = ConfigLoader.readConfig(configPath)
val buildConfig = ConfigLoader.toBuildConfig(fileConfig, configDir)
val built = RegistryBuilder.buildRegistry(buildConfig)
Files.write(Path.of("kotlin-out/built.p12"), built)
SignatureVerifier.verifyRegistry(built)
```

### config.json

Файл `config.json` располагается в **корне проекта** (родительский каталог относительно `kotlin/`).
Относительные пути к PEM (`certs/signer.pem`, `certs/driver.pem`, …) разрешаются от каталога, в котором лежит `config.json`.

Минимальный набор полей:

| Поле | Описание |
|------|----------|
| `signerCert`, `signerKey` | Пути к PEM подписанта (или `signerCertPem` / `signerKeyPem`) |
| `vin`, `uid` | ATOM authenticatedAttributes |
| `verTimestamp`, `verVersion` | Начальная версия VER (V ≥ 1) |
| `safeBags[]` | Сертификаты ролей: `cert`, `roleName`, `roleNotBefore`, `roleNotAfter`, `localKeyID` |

При вызове `ConfigLoader.toBuildConfig` передайте каталог конфига как `configDir` (обычно `"."` при запуске из корня проекта).

## Реестр PKCS#12

Операции над контейнером **ATOM-PKCS12-REGISTRY** (`.p12`). Cloud configuration — отдельный CMS-формат, см. [ниже](#cloud-configuration-mob-dev).

## VER при изменении реестра (.p12)

Атрибут **VER** (OID `1.3.6.1.4.1.99999.1.2`) — обязательная версия реестра в `SignerInfo.authenticatedAttributes`.  
При **любом** изменении существующего `.p12` библиотека **автоматически** обновляет VER и переподписывает CMS.

### Когда применяется

| Операция | Метод | Поведение VER |
|----------|--------|----------------|
| Первая сборка из config | `RegistryBuilder.buildRegistry` | VER из `config.json` (`verTimestamp`, `verVersion`); должен быть задан явно (V ≥ 1) |
| Добавить сертификат | `addCertificateAndResign` | VER из исходного `.p12` → **V{n+1}** + текущий UTC |
| Удалить по SKID | `removeCertificateBySkidAndResign` | то же |
| Любая переподпись SafeBag | `resignWithSafeBags` | `requirePresent` + VER из переданных `SignerAttrs` |

Методы изменения **не принимают** версию VER вручную — инкремент выполняется внутри библиотеки.  
Параметр `signerAttrs` в `AddCertificateRequest` / `RemoveCertificateBySkidRequest` может переопределить только **VIN** и **UID**; VER всегда берётся из исходного реестра и увеличивается на 1.

### Формат

Текстовое представление (в отчётах и `RegistryAnalyzer`):

```
yyyy-MM-dd HH:mm:ss:V{n}
```

Пример: `2026-01-19 12:00:00:V102`

В DER (CMS): `SEQUENCE { GeneralizedTime, INTEGER version }`.

Правила:
- `n ≥ 1` (V0 недопустим);
- timestamp — UTC, точность до секунды;
- при изменении реестра: **ровно +1** к номеру версии, timestamp = `Instant.now()` (UTC).

### Внутренняя цепочка (Kotlin)

```
RegistryParser.parse(existingP12)
  → RegistryConverters.extractSignerAttrs()   // VER обязателен, parseText()
  → VerAttribute.resolveForRegistryUpdate()   // merge VIN/UID, bumpForRegistryUpdate()
  → buildSafeContents(...) + buildPfxFromContent()  // requirePresent(), новая подпись
```

Утилита: `com.atom.sgwregistry.builder.VerAttribute`

| Метод | Назначение |
|-------|------------|
| `parseText(value)` | Разбор и валидация строки VER → `(Instant, version)` |
| `formatText(timestamp, version)` | Формирование строки для отображения |
| `requirePresent(attrs)` | Проверка перед подписью: `verVersion > 0`, timestamp ≠ EPOCH |
| `bumpForRegistryUpdate(attrs)` | V{n} → V{n+1}, timestamp = now UTC |
| `resolveForRegistryUpdate(container, override?)` | Извлечь VER из `.p12`, опционально VIN/UID, затем bump |

### Ошибки (типичные)

| Ситуация | Исключение |
|----------|------------|
| В исходном `.p12` нет атрибута VER | `IllegalStateException`: `VER attribute required in registry` |
| Неверный формат VER | `IllegalArgumentException`: `Invalid VER format...` |
| V0 или отрицательная версия | `IllegalArgumentException`: `VER version must be positive` |
| Сборка без VER в config | `IllegalArgumentException`: `VER is required` |

`SignatureVerifier.verifyRegistry` проверяет **криптографическую подпись**, но **не** сравнивает монотонность версий между двумя файлами — это обеспечивается только при изменении через API библиотеки.

## Добавить сертификат в существующий реестр

```kotlin
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.builder.VerAttribute
import com.atom.sgwregistry.config.ConfigLoader
import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.model.AddCertificateRequest
import com.atom.sgwregistry.model.SafeBagInput
import com.atom.sgwregistry.analyzer.RegistryAnalyzer
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.verifier.SignatureVerifier
import java.nio.file.Files
import java.nio.file.Path

val existingP12 = Files.readAllBytes(Path.of("demo-original-container.p12"))
val buildCfg = ConfigLoader.toBuildConfig(
    ConfigLoader.readConfig("config.json"),
    ".",
)

// опционально: проверить VER до изменения
val beforeVer = RegistryAnalyzer.parseAuthenticatedAttributes(
    RegistryParser.parse(existingP12).authenticatedAttributesSetBytes,
).first { it.first == "VER" }.second
VerAttribute.parseText(beforeVer)

val newBag = SafeBagInput(
    certDer = PemEncoding.decodePemOrDer(Files.readAllBytes(Path.of("certs/passenger.pem"))),
    roleName = "dast-agent",
    roleNotBefore = buildCfg.safeBags[1].roleNotBefore,
    roleNotAfter = buildCfg.safeBags[1].roleNotAfter,
)

val updated = RegistryBuilder.addCertificateAndResign(
    AddCertificateRequest(
        existingP12 = existingP12,
        newBag = newBag,
        signerCertDer = buildCfg.signerCertDer,
        signerKey = buildCfg.signerKey,
    ),
)
Files.write(Path.of("kotlin-out/updated.p12"), updated)
SignatureVerifier.verifyRegistry(updated)
```

См. раздел [VER при изменении реестра (.p12)](#ver-при-изменении-реестра-p12) — правила auto-bump обязательны.

## Удалить сертификат по SKID

```kotlin
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.model.RemoveCertificateBySkidRequest
import com.atom.sgwregistry.crypto.PemEncoding  // commonMain (KMP)
// JVM: import com.atom.sgwregistry.crypto.PemUtils

val updated = RegistryBuilder.removeCertificateBySkidAndResign(
    RemoveCertificateBySkidRequest(
        existingP12 = existingP12Bytes,
        subjectKeyId = PemEncoding.decodeSkidHex("a1b2c3..."),
        signerCertDer = buildCfg.signerCertDer,
        signerKey = buildCfg.signerKey,
    ),
)
```

См. [VER при изменении реестра (.p12)](#ver-при-изменении-реестра-p12).

SKID сопоставляется с `localKeyID` SafeBag и с расширением Subject Key Identifier (2.5.29.14) сертификата.

## Cloud configuration (mob-dev)

Ответ облачного сервиса **не** `.p12`-реестр. Это JSON с полем `cloud_configuration`: подписанная CMS-конфигурация брокера и метаданные владельца.

| Сценарий | API | CLI |
|----------|-----|-----|
| Parse / verify / resign готового envelope | `CloudConfigCms` | `cloud-config`, `cloud-config-trust` |
| Invitation (`resp-context.json`) → TBOX + CES FQDN + CMS | `CloudConfigFromContext` + `CloudBrokerFqdn` | `cloud-config-from-context` |
| TBOX JSON → `cloud_config_pem` | `CloudConfigFromContext.signTboxPayload` | `sign-tbox` |
| Ownership PKCS#10 CSR (EKU Email Protection + SAN) | `OwnershipCsr` | `gen-ownership-csr` |
| Ownership statement ledger (`ownership_registry[]` CMS) | `OwnershipRegistryVerifier` | `ownership-verify`, `ownership-verify-list` |

Полный справочник: [API.md — Cloud config](kotlin/API.md#cloud-config--cloudconfigcms-mob-dev), [API.md — Ownership CSR](kotlin/API.md#ownership-csr--ownershipcsr), [API.md — Ownership ledger](kotlin/API.md#ownership-ledger--ownershipregistryverifier).  
Запуск CLI: [Запуск примеров](#запуск-примеров).

### Ownership ledger (`ownership-verify`)

Проверка цепочки подписанных statements о владении автомобилем.

API принимает **три явных аргумента**:

| # | Аргумент | Тип | Смысл |
|---|----------|-----|--------|
| 1 | `ownershipRegistryCms` | `List<String>` | упорядоченный список CMS PEM |
| 2 | `ownerId` | `String` | UID текущего владельца (последний `owner_dn`) |
| 3 | `vin` | `String` | VIN (одинаковый во всей цепочке) |

```kotlin
// A) из JSON invitation
val ledger = OwnershipLedgerJson.parse(bytes)
OwnershipRegistryVerifier.verify(
    ownershipRegistryCms = ledger.context.ownershipRegistry,
    ownerId = "7f9fc821-a09e-4f96-badc-643daca070c6",
    vin = "AAABBBCCC3",
)

// B) только готовая List<String> (без JSON)
val ownershipRegistryCms: List<String> = listOf(cmsPem0, cmsPem1)
SgwRegistry.verifyOwnershipRegistry(
    ownershipRegistryCms = ownershipRegistryCms,
    ownerId = "7f9fc821-a09e-4f96-badc-643daca070c6",
    vin = "AAABBBCCC3",
)
```

Проверки: подпись каждого CMS → связность `p_hash` → единый VIN → UID последнего `owner_dn`.  
Fixture: `ownership-resp.json`. Подробнее: [API.md](kotlin/API.md#ownership-ledger--ownershipregistryverifier).

### Ownership CSR (PKCS#10)

Генерация CSR для Ownership leaf **без BouncyCastle** (`AsnWriter` + `PlatformCrypto`).

По умолчанию в `extensionRequest`:

| Расширение | Значение |
|------------|----------|
| KeyUsage | `digitalSignature` (critical) |
| EKU | **Email Protection** (`1.3.6.1.5.5.7.3.4`) — для CMS cloud_config |
| SAN | `URI:atombus:/user/{ownerId}` |
| Subject | `O=ATOM`, `OU=Customers` + `EnhancedAuth`, `UID={ownerId}` |

```kotlin
import com.atom.sgwregistry.csr.OwnershipCsr
import com.atom.sgwregistry.csr.OwnershipCsrRequest

val csr = OwnershipCsr.buildFromEcPrivateKeyPem(
    OwnershipCsrRequest(ownerId = "d231b684-82b4-4fdc-83dd-fc9a1861c293"),
    ecPrivateKeyPem, // SEC1 EC PRIVATE KEY с publicKey [1]
)
// csr.csrPem → Cloud PKI
// После выдачи leaf: CloudConfigCms.requireSignerEkuForCms / requireOwnerIdBinding
```

> CA для отладки  может проигнорировать запрошенный EKU. После enroll всегда валидируйте leaf.

JVM CLI:

```bash
./gradlew :samples:registry-examples:runGen-ownership-csr
openssl req -in ../kotlin-out/ownership.csr.pem -noout -text -verify
```

### Invitation / resp-context → TBOX payload + CMS

Вход сервиса invitation (`resp-context.json`):

- `context.vehicle_cloud_configuration` — snake_case draft брокера (`root_cas`, `base_domain` = суффикс вроде `mqtt.atom.auto`)
- `context.ownership_registry` — PFX v3 / CMS с leaf UID (= `owner_id`)
- `vin`, `tenant_id`

`CloudConfigFromContext` собирает camelCase payload для TBOX и (опционально) CMS:

```json
{
  "v": 5,
  "cloudBroker": {
    "rootCAs": [ "...PEM..." ],
    "endpoint": {
      "fqdnConstrAlg": 1,
      "baseDomain": "d06e-2281305f-….mqtt.atom.auto"
    }
  }
}
```

#### CES §5 — FQDN (`fqdnConstrAlg = 1`)

```
FQDN = hashB(VIN) + "-" + identityId + "." + domainSuffix
hashB = последние 4 hex SHA-1(ASCII VIN)
```

Пример из CES: `c602-bdb79393-a9e3-4024-86a8-5f372df9121f.mqtt.atom.auto`  
В invitation-примере `identityId` = `tenant_id` (CES для production — owner UID).  
API: `CloudBrokerFqdn.hashB` / `buildFqdn` / `resolveBaseDomain`.

В signed / TBOX JSON поле `endpoint.baseDomain` хранит **полный FQDN** (не только суффикс).

```kotlin
val response = CloudConfigFromContext.parseInvitationResponse(bytes)
// FQDN: hashB(vin)-tenant_id.mqtt… ; owner_id = UID ownership leaf
val signed = CloudConfigFromContext.buildAndSign(
    response, ownerCertDer, ownerKey, payloadVersion = 5,
)
CloudConfigCms.verifyCloudConfiguration(signed)
val tboxPretty = CloudConfigFromContext.encodeTboxPayload(signed) // для TBOX
val cmsPem = signed.cloudConfigPem                              // cloud_config_pem
```

JVM CLI (подробнее — [Запуск примеров](#запуск-примеров)):

```bash
./gradlew :samples:registry-examples:runCloud-config-from-context
./gradlew :samples:registry-examples:runSign-tbox
```

| Выход | Смысл |
|-------|--------|
| `kotlin-out/cloud-config-tbox.json` | payload для TBOX (`v` + `cloudBroker`) |
| `…tbox.envelope.json` | mob-dev envelope + CMS (для `cloud-config-trust`) |
| `…tbox-signed.pem` | только CMS PEM (= `cloud_config_pem`) |

### Формат mob-dev envelope

```json
{
  "cloud_configuration": {
    "root_cas": [ "-----BEGIN CERTIFICATE-----...", "..." ],
    "id": "...",
    "vin": "79079999999",
    "owner_id": "d231b684-82b4-4fdc-83dd-fc9a1861c293",
    "version": "1",
    "base_domain": "...",
    "cloud_config_json": "{...}",
    "cloud_config_pem": "-----BEGIN CMS-----\\n...\\n-----END CMS-----",
    "created_at": "...",
    "updated_at": "..."
  }
}
```

| Поле | Смысл |
|------|--------|
| `cloud_config_json` | Полезная нагрузка (broker, rootCAs, endpoint) — то, что подписано |
| `cloud_config_pem` | CMS **SignedData** (standalone, не PFX); eContent = UTF-8 байты `cloud_config_json` |
| `vin` / `owner_id` | Идентичность конфигурации |
| `root_cas` | CA для TLS брокера (ATOM ROOT / Tenant) — **другая ветка**, чем issuer CMS-leaf |

В CMS обычно только **leaf** владельца (`issuer` = ATOM Ownership CA, в subject — `UID` = `owner_id`).

### API (`commonMain` — JVM / Android / iOS)

Пакет `com.atom.sgwregistry.cloudconfig` / фасад `SgwRegistry`:

| Задача | `CloudConfigCms` | `SgwRegistry` |
|--------|-----------------|---------------|
| Parse JSON | `parseMobDevResponse` | `parseMobDevCloudConfig` |
| Parse CMS | `parsePem` | `parseCloudConfigPem` |
| Verify CMS | `verify` / `verifyPem` / `tryVerify` | `verifyCloudConfigPem` |
| JSON == eContent + CMS | `verifyCloudConfiguration` | `verifyCloudConfiguration` |
| vin / owner_id | `matchesIdentity` / `requireIdentity` | `requireCloudConfigIdentity` |
| owner_id ↔ UID leaf | `requireOwnerIdInSigner` | `requireCloudConfigOwnerIdInSigner` |
| owner_id ↔ FQDN ↔ SAN ↔ EKU | `requireOwnerIdBinding(..., requireEku=true)` / `requireSignerEkuForCms` | `requireCloudConfigOwnerIdBinding` / `requireCloudConfigSignerEku` |
| Resign (eContent из JSON) | `resignToPem` / `resignConfiguration` | `resignCloudConfigPem` |
| Resign (eContent как в CMS) | `resignOnlyToPem` / `resignConfigurationOnly` | `resignCloudConfigOnly` / `resignCloudConfigurationOnly` |
| Отчёт | `toText` | `cloudConfigToText` |

#### Как игнорировать EKU

**Проверка подписи CMS (`verify` / `verifyCloudConfiguration`) EKU не проверяет.**  
EKU — только в `requireOwnerIdBinding` / `requireSignerEkuForCms`.

```kotlin
// только подпись + JSON == eContent
CloudConfigCms.verifyCloudConfiguration(dto)

// FQDN + SAN, без EKU (demo-signer / Client Auth leaf)
CloudConfigCms.requireOwnerIdBinding(dto, requireEku = false)
SgwRegistry.requireCloudConfigOwnerIdBinding(dto, requireEku = false)

// полный CES-контракт (default)
CloudConfigCms.requireOwnerIdBinding(dto) // requireEku = true
```

По умолчанию `requireEku = true`. В production для cloud_config обычно оставляют включённым.

`CloudConfigFromContext` / фасад:

| Задача | Метод |
|--------|--------|
| Parse invitation | `parseInvitationResponse` / `SgwRegistry.parseInvitationContext` |
| Build + sign | `buildAndSign` / `SgwRegistry.buildCloudConfigurationFromContext` |
| TBOX JSON | `encodeTboxPayload` |
| Sign TBOX | `signTboxPayload` |
| CES FQDN | `CloudBrokerFqdn.hashB` / `buildFqdn` / `resolveBaseDomain` |
| Ownership CSR | `OwnershipCsr.build*` / `SgwRegistry.buildOwnershipCsr*` |
| Ownership ledger | `OwnershipRegistryVerifier.verify*` / `SgwRegistry.verifyOwnershipRegistry` |

**`resign` vs `resignOnly`:**

| Метод | eContent | Когда |
|-------|----------|-------|
| `resignConfiguration` / `resignToPem` | пересборка: `cloud_config_json.encodeToByteArray()` | меняли JSON |
| `resignConfigurationOnly` / `resignOnly*` | байты из существующего CMS **как есть** | только новый signer |

Методы библиотеки по умолчанию **не** проверяют были ли изменены данные в поле:  `cloud_config_json`, поэтому перед тем как подписать payload проверяте и выбирайте явно метод подписи : `resignToPem` или `resignOnly`.

```kotlin
import com.atom.sgwregistry.cloudconfig.CloudConfigCms
import com.atom.sgwregistry.model.MobDevCloudConfigJson

val dto = MobDevCloudConfigJson.parse(responseBytes).cloudConfiguration

CloudConfigCms.requireIdentity(dto, expectedVin, expectedOwnerId)
CloudConfigCms.requireOwnerIdInSigner(dto)
CloudConfigCms.verifyCloudConfiguration(dto)

// только переподпись (payload не трогаем)
val updated = CloudConfigCms.resignConfigurationOnly(
    dto = dto,
    signerCertDer = ownerCertDer,
    signerKey = signingKey,
)
```

PKIX-цепочка к CA **не** входит в `CloudConfigCms` (платформозависима). На JVM пример: `JvmCertificateTrust` + `cloud-config-trust`.

### Цепочка доверия CMS-подписанта

```
leaf (owner, UID=owner_id)
  → ATOM Ownership CA          ← certs/ATOM Ownership CA.pem (intermediate)
    → ATOM ROOT ext CA         ← certs/ATOM ROOT ext CA.pem (trust anchor)
```

`root_cas` из JSON (ATOM ROOT / Tenant) — для MQTT/брокера; сами по себе к CMS-leaf не ведут.

После `resign` trust сохраняется **только если** новый `signerCert` из ветки Ownership CA. Demo-signer из `config.json` (`CN=Owner Registry Signer`) даёт OK по подписи, но FAIL по Ownership-PKIX / UID.

### Fixture и артефакты

| Файл | Роль |
|------|------|
| `mob-dev-cloud_config.json` | исходный ответ (owner-leaf); тесты + примеры |
| `resp-context.json` | invitation → TBOX |
| `certs/ATOM Ownership CA.pem` | intermediate PKIX |
| `certs/ATOM ROOT ext CA.pem` | extra trust anchor PKIX |
| `config.json` + `certs/signer.pem` | demo resign / sign-tbox |
| `kotlin-out/cloud-config-tbox.json` | TBOX payload |
| `kotlin-out/mob-dev-cloud_config-resigned.json` | результат resign (**исходник не перезаписывается**) |

Stage-leaf в fixture часто короткоживущий (~1 ч). В `cloud-config-trust`, если leaf уже истёк «по часам», PKIX проверяется на `leaf.notBefore`.

### JVM CLI

См. раздел [Запуск примеров](#запуск-примеров):

| Gradle-задача | Сценарий |
|---------------|----------|
| `runCloud-config` | parse / verify / resign |
| `runCloud-config-trust` | identity → PKIX → CMS |
| `runCloud-config-from-context` | invitation → TBOX + FQDN |
| `runSign-tbox` | TBOX → `cloud_config_pem` |
| `runSign-cloud-config` | fixtures → binding + resign |
| `runGen-ownership-csr` | PKCS#10 Ownership CSR (EKU + SAN) |
| `runOwnership-verify` | JSON → List CMS → verify(cms, ownerId, vin) |
| `runOwnership-verify-list` | готовая List CMS PEM → verify |

## Сборка и тесты

Команды выполняются из каталога `kotlin/`. Тесты и примеры используют данные из корня проекта (`config.json`, `certs/`, `*.p12`).

### Unit-тесты библиотеки (исходники `:sgw-registry`)

Проверяют код модуля напрямую (без Maven-артефакта):

```bash
cd kotlin
export JAVA_HOME=$(/usr/libexec/java_home -v 21 2>/dev/null || /usr/libexec/java_home)

# JVM / Android / iOS unit-тесты (66 тестов)
./gradlew :sgw-registry:jvmTest

# iOS Simulator — тот же набор (требуется Xcode)
./gradlew :sgw-registry:iosSimulatorArm64Test
```

### Тестирование на iOS (`iosSimulatorArm64Test`)

На iOS и Android выполняется **тот же набор из 66 unit-тестов**, что и на JVM. Тесты в **`commonTest`**; платформо-специфичным остаётся только чтение файловых фикстур.

#### Структура исходников тестов

```
sgw-registry/src/
├── commonTest/kotlin/com/atom/sgwregistry/
│   ├── RegistryGoldenTest.kt           # parse / verify / build / add / remove (23)
│   ├── CloudConfigCmsTest.kt           # mob-dev CMS parse/verify/resign (9)
│   ├── CloudConfigFromContextTest.kt   # invitation → TBOX + FQDN (4)
│   ├── CloudBrokerFqdnTest.kt          # CES §5 hashB / FQDN (3)
│   ├── OwnershipCsrTest.kt             # PKCS#10 Ownership CSR EKU/SAN
│   ├── OwnershipRegistryVerifierTest.kt # ledger CMS chain + VIN + ownerId
│   ├── AddCertificatePlatformTest.kt   # add/remove + PlatformCrypto (3)
│   ├── SubjectKeyIdTest.kt             # X509DerParser + SKID (3)
│   ├── VerAttributeTest.kt             # VER CMS (3)
│   ├── TestFixtures.kt                 # expect — чтение фикстур
│   └── TestBuildConfig.kt              # config.json → BuildConfig
├── jvmTest/…/TestFixtures.jvm.kt       # actual: java.nio.file + repoRoot
└── iosSimulatorArm64Test/…/TestFixtures.ios.kt  # actual: рядом с test.kexe
```

| Класс | Что проверяет |
|-------|----------------|
| **RegistryGoldenTest** | `.p12` parse/verify/build/add/remove, VER bump, immutability |
| **CloudConfigCmsTest** | mob-dev CMS: parse, verify, resign / resignOnly |
| **CloudConfigFromContextTest** | invitation → camelCase TBOX, FQDN, ownership UID |
| **CloudBrokerFqdnTest** | `hashB(VIN)`, `buildFqdn`, `resolveBaseDomain` |
| **OwnershipCsrTest** | PKCS#10 CSR: Email Protection EKU, SAN, UID, PEM round-trip |
| **OwnershipRegistryVerifierTest** | ledger: signatures, `p_hash`, VIN, last `owner_dn` (`ownership-resp.json`) |
| **SubjectKeyIdTest** | `X509DerParser` + SKID через `PlatformCrypto` |
| **VerAttributeTest** | формат VER и `bumpForRegistryUpdate` |
| **AddCertificatePlatformTest** | add/remove на commonMain crypto |

На JVM тесты используют JCA (`PemUtils`, `ConfigLoader`). На iOS — только **commonMain** API: `BuildConfigFactory`, `PlatformCrypto`, `PemEncoding`, `X509DerParser` (внутренний парсер DER для сертификатов в `iosMain`).

#### Тестовые данные (фикстуры)

Фикстуры берутся из **корня проекта** (родитель каталога `kotlin/`):

| Файл / каталог | Используется в тестах |
|----------------|----------------------|
| `demo-original-container.p12` | parse, verify, tamper, VER, authenticated attributes |
| `spas-delegate.p12` | неподписанный контейнер, verify должен падать |
| `config.json` | round-trip build, add/remove cert, duplicate rejection |
| `certs/signer.pem` | SKID подписанта |
| `certs/signer-key.pem` | `loadSignerKeyFromPem` |
| `certs/driver.pem`, `passenger.pem`, … | safeBags из config (build/add/remove) |
| `mob-dev-cloud_config.json` | CloudConfigCmsTest |
| `resp-context.json` | CloudConfigFromContextTest |

**JVM:** `workingDir` = корень проекта, путь через `systemProperty("sgw.registry.repoRoot")` (`TestFixtures.jvm.kt`).

**iOS:** Kotlin/Native запускает тесты как **`test.kexe`**, а не `.app` bundle — у `NSBundle.mainBundle` нет встроенных ресурсов. Gradle копирует фикстуры **в ту же папку**, где лежит исполняемый файл; `TestFixtures.ios.kt` читает их по относительному пути (`certs/signer.pem`, `demo-original-container.p12`, …).

#### Gradle-задачи (цепочка iOS-тестов)

При `./gradlew :sgw-registry:iosSimulatorArm64Test` выполняется:

| Задача | Назначение |
|--------|------------|
| `compileTestKotlinIosSimulatorArm64` | компиляция `commonTest` + `iosSimulatorArm64Test` |
| `linkDebugTestIosSimulatorArm64` | линковка `test.kexe` |
| `syncIosTestFixtures` | копия фикстур из корня проекта → `build/iosTestFixtures/` |
| `copyIosSimulatorArm64TestResources` | всё в каталог рядом с `test.kexe` |
| `iosSimulatorArm64Test` | запуск `test.kexe` на симуляторе arm64 |

Конфигурация в `sgw-registry/build.gradle.kts` (задачи `syncIosTestFixtures`, `copyIosSimulatorArm64TestResources`).

**Артефакты после сборки:**

```
sgw-registry/build/bin/iosSimulatorArm64/debugTest/
├── test.kexe                      # исполняемый файл тестов
├── test.kexe.dSYM/                # символы отладки
├── demo-original-container.p12
├── spas-delegate.p12
├── config.json
└── certs/                         # PEM из config.json
```

**Отчёт:** `sgw-registry/build/reports/tests/iosSimulatorArm64Test/index.html`

```bash
cd kotlin
./gradlew :sgw-registry:iosSimulatorArm64Test

# JVM + iOS одной командой
./gradlew :sgw-registry:jvmTest :sgw-registry:iosSimulatorArm64Test
```

> KGP может предупреждать, что версия Xcode новее протестированной. Подавить: `kotlin.apple.xcodeCompatibility.nowarn=true` в `gradle.properties`.

### Интеграционные примеры

Модули `samples/registry-examples` и `samples/build-registry-example` — JVM CLI для отладки API.

**Локальная разработка (по умолчанию):** примеры подключают библиотеку напрямую:

```kotlin
// samples/registry-examples/build.gradle.kts
dependencies {
    implementation(project(":sgw-registry"))
}
```

Публикация в Maven **не нужна** — достаточно собрать модуль:

```bash
cd kotlin
./gradlew :samples:registry-examples:runCloud-config
```

**Проверка опубликованного Maven-артефакта** (как внешний потребитель): временно замените зависимость на `com.atom:sgw-registry:2.6.0`, опубликуйте в `kotlin/dist/maven/` и запустите smoke-тест (см. [API.md — Проверка опубликованного пакета](kotlin/API.md#проверка-опубликованного-пакета-тесты-и-примеры)).

Рабочий каталог всех примеров: **корень репозитория** (родитель `kotlin/`). Gradle передаёт `sgw.registry.repoRoot`.

## Запуск примеров

Модуль `samples/registry-examples` — JVM CLI для отладки API на desktop  
(`implementation(project(":sgw-registry"))`, публикация Maven не нужна).

Все команды — из каталога `kotlin/`. Пути в аргументах относительно **корня репозитория** (родитель `kotlin/`).  
Аналогичная структура разделов: [API.md — JVM-примеры](kotlin/API.md#jvm-примеры-registry-examples).

### Быстрый старт

```bash
cd kotlin

# .p12 — полный набор (parse, verify, build, add/remove)
./gradlew :samples:registry-examples:runAll

# mob-dev cloud_configuration — parse + verify (+ resign при наличии config.json)
./gradlew :samples:registry-examples:runCloud-config

# invitation → TBOX JSON с CES FQDN + CMS (envelope)
./gradlew :samples:registry-examples:runCloud-config-from-context

# TBOX JSON → cloud_config_pem (+ envelope)
./gradlew :samples:registry-examples:runSign-tbox

# Ownership PKCS#10 CSR (EKU Email Protection + SAN)
./gradlew :samples:registry-examples:runGen-ownership-csr

# ownership ledger — JSON → List CMS → verify(cms, ownerId, vin)
./gradlew :samples:registry-examples:runOwnership-verify

# ownership ledger — только готовая List<String> CMS PEM
./gradlew :samples:registry-examples:runOwnership-verify-list

# пустой owner.p12 (0 SafeBag)
./gradlew :samples:registry-examples:runEmpty-owner
```

### Сокращённые Gradle-задачи (`registry-examples`)

| Gradle-задача | Команда CLI | Что делает |
|---------------|-------------|------------|
| `runParse` | `parse` | Разбор `.p12` → `RegistryContainer` |
| `runVerify` | `verify` | `SignatureVerifier.verifyRegistry` |
| `runAnalyze` | `analyze` | Отчёт, JSON, экспорт PEM |
| `runConfig` | `config` | `ConfigLoader` + SKID signer |
| `runBuild` | `build` | Сборка `.p12` из `config.json` |
| `runEmpty-owner` | `empty-owner` | Пустой `owner.p12` (0 SafeBag) + VIN/UID/VER |
| `runEmpty-owner-unsigned` | `empty-owner-unsigned` | Без подписи: SafeContents.der + header.json |
| `runAdd-cert` | `add-cert` | Добавить SafeBag + переподпись |
| `runRemove-cert` | `remove-cert` | Удалить SafeBag по SKID |
| `runUpdate-registry` | `update-registry` | add → verify → remove (round-trip) |
| `runCloud-config` | `cloud-config` | mob-dev JSON: parse/verify/resign CMS |
| `runCloud-config-trust` | `cloud-config-trust` | identity → PKIX(root_cas + ROOT ext) → CMS signature |
| `runCloud-config-from-context` | `cloud-config-from-context` | resp-context → TBOX JSON (+ envelope, CES FQDN) |
| `runSign-tbox` | `sign-tbox` | TBOX JSON → `cloud_config_pem` (+ envelope) |
| `runSign-cloud-config` | `sign-cloud-config` | fixtures: binding + resign + from-context |
| `runGen-ownership-csr` | `gen-ownership-csr` | Ownership PKCS#10 CSR (EKU + SAN) |
| `runOwnership-verify` | `ownership-verify` | JSON → List CMS → verify(cms, ownerId, vin) |
| `runOwnership-verify-list` | `ownership-verify-list` | готовая `List<String>` CMS PEM → verify |
| `runAll` | `all` | Все `.p12` сценарии (**без** cloud-config) |

С `--args` можно передать только пути (имя команды подставится автоматически):

```bash
./gradlew :samples:registry-examples:runRemove-cert --args="in.p12 config.json out.p12"
./gradlew :samples:registry-examples:runCloud-config --args="mob-dev-cloud_config.json config.json"
```

Эквивалент через `run`:

```bash
./gradlew :samples:registry-examples:run --args="cloud-config mob-dev-cloud_config.json config.json"
```

### Необходимые файлы

| Файл / каталог | Нужен для |
|----------------|-----------|
| `demo-original-container.p12` | parse, verify, analyze, update-registry |
| `config.json` + `certs/` | build, add/remove, resign / sign-tbox |
| `mob-dev-cloud_config.json` | cloud-config / cloud-config-trust |
| `resp-context.json` | cloud-config-from-context (invitation draft) |
| `owner-empty-config.json` | empty-owner (`safeBags: []`) |
| `certs/ATOM Ownership CA.pem` | PKIX intermediate (trust) |
| `certs/ATOM ROOT ext CA.pem` | PKIX trust anchor (trust) |
| `kotlin-out/` | выходные артефакты (создаётся автоматически) |

**Если `P12 not found: demo-original-container.p12`:**

1. Запускайте из каталога `kotlin/`:
   ```bash
   cd kotlin
   ./gradlew :samples:registry-examples:run --args="parse demo-original-container.p12"
   ```
2. Файл должен быть в **корне проекта** (родитель `kotlin/`) или в `kotlin/demo-original-container.p12`.
3. Не используйте битую symlink — нужен обычный файл (~4.6 KB):
   ```bash
   ls -la demo-original-container.p12
   cp kotlin/demo-original-container.p12 demo-original-container.p12   # если ссылка битая
   ```

   cp kotlin/demo-original-container.p12 demo-original-container.p12   # если ссылка битая
   ```

### `.p12` реестры (`registry-examples`)

```bash
cd kotlin

# все .p12 примеры подряд
./gradlew :samples:registry-examples:runAll

# отдельные команды
./gradlew :samples:registry-examples:runParse
./gradlew :samples:registry-examples:runVerify
./gradlew :samples:registry-examples:runAnalyze
./gradlew :samples:registry-examples:runConfig
./gradlew :samples:registry-examples:runBuild
./gradlew :samples:registry-examples:runAdd-cert
./gradlew :samples:registry-examples:runRemove-cert
./gradlew :samples:registry-examples:runUpdate-registry

# с кастомными путями
./gradlew :samples:registry-examples:run --args="add-cert demo-original-container.p12 config.json kotlin-out/updated.p12 0"
./gradlew :samples:registry-examples:run --args="remove-cert kotlin-out/registry-with-added-cert.p12 config.json kotlin-out/after-remove.p12"
./gradlew :samples:registry-examples:run --args="update-registry demo-original-container.p12 config.json kotlin-out/added.p12 kotlin-out/final.p12"
./gradlew :samples:registry-examples:run --args="parse demo-original-container.p12"
./gradlew :samples:registry-examples:run --args="build config.json kotlin-out/my.p12"
```

| Команда | Методы библиотеки |
|---------|-------------------|
| `parse` | `RegistryParser.parse` |
| `verify` | `SignatureVerifier.verifyRegistry`, `verifyContainer`, `tryVerifyRegistry` |
| `analyze` | `RegistryAnalyzer.*` (toText, toJson, toPem, export*) |
| `build` | `RegistryBuilder.buildRegistry`, `ConfigLoader.toBuildConfig` |
| `add-cert` | `RegistryBuilder.addCertificateAndResign` |
| `remove-cert` | `RegistryBuilder.removeCertificateBySkidAndResign` |
| `update-registry` | add + remove + `SgwRegistry` |
| `config` | `ConfigLoader.*`, `PemUtils.getSubjectKeyId` |
| `all` | всё выше |

По умолчанию: P12 = `demo-original-container.p12`, config = `config.json`, export = `kotlin-out/examples-export`.

> **Не путать `remove-cert` и `update-registry`:**
>
> - **`remove-cert`** — одна операция: удалить SafeBag по SKID.
> - **`update-registry`** — add → verify → remove **только что добавленного** (round-trip).

### Cloud configuration (`cloud-config`)

JVM-демо parse / verify / resign. Подробности формата и API — [Cloud configuration (mob-dev)](#cloud-configuration-mob-dev).

```bash
cd kotlin

# parse + verify (mob-dev-cloud_config.json в корне репозитория)
./gradlew :samples:registry-examples:runCloud-config

# свой JSON от облака
./gradlew :samples:registry-examples:run --args="cloud-config path/to/mob-dev-cloud_config.json"

# + resign (config.json) — только переподпись CMS, eContent не пересобирается
./gradlew :samples:registry-examples:run --args="cloud-config mob-dev-cloud_config.json config.json"

# + запись результата
./gradlew :samples:registry-examples:run --args="cloud-config mob-dev-cloud_config.json config.json kotlin-out/mob-dev-cloud_config-resigned.json"
```

| Аргумент | По умолчанию | Назначение |
|----------|--------------|------------|
| `mob-dev.json` | `mob-dev-cloud_config.json` | JSON с `cloud_configuration` |
| `config.json` | — (опционально) | signer cert + key для resign |
| `out.json` | `kotlin-out/mob-dev-cloud_config-resigned.json` | обновлённый `cloud_configuration` |

> **CLI:** у `run` первый аргумент — команда (`cloud-config …`), не голый путь к JSON.  
> Resign **не** меняет `mob-dev-cloud_config.json`; пишет в `out.json`. Signer — из `config.json` (обычно `certs/signer.pem`), не Ownership leaf.

**Что делает `CloudConfigExample.kt`:** parse → `toText` → `verifyCloudConfiguration` → при наличии `config.json` — `resignConfigurationOnly` → запись `out.json`.

```
verifyCloudConfiguration: OK
messageDigest check: OK
signature check: OK
resign with config signer: OK (resignConfigurationOnly)
```

Исходник: `samples/registry-examples/.../CloudConfigExample.kt`.

### Cloud config trust (`cloud-config-trust`)

Пошаговая проверка (identity → UID → PKIX → CMS). Цепочка и CA — [Cloud configuration (mob-dev)](#cloud-configuration-mob-dev).

```bash
cd kotlin

./gradlew :samples:registry-examples:runCloud-config-trust

./gradlew :samples:registry-examples:run --args="cloud-config-trust mob-dev-cloud_config.json 79079999999 d231b684-82b4-4fdc-83dd-fc9a1861c293"

./gradlew :samples:registry-examples:run --args="cloud-config-trust kotlin-out/mob-dev-cloud_config-resigned.json 79079999999 d231b684-82b4-4fdc-83dd-fc9a1861c293"
```

> У `run` первый аргумент — имя команды. У `runCloud-config-trust` команда подставляется сама.  
> Для исходного owner-leaf PKIX OK (с Ownership + ROOT ext в `certs/`). Для resigned test-signer — обычно FAIL на 2a/2b.

Исходник: `CloudConfigTrustExample.kt`, PKIX — `JvmCertificateTrust.kt`.

### Invitation → TBOX + FQDN (`cloud-config-from-context`)

Из `resp-context.json` собирает camelCase TBOX с CES FQDN и CMS-подписью.

```bash
cd kotlin

./gradlew :samples:registry-examples:runCloud-config-from-context

./gradlew :samples:registry-examples:run \
  --args="cloud-config-from-context resp-context.json config.json 5"

# свой путь выхода
./gradlew :samples:registry-examples:run \
  --args="cloud-config-from-context resp-context.json config.json 5 kotlin-out/my-tbox.json"
```

Выход: `kotlin-out/cloud-config-tbox.json` (+ `.envelope.json`).  
Исходник: `CloudConfigFromContextExample.kt`.

### Подпись на фикстурах (`sign-cloud-config`)

OK-фикстура → binding (FQDN + SAN + EKU) → resign; `resp-context` → `buildAndSign` с `owner_id` в FQDN; негатив `a1-…`.

```bash
cd kotlin
./gradlew :samples:registry-examples:runSign-cloud-config

# defaults: cloud-config.json + resp-context.json + config.json
# → kotlin-out/cloud-config-signed-fixture.json|.pem
# → kotlin-out/cloud-config-signed-fixture-from-context.json|.pem|-tbox.json
```

| Fixture | Роль |
|---------|------|
| `cloud-config.json` | OK: owner_id = FQDN = SAN, EKU Email Protection |
| `resp-context.json` | invitation → CMS |
| `a1-cloud-config-signed.json` | FAIL: UID ≠ FQDN |

Demo `config.json` signer без Ownership SAN → `requireOwnerBinding` выкл.; в production — Ownership leaf.

### Ownership CSR (`gen-ownership-csr`)

PKCS#10 CSR для Ownership leaf: EKU Email Protection + SAN `atombus:/user/{ownerId}`.

```bash
cd kotlin
./gradlew :samples:registry-examples:runGen-ownership-csr

./gradlew :samples:registry-examples:run --args="gen-ownership-csr \
  d231b684-82b4-4fdc-83dd-fc9a1861c293 \
  certs/signer-key.pem \
  kotlin-out/ownership.csr.pem"

openssl req -in ../kotlin-out/ownership.csr.pem -noout -text -verify
```

| Аргумент | По умолчанию |
|----------|--------------|
| ownerId | `d231b684-82b4-4fdc-83dd-fc9a1861c293` |
| key.pem | `certs/signer-key.pem` (SEC1 с `publicKey [1]`) |
| out | `kotlin-out/ownership.csr.pem` (+ `.der`) |

API: `OwnershipCsr` — [API.md](kotlin/API.md#ownership-csr--ownershipcsr). Исходник: `GenOwnershipCsrExample.kt`.

### Ownership ledger (`ownership-verify` / `ownership-verify-list`)

Два JVM-примера одного API `verify(ownershipRegistryCms, ownerId, vin)`:

| CLI | Вход | Метод в `OwnershipVerifyExample` |
|-----|------|----------------------------------|
| `ownership-verify` | JSON `ownership-resp.json` → извлечь массив | `run` → `runFromCmsList` |
| `ownership-verify-list` | готовые PEM → `List<String>` | `runFromPemFiles` → `runFromCmsList` |

```bash
cd kotlin

# A) JSON invitation (все аргументы явно)
./gradlew :samples:registry-examples:runOwnership-verify
./gradlew :samples:registry-examples:run --args="ownership-verify \
  ownership-resp.json \
  7f9fc821-a09e-4f96-badc-643daca070c6 \
  AAABBBCCC3"

# B) только List<String> из PEM-файлов
./gradlew :samples:registry-examples:runOwnership-verify-list
./gradlew :samples:registry-examples:run --args="ownership-verify-list \
  7f9fc821-a09e-4f96-badc-643daca070c6 AAABBBCCC3 \
  kotlin-out/ownership-stmt-0.pem kotlin-out/ownership-stmt-1.pem"
```

| Аргумент | Default (fixture) |
|----------|-------------------|
| ownerId | `7f9fc821-a09e-4f96-badc-643daca070c6` |
| vin | `AAABBBCCC3` |
| cms PEM (list) | `kotlin-out/ownership-stmt-*.pem` (создаются из JSON при отсутствии) |

Примеры показывают `tryVerify` / `verify` / `SgwRegistry.verifyOwnershipRegistry` и негативы (неверный ownerId / VIN).  
API: [API.md — Ownership ledger](kotlin/API.md#ownership-ledger--ownershipregistryverifier). Исходник: `OwnershipVerifyExample.kt`.

### Подпись TBOX (`sign-tbox`)

TBOX JSON → `cloud_config_pem` (CMS PEM). При `vin` + `fqdnId` пересчитывает FQDN по CES §5.

```bash
cd kotlin

./gradlew :samples:registry-examples:runSign-tbox

./gradlew :samples:registry-examples:run --args="sign-tbox \
  kotlin-out/cloud-config-tbox.json config.json kotlin-out/cloud-config-tbox-signed \
  EAY1F1C56T2000014 2281305f-4b16-4a49-989a-9abeeac2df20 9c1dc2f4-a015-46b7-b88f-a9e30d0a9f86"
```

Выход: `kotlin-out/cloud-config-tbox-signed.pem` (+ `.envelope.json`).  
Исходник: `SignTboxCloudConfigExample.kt`.

### Empty owner.p12 (`empty-owner` / `empty-owner-unsigned`)

```bash
cd kotlin

./gradlew :samples:registry-examples:runEmpty-owner
./gradlew :samples:registry-examples:run --args="empty-owner owner-empty-config.json kotlin-out/owner.p12"

# без подписи: SafeContents.der + header.json
./gradlew :samples:registry-examples:run --args="empty-owner-unsigned kotlin-out/owner-unsigned"
```

| Команда | Результат |
|---------|-----------|
| `empty-owner` | валидный PFX v3 + CMS, `safeBags: []` |
| `empty-owner-unsigned` | только `*.safecontents.der` + `*.header.json` |

### `build-registry-example` (минимальный CLI)

```bash
# Сборка реестра
./gradlew :samples:build-registry-example:run --args="-config config.json -output kotlin-out/regular-dast.p12"

# Анализ .p12
./gradlew :samples:build-registry-example:runAnalyze --args="demo-original-container.p12"

# add / remove
./gradlew :samples:build-registry-example:runUpdateAdd
./gradlew :samples:build-registry-example:runUpdateRemove
```

### Проверка тестами (JVM / iOS / Android)

```bash
cd kotlin

# JVM
./gradlew :sgw-registry:jvmTest

# iOS (simulator)
./gradlew :sgw-registry:iosSimulatorArm64Test

# Android (unit)
./gradlew :sgw-registry:testDebugUnitTest

# все платформы
./gradlew :sgw-registry:jvmTest :sgw-registry:iosSimulatorArm64Test :sgw-registry:testDebugUnitTest
```

Исходники примеров:
- `samples/registry-examples/.../AddCertificateExample.kt`
- `samples/registry-examples/.../RemoveCertificateExample.kt`
- `samples/registry-examples/.../UpdateRegistryExample.kt`
- `samples/registry-examples/.../CloudConfigExample.kt`
- `samples/registry-examples/.../CloudConfigTrustExample.kt`
- `samples/registry-examples/.../CloudConfigFromContextExample.kt`
- `samples/registry-examples/.../SignTboxCloudConfigExample.kt`
- `samples/registry-examples/.../SignCloudConfigFixtureExample.kt`
- `samples/registry-examples/.../GenOwnershipCsrExample.kt`
- `samples/registry-examples/.../OwnershipVerifyExample.kt`
- `samples/registry-examples/.../EmptyOwnerP12Example.kt`
- `samples/registry-examples/.../EmptyOwnerUnsignedExample.kt`
- `samples/build-registry-example/.../UpdateRegistryMain.kt`

## API

Подробное описание всех классов, методов и моделей — в [API.md](kotlin/API.md).

Краткая сводка:

| Kotlin | Описание |
|--------|----------|
| `RegistryParser.parse(p12Der)` | Разбор .p12 → `RegistryContainer` (immutable bytes) |
| `RegistryParser.parse(p12Der, ParseOptions(strict=true))` | Строгий разбор: любое предупреждение → исключение |
| `SgwRegistry` | Фасад `RegistryParserService` / `RegistryBuilderService` / … |
| `ParseOptions` | Параметры разбора (`strict`) |
| `RegistryBuilder.buildRegistry(cfg)` | Сборка .p12 |
| `RegistryBuilder.buildSafeContents(bags)` | Только eContent (SafeContents) |
| `RegistryBuilder.addCertificateAndResign(request)` | Добавить SafeBag; парсит `existingP12` |
| `RegistryBuilder.addCertificateAndResign(container, request)` | То же без повторного parse (если контейнер уже есть) |
| `RegistryBuilder.removeCertificateBySkidAndResign(request)` | Удалить SafeBag по SKID; парсит `existingP12` |
| `RegistryBuilder.removeCertificateBySkidAndResign(container, request)` | То же без повторного parse |
| `RegistryBuilder.resignWithSafeBags(...)` | Переподпись списка SafeBag; `VerAttribute.requirePresent` |
| `PemEncoding.decodeSkidHex` / `skidToHex` | SKID hex ↔ bytes (**commonMain**, все платформы) |
| `PemUtils.decodeSkidHex` / `skidToHex` | То же на **JVM** (алиас к JCA-утилитам) |
| `AddCertificateRequest` | existingP12, newBag, signerCertDer/Key; `signerAttrs` — только VIN/UID override |
| `RemoveCertificateBySkidRequest` | existingP12, subjectKeyId, signerCertDer/Key; VER не задаётся вручную |
| `VerAttribute` | `parseText`, `formatText`, `bumpForRegistryUpdate`, `resolveForRegistryUpdate` |
| `SignatureVerifier.verifyRegistry(p12Der)` | Проверка подписи ATOM |
| `SignatureVerifier.tryVerifyRegistry(p12Der)` | Проверка без исключения: `Pair<Boolean, String?>` |
| `RegistryAnalyzer.toTextDetailed(c)` | Отчёт с VIN/UID/VER и проверками digest/signature |
| `RegistryAnalyzer.parseAuthenticatedAttributes(bytes)` | Разбор authAttrs из SignerInfo |
| `ConfigLoader.toBuildConfig(...)` | Загрузка config.json → `BuildConfig` (**только JVM**) |
| `BuildConfigFactory` | Сборка `BuildConfig` из JSON/PEM bytes (**все платформы**) |
| `readMainBundleResource` | Чтение файла из iOS bundle по пути (**только iosMain**) |
| `CloudConfigCms.parseMobDevResponse` | JSON mob-dev → DTO |
| `CloudConfigCms.verifyCloudConfiguration` | `cloud_config_json` == eContent + CMS verify |
| `CloudConfigCms.requireIdentity` / `requireOwnerIdInSigner` | vin/owner_id и UID leaf |
| `CloudConfigCms.resignToPem` / `resignConfiguration` | Переподпись с пересборкой eContent из JSON |
| `CloudConfigCms.resignOnly` / `resignConfigurationOnly` | Только переподпись CMS (eContent без изменений) |
| `CloudConfigFromContext.buildAndSign` / `encodeTboxPayload` / `signTboxPayload` | Invitation → TBOX + CMS |
| `CloudBrokerFqdn.hashB` / `buildFqdn` / `resolveBaseDomain` | CES §5 FQDN (`fqdnConstrAlg=1`) |
| `OwnershipCsr.build` / `buildFromEcPrivateKeyPem` / `buildToPem` | PKCS#10 Ownership CSR (EKU + SAN) |
| `OwnershipRegistryVerifier.verify` / `tryVerify` | ledger CMS[]: signatures + p_hash + VIN + ownerId |
| `OwnershipLedgerJson.parse` | `ownership-resp.json` → `OwnershipLedgerResponse` |
| `SgwRegistry.buildOwnershipCsr` / `buildOwnershipCsrFromEcPrivateKeyPem` | Фасад CSR |
| `SgwRegistry.verifyOwnershipRegistry` / `parseOwnershipLedger` | Фасад ledger |
| `SgwRegistry.parseInvitationContext` / `buildCloudConfigurationFromContext` | Фасад invitation → signed DTO |
| `SgwRegistry.parseMobDevCloudConfig` / `…` | Фасад mob-dev CMS |
| `PemEncoding.csrToPem` | DER CSR → PEM `CERTIFICATE REQUEST` |

Поля `RegistryContainer`: `signerCertResolved`, `parseWarnings`, `eContentBytes`, `authenticatedAttributesSetBytes`, `encryptedDigest`.

Разделы: [Cloud configuration (mob-dev)](#cloud-configuration-mob-dev), [Ownership CSR](#ownership-csr-pkcs10), [API.md — Ownership CSR](kotlin/API.md#ownership-csr--ownershipcsr).

## Зависимости

| Зависимость | Где |
|-------------|-----|
| `kotlinx-serialization-json` | commonMain (JSON-отчёты, ConfigLoader на JVM) |
| `kotlinx-datetime` | commonMain (`Instant`, VER, роли) |
| JCA (`java.security`) | jvmMain, androidMain |
| Security.framework | iosMain |

ASN.1/DER — собственный код в commonMain (`AsnReader` / `AsnWriter` / `DerUtils`), без Bouncy Castle.

## Статус

**v2.6.0:** OwnershipCsr (PKCS#10), OwnershipRegistryVerifier (ledger CMS chain / VIN / ownerId), CloudConfigFromContext (invitation → TBOX), CloudBrokerFqdn (CES §5), CLI `gen-ownership-csr` / `ownership-verify*`; CloudConfigCms + KMP jvm / android / ios.  
**v2.5.0:** parse/build/verify `.p12`, CloudConfigCms (mob-dev CMS), KMP jvm / android / ios.

MVP-паритет с реализациями SgwRegistry (.NET / Go) по реестру; cloud configuration — отдельный CMS-формат (не PFX).

---
**ATOM SA Team 2026**
