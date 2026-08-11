# SgwRegistry — справочник API

Документация API библиотеки **com.atom:sgw-registry:2.6.0** (Kotlin Multiplatform).

**Артефакты:** `kotlin/dist/maven/` (KMP: metadata + `-jvm` / `-android` / `-iosarm64` / `-iossimulatorarm64`)  
или плоский JVM JAR `dist/sgw-registry-2.6.0.jar` (только desktop).

## Оглавление

1. [Обзор](#обзор) — KMP-таргеты, source sets, подключение
2. [Модели данных](#модели-данных) — `RegistryContainer`, `BuildConfig`, …
3. [Реестр PKCS#12](#реестр-pkcs12)
   - [Parse — `RegistryParser`](#parse--registryparser)
   - [Build — `RegistryBuilder`](#build--registrybuilder)
   - [Verify — `SignatureVerifier`](#verify--signatureverifier)
   - [Analyze — `RegistryAnalyzer`](#analyze--registryanalyzer)
   - [Config — `BuildConfigFactory` / `ConfigLoader`](#config--buildconfigfactory-commonmain-и-configloader-jvm)
   - [Crypto — `PemEncoding`](#crypto--pemencoding-commonmain) · [`PlatformCrypto`](#crypto--platformcrypto-и-signingkey) · [`PemUtils`](#crypto--pemutils-jvm)
   - [VER — `VerAttribute`](#ver--verattribute)
   - [Converters](#converters--registryconverters)
   - [Фасад — `SgwRegistry`](#фасад--sgwregistry)
   - [ATOM OID](#atom-oid-справочно)
4. [Cloud configuration](#cloud-config--cloudconfigcms-mob-dev)
   - [`CloudConfigCms`](#cloudconfigcms) · [`CloudConfigFromContext`](#cloudconfigfromcontext) · [`CloudBrokerFqdn`](#cloudbrokerfqdn-ces-vehicle-cloud-configuration-212-5)
   - [Invitation → TBOX + CMS](#invitation-context--tbox--cms)
   - [Ownership CSR — `OwnershipCsr`](#ownership-csr--ownershipcsr)
   - [Ownership ledger — `OwnershipRegistryVerifier`](#ownership-ledger--ownershipregistryverifier)
5. [Типичные сценарии](#типичные-сценарии)
6. [JVM-примеры (`registry-examples`)](#jvm-примеры-registry-examples)
   - [Быстрый старт](#быстрый-старт) · [Gradle-задачи](#сокращённые-gradle-задачи)
   - [`cloud-config`](#cloud-configuration-cloud-config) · [`trust`](#cloud-config-trust-cloud-config-trust) · [`from-context`](#invitation--tbox-cloud-config-from-context) · [`sign-tbox`](#подпись-tbox-sign-tbox)
   - [`gen-ownership-csr`](#ownership-csr-gen-ownership-csr) · [`ownership-verify`](#ownership-ledger-ownership-verify) · [`ownership-verify-list`](#ownership-ledger-ownership-verify-list)
7. [Примеры для мобильных платформ](#примеры-для-мобильных-платформ-android--ios--commonmain)
8. [Проверка опубликованного пакета](#проверка-опубликованного-пакета-тесты-и-примеры)
9. [Сводка исключений](#сводка-исключений)

---

## Обзор

Библиотека реализует формат **ATOM-PKCS12-REGISTRY** — PKCS#12 v3 контейнер с CMS SignedData (без macData/пароля), подписанный ECDSA-SHA256.

| Возможность | Описание | Платформы |
|-------------|----------|-----------|
| Parse | Разбор `.p12` → `RegistryContainer` | commonMain (все) |
| Build | Сборка `.p12` из `BuildConfig` | commonMain (все) |
| Verify | Проверка CMS-подписи и messageDigest | commonMain (все) |
| Analyze | Текстовые/JSON отчёты, PEM | commonMain (все) |
| Update | Добавление/удаление SafeBag с auto-bump VER | commonMain (все) |
| Cloud config | mob-dev CMS: parse/verify/resign; invitation → TBOX + CES FQDN; sign-tbox | commonMain (все) |
| Ownership CSR | PKCS#10 CSR (EKU Email Protection + SAN `atombus:/user/{ownerId}`) | commonMain (все) |
| Ownership ledger | цепочка CMS statements: `verify(cmsList, ownerId, vin)` | commonMain (все) |
| Config JSON | `config.json` → `BuildConfig` | **JVM:** `ConfigLoader`; **mobile:** `BuildConfigFactory` + `loadPem` |
| File export | Экспорт PEM на диск | **только JVM** (`RegistryAnalyzerJvm`) для мобильных платфром, хранение данных реестра зависит от мобильной платфромы |

**Требования:** Kotlin 2.0+, JDK 21+ (JVM), Android SDK (Android), Xcode (iOS).  
**Зависимости (common):** `kotlinx-serialization-json`, `kotlinx-datetime`.  
**Криптография:** `expect/actual PlatformCrypto` — JCA на JVM/Android, Security.framework на iOS (`kSecKeyAlgorithmECDSASignatureDigestX962SHA256` для NONEwithECDSA над digest); ASN.1/DER — собственный код в commonMain (**без Bouncy Castle**).

### Kotlin Multiplatform — таргеты и артефакты

| Gradle target | Maven publication | Формат |
|---------------|-------------------|--------|
| `jvm` | `com.atom:sgw-registry-jvm:2.6.0` | JAR |
| `android` | `com.atom:sgw-registry-android:2.6.0` | AAR |
| `iosArm64` | `com.atom:sgw-registry-iosarm64:2.6.0` | `.klib` |
| `iosSimulatorArm64` | `com.atom:sgw-registry-iossimulatorarm64:2.6.0` | `.klib` |
| metadata | `com.atom:sgw-registry:2.6.0` | `.module` + common metadata |

В KMP-проекте зависимость объявляется **один раз** в `commonMain`:

```kotlin
commonMain.dependencies {
    implementation("com.atom:sgw-registry:2.6.0")
}
```

### Распределение API по source sets

| API | commonMain | jvmMain | androidMain | iosMain |
|-----|:----------:|:-------:|:-----------:|:-------:|
| `RegistryParser`, `RegistryBuilder`, `SignatureVerifier`, `RegistryAnalyzer` | ✓ | ✓ | ✓ | ✓ |
| `SgwRegistry`, `PemEncoding`, `VerAttribute`, модели (`BuildConfig`, …) | ✓ | ✓ | ✓ | ✓ |
| `CloudConfigCms`, `CloudConfigFromContext`, `CloudBrokerFqdn` | ✓ | ✓ | ✓ | ✓ |
| `OwnershipCsr`, `OwnershipCsrRequest` / `Result`, `EcSpkiEncoding` | ✓ | ✓ | ✓ | ✓ |
| `OwnershipRegistryVerifier`, `OwnershipLedgerJson` | ✓ | ✓ | ✓ | ✓ |
| `SigningKey`, `PlatformCrypto` (expect/actual) | expect | actual (JCA) | actual (JCA) | actual (SecKey) |
| `BuildConfigFactory`, `RegistryConfig` | ✓ | ✓ | ✓ | ✓ |
| `ConfigLoader`, `PemUtils` | — | ✓ | — | — |
| `RegistryAnalyzerJvm` | — | ✓ | — | — |
| `buildConfigFromJvm`, `addCertificateRequestFromJvm`, … | — | ✓ | — | — |

**Примечание:** в `commonMain` не используйте `java.*`, `ConfigLoader` или `PemUtils`. На мобильных, релаизация через собственые классы и структуры: `BuildConfigFactory` + PEM в `ByteArray` (assets/bundle/API).

### Подключение

```kotlin
// KMP — commonMain (Android + iOS + JVM)
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
```

```kotlin
// JVM-only
dependencies {
    implementation("com.atom:sgw-registry:2.6.0")
}
```

```kotlin
// Импорты — commonMain (все платформы)
import com.atom.sgwregistry.api.SgwRegistry
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.verifier.SignatureVerifier
import com.atom.sgwregistry.analyzer.RegistryAnalyzer
import com.atom.sgwregistry.cloudconfig.CloudConfigCms
import com.atom.sgwregistry.cloudconfig.CloudConfigFromContext
import com.atom.sgwregistry.cloudconfig.CloudBrokerFqdn
import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.crypto.PlatformCrypto

// Только JVM / CLI:
import com.atom.sgwregistry.config.ConfigLoader
import com.atom.sgwregistry.crypto.PemUtils
```

### Точки входа

Два способа вызова API:

1. **Фасад** `SgwRegistry` — единый object, реализует интерфейсы сервисов.
2. **Специализированные object-ы** — `RegistryParser`, `RegistryBuilder`, `SignatureVerifier`, `RegistryAnalyzer` (все платформы); `ConfigLoader`, `PemUtils` (**только JVM**); `VerAttribute`.

Пакеты `com.atom.sgwregistry.internal.*` и низкоуровневый ASN.1 (`asn1.*`) предназначены для внутреннего использования; стабильный контракт — пакеты `api`, `model`, `parser`, `builder`, `verifier`, `analyzer`, `cloudconfig`, `crypto`.

---

## Модели данных

Пакет: `com.atom.sgwregistry.model`

### `RegistryContainer`

Результат разбора `.p12`. Все поля `ByteArray` — **иммутабельные копии** (через `RegistryContainer.immutable()`).

| Поле | Тип | Описание |
|------|-----|----------|
| `pfxVersion` | `Int` | Версия PFX (ожидается `3`) |
| `contentType` | `String` | OID contentType (обычно `pkcs7-signedData`) |
| `certificatesDer` | `List<ByteArray>` | Сертификаты из SignedData |
| `safeBagInfos` | `List<SafeBagInfo>` | SafeBag из eContent |
| `signerCertDer` | `ByteArray?` | DER сертификата подписанта |
| `eContentBytes` | `ByteArray?` | SafeContents (подписываемые данные) |
| `authenticatedAttributesSetBytes` | `ByteArray?` | SET authenticatedAttributes |
| `encryptedDigest` | `ByteArray?` | ECDSA-подпись (DER) |
| `digestAlgorithmOid` | `IntArray?` | OID digest (SHA-256) |
| `signatureAlgorithmOid` | `IntArray?` | OID signature (ecdsaWithSHA256) |
| `firstSignerSidTag` | `Int` | Тег SignerIdentifier (`0xA0` = SKID) |
| `signerCertResolved` | `Boolean` | Подписант найден по SKID или issuerAndSerial |
| `parseWarnings` | `List<String>` | Предупреждения при мягком разборе |

```kotlin
val immutable = RegistryContainer.immutable(container)
```

### `SafeBagInfo`

Информация о одном SafeBag после разбора.

| Поле | Тип | Описание |
|------|-----|----------|
| `roleName` | `String` | Имя роли (ATOM) |
| `roleNotBefore`, `roleNotAfter` | `Instant` | Период действия роли |
| `localKeyId` | `ByteArray?` | localKeyID атрибут |
| `certValueDer` | `ByteArray?` | DER сертификата роли |
| `certSummary` | `CertSummary?` | Краткие поля X.509 |
| `bagId`, `certId`, `certTypeName` | `String` | OID-идентификаторы |

### `SafeBagInput`

Вход для сборки SafeBag.

```kotlin
data class SafeBagInput(
    val certDer: ByteArray,
    val roleName: String = "",
    val roleNotBefore: Instant = Instant.EPOCH,
    val roleNotAfter: Instant = Instant.EPOCH,
    val localKeyId: ByteArray? = null,
)
```

### `SignerAttrs`

ATOM authenticatedAttributes подписанта.

```kotlin
data class SignerAttrs(
    val vin: String = "",
    val verTimestamp: Instant = EPOCH_INSTANT,  // kotlinx.datetime
    val verVersion: Int = 0,
    val uid: String = "",
)
```

### `BuildConfig`

Полная конфигурация для `buildRegistry` (multiplatform).

> **Не путать** с Android `BuildConfig` из Gradle.  
> Это **доменная модель** в `commonMain` (`com.atom.sgwregistry.model.BuildConfig`) — всё, что нужно для сборки или переподписи `.p12` реестра.

| Слой | Класс / пакет | Платформы |
|------|----------------|-----------|
| Модель | `model.BuildConfig` | commonMain (JVM, Android, iOS) |
| Фабрика | `config.BuildConfigFactory` | commonMain |
| JSON-схема | `RegistryConfig`, `SafeBagConfigEntry` | commonMain |
| Загрузка с диска | `ConfigLoader.toBuildConfig(...)` | **только JVM** |
| JVM-удобства | `buildConfigFromJvm(...)` | **только JVM** |

Все поля — кроссплатформенные типы: `ByteArray`, `SigningKey` (expect/actual), `Instant` (kotlinx-datetime). Без `java.io`, `X509Certificate`, `Context`.

```kotlin
data class BuildConfig(
    val signerCertDer: ByteArray,
    val signerKey: SigningKey,
    val vin: String,
    val verTimestamp: Instant,
    val verVersion: Int,
    val uid: String,
    val safeBags: List<SafeBagInput>,
)
```

#### Как получить `BuildConfig` (KMP)

| Платформа | Способ |
|-----------|--------|
| **Android / iOS / commonMain** | `BuildConfigFactory` + `loadPem` (assets/bundle/API), `toBuildConfigFromInlinePem`, прямые PEM `ByteArray`, или вручную `BuildConfig(...)` |
| **JVM** | `ConfigLoader.readConfig` + `toBuildConfig` (файлы на диске) или `buildConfigFromJvm` (JCA) |

Подробнее: раздел [Config — BuildConfigFactory](#config--buildconfigfactory-commonmain-и-configloader-jvm).

#### Как используется после создания

| Задача | API | Что передаётся |
|--------|-----|----------------|
| Сборка нового `.p12` | `RegistryBuilder.buildRegistry(cfg)` | весь `BuildConfig` |
| Добавить SafeBag | `RegistryBuilder.addCertificateAndResign(AddCertificateRequest(...))` | из `BuildConfig`: `signerCertDer`, `signerKey`; `newBag` — элемент `safeBags` |
| Удалить по SKID | `RegistryBuilder.removeCertificateBySkidAndResign(RemoveCertificateBySkidRequest(...))` | из `BuildConfig`: `signerCertDer`, `signerKey`; `subjectKeyId` — отдельно |

```kotlin
// add/remove — поля подписанта из buildConfig, не весь объект BuildConfig
RegistryBuilder.addCertificateAndResign(
    AddCertificateRequest(
        existingP12 = existingP12,
        newBag = buildConfig.safeBags[0],
        signerCertDer = buildConfig.signerCertDer,
        signerKey = buildConfig.signerKey,
    ),
)
```

**JVM:** `buildConfigFromJvm(signerCert: X509Certificate, signerKey: PrivateKey, …)` в пакете `com.atom.sgwregistry.model`.

**Android / iOS:** предпочтительно через `BuildConfigFactory` (см. ниже); либо вручную из `ByteArray`:

```kotlin
val signerCertDer = PemEncoding.decodePemOrDer(signerCertPemBytes)
val signerKey = PlatformCrypto.parseEcPrivateKey(signerKeyPemBytes)
val cfg = BuildConfig(
    signerCertDer = signerCertDer,
    signerKey = signerKey,
    vin = "...",
    verTimestamp = Instant.parse("2024-01-01T00:00:00Z"),
    verVersion = 1,
    uid = "...",
    safeBags = listOf(/* SafeBagInput */),
)
```
### `AddCertificateRequest`

```kotlin
data class AddCertificateRequest(
    val existingP12: ByteArray,
    val newBag: SafeBagInput,
    val signerCertDer: ByteArray,
    val signerKey: SigningKey,
    val signerAttrs: SignerAttrs? = null,
    val rejectDuplicateCert: Boolean = true,
)
```

**JVM:** `addCertificateRequestFromJvm(…)` — обёртка с `X509Certificate` / `PrivateKey`.

### `RemoveCertificateBySkidRequest`

```kotlin
data class RemoveCertificateBySkidRequest(
    val existingP12: ByteArray,
    val subjectKeyId: ByteArray,
    val signerCertDer: ByteArray,
    val signerKey: SigningKey,
    val signerAttrs: SignerAttrs? = null,
    val removeAllMatches: Boolean = false,
)
```

**JVM:** `removeCertificateBySkidRequestFromJvm(…)` — обёртка с `X509Certificate` / `PrivateKey`.

SKID сопоставляется с `localKeyID` SafeBag и расширением Subject Key Identifier (`2.5.29.14`).

### `CertSummary`

Краткая сводка X.509: `subject`, `issuer`, `serial`, `notBefore`, `notAfter`, `keyAlg`.

---

## Реестр PKCS#12

API контейнера **ATOM-PKCS12-REGISTRY** (`.p12` / PFX v3 + CMS SignedData): parse → build → verify → analyze → update.  
Cloud configuration (отдельный CMS, не PFX) — [ниже](#cloud-config--cloudconfigcms-mob-dev).

## Parse — `RegistryParser`

Пакет: `com.atom.sgwregistry.parser`  
Интерфейс: `RegistryParserService`

```kotlin
object RegistryParser : RegistryParserService
```

### Методы

```kotlin
fun parse(p12Der: ByteArray): RegistryContainer
fun parse(p12Der: ByteArray, options: ParseOptions = ParseOptions()): RegistryContainer
```

### `ParseOptions`

```kotlin
data class ParseOptions(
    val strict: Boolean = false,  // true → любое parseWarnings → IllegalStateException
)
```

### Поведение

- Ожидается PFX version `3`, contentType `pkcs7-signedData`.
- При `strict = false` некритичные проблемы попадают в `parseWarnings` (пропущенные bag, несовпадение SKID и т.д.).
- При `strict = true` разбор прерывается с `IllegalStateException`.
- Пустой вход → `IllegalArgumentException("Empty PFX data")`.

---

## Build — `RegistryBuilder`

Пакет: `com.atom.sgwregistry.builder`  
Интерфейс: `RegistryBuilderService`

```kotlin
object RegistryBuilder : RegistryBuilderService
```

### Методы

| Метод | Возврат | Описание |
|-------|---------|----------|
| `buildRegistry(cfg: BuildConfig)` | `ByteArray` | Полная сборка `.p12` |
| `buildSafeContents(safeBags: List<SafeBagInput>)` | `ByteArray` | Только eContent (SEQUENCE OF SafeBag) |
| `addCertificateAndResign(request)` | `ByteArray` | Парсит `existingP12`, добавляет SafeBag, переподписывает |
| `addCertificateAndResign(container, request)` | `ByteArray` | То же без повторного parse |
| `removeCertificateBySkidAndResign(request)` | `ByteArray` | Удаляет SafeBag по SKID, переподписывает |
| `removeCertificateBySkidAndResign(container, request)` | `ByteArray` | То же без повторного parse |
| `resignWithSafeBags(safeBags, signerCertDer, signerKey, attrs)` | `ByteArray` | Переподпись готового списка SafeBag |

### Перегрузки JVM (`com.atom.sgwregistry.model`)

Доступны только на **JVM** — принимают `X509Certificate` / `PrivateKey` вместо `ByteArray` / `SigningKey`:

```kotlin
fun buildConfigFromJvm(
    signerCert: X509Certificate,
    signerKey: PrivateKey,
    vin: String,
    verTimestamp: Instant,
    verVersion: Int,
    uid: String,
    safeBags: List<SafeBagInput>,
): BuildConfig

fun addCertificateRequestFromJvm(
    existingP12: ByteArray,
    newBag: SafeBagInput,
    signerCert: X509Certificate,
    signerKey: PrivateKey,
    signerAttrs: SignerAttrs? = null,
): AddCertificateRequest

fun RegistryBuilder.addCertificateAndResign(
    existingP12: ByteArray,
    newBag: SafeBagInput,
    signerCert: X509Certificate,
    signerKey: PrivateKey,
    signerAttrs: SignerAttrs? = null,
): ByteArray

fun RegistryBuilder.removeCertificateBySkidAndResign(
    existingP12: ByteArray,
    subjectKeyId: ByteArray,
    signerCert: X509Certificate,
    signerKey: PrivateKey,
    signerAttrs: SignerAttrs? = null,
    removeAllMatches: Boolean = false,
): ByteArray

fun RegistryBuilder.removeCertificateBySkidAndResign(
    existingP12: ByteArray,
    subjectKeyIdHex: String,
    signerCert: X509Certificate,
    signerKey: PrivateKey,
    signerAttrs: SignerAttrs? = null,
    removeAllMatches: Boolean = false,
): ByteArray
```

### Цепочка сборки

```
SafeContents → SHA-256 → authenticatedAttributes (contentType, VIN, VER, UID, messageDigest)
  → canonical SET → SHA-256 → ECDSA → SignedData → ContentInfo → PFX v3
```

### VER при изменении реестра

| Операция | Поведение VER |
|----------|---------------|
| `buildRegistry` | VER из `BuildConfig` / `config.json` (`verTimestamp`, `verVersion`; V ≥ 1) |
| `addCertificateAndResign` | VER из исходного `.p12` → **V{n+1}**, timestamp = now UTC |
| `removeCertificateBySkidAndResign` | то же |
| `resignWithSafeBags` | `VerAttribute.requirePresent(attrs)` — VER обязателен |

`signerAttrs` в add/remove может переопределить только **VIN** и **UID**; VER всегда инкрементируется автоматически.

---

## Verify — `SignatureVerifier`

Пакет: `com.atom.sgwregistry.verifier`  
Интерфейс: `SignatureVerifierService`

```kotlin
object SignatureVerifier : SignatureVerifierService
```

### Методы

```kotlin
fun verifyRegistry(p12Der: ByteArray)
fun verifyContainer(c: RegistryContainer)
fun tryVerifyRegistry(p12Der: ByteArray): Pair<Boolean, String?>
```

### Алгоритм проверки

1. Извлечь `authenticatedAttributes` (SET) из SignerInfo.
2. Построить канонический DER SET (сортировка атрибутов).
3. `SHA-256(canonical SET)` → digest для ECDSA.
4. Проверить `encryptedDigest` публичным ключом сертификата подписанта.

### Поддерживаемые алгоритмы

- Digest: **SHA-256** (`2.16.840.1.101.3.4.2.1`)
- Signature: **ecdsaWithSHA256** (`1.2.840.10045.4.3.2`)

### Исключения (`verifyRegistry` / `verifyContainer`)

| Ситуация | Исключение |
|----------|------------|
| Нет authenticatedAttributes | `IllegalStateException` |
| Нет encryptedDigest | `IllegalStateException` |
| Не найден сертификат подписанта | `IllegalStateException` |
| Неподдерживаемый алгоритм | `IllegalStateException` |
| Подпись не совпадает | `IllegalStateException: Signature verification failed` |

`tryVerifyRegistry` не бросает исключения — возвращает `(false, message)`.

---

## Analyze — `RegistryAnalyzer`

Пакет: `com.atom.sgwregistry.analyzer`  
Интерфейс: `RegistryAnalyzerService`

```kotlin
object RegistryAnalyzer : RegistryAnalyzerService
```

### Методы

| Метод | Возврат | Описание |
|-------|---------|----------|
| `verifyRegistry(p12Der)` | `Unit` | Делегирует `SignatureVerifier` |
| `toText(c)` | `String` | Краткий текстовый отчёт |
| `toTextDetailed(c, useColor, skipVerify)` | `String` | Полный отчёт с VIN/UID/VER |
| `toJson(c)` | `ByteArray` | JSON (pretty-print) |
| `toPem(c)` | `ByteArray` | PEM всех сертификатов |
| `toSafeBagsPem(c)` | `ByteArray` | PEM сертификатов SafeBag |
| `signerCertPem(c)` | `ByteArray` | PEM сертификата подписанта |
| `parseAuthenticatedAttributes(setBytes)` | `List<Pair<String, String>>` | Разбор authAttrs |

### JVM file I/O — `RegistryAnalyzerJvm`

Пакет: `com.atom.sgwregistry.analyzer` — **только jvmMain** (desktop/CLI)

| Метод | Описание |
|-------|----------|
| `verifyRegistryFile(path)` | Проверка `.p12` по пути |
| `exportCertificatesToDir(c, dir)` | Запись `cert-N.pem` |
| `exportSafeBagCertsToDir(c, dir)` | PEM сертификатов SafeBag |

### `toTextDetailed`

Параметры:
- `useColor` — зарезервирован (по умолчанию `false`)
- `skipVerify` — не выполнять проверку подписи в отчёте

Отчёт включает секции: PFX, Certificates, Подписант, SafeContents, Parse warnings, Signers and ATOM attributes.

---

## Config — `BuildConfigFactory` (commonMain) и `ConfigLoader` (JVM)

Пакет: `com.atom.sgwregistry.config`

### Роль в KMP

`BuildConfigFactory` создаёт `BuildConfig` на **всех** платформах без `java.io`.  
`ConfigLoader` — JVM-обёртка: читает `config.json` и PEM с диска, затем делегирует в `BuildConfigFactory`.

```
RegistryConfig (JSON)
        │
        ├─ JVM: ConfigLoader.readConfig + toBuildConfig(configDir)
        │
        └─ Mobile: BuildConfigFactory.parseConfig + toBuildConfig(loadPem)
                    loadPem ← assets / NSBundle / API / secure storage
        │
        ▼
   BuildConfig (commonMain)
        │
        ├─ RegistryBuilder.buildRegistry(buildConfig)     — новый .p12
        └─ add/remove: signerCertDer + signerKey из buildConfig
                       + newBag / subjectKeyId отдельно
```

JVM-отладка тех же сценариев: `samples/registry-examples/` (`./gradlew :samples:registry-examples:runAll`).

### `BuildConfigFactory` — все платформы (Android / iOS / JVM)

Замена `ConfigLoader` на мобильных: без `java.io`, только `ByteArray` и JSON.

```kotlin
object BuildConfigFactory
```

| Метод | Описание |
|-------|----------|
| `parseConfig(jsonText)` | Десериализация JSON → `RegistryConfig` |
| `toBuildConfig(vin, uid, ver…, signerCertPem, signerKeyPem, safeBags)` | Прямая сборка из PEM bytes (без JSON) |
| `toBuildConfig(cfg, loadPem)` | JSON с путями; `loadPem("certs/signer.pem")` — assets/bundle/API |
| `toBuildConfigFromInlinePem(cfg)` | JSON с `signerCertPem` / `certPem` inline (ответ backend) |
| `decodeLocalKeyId(s)` | Hex SKID → bytes |
| `parseRfc3339(s)` | RFC3339 → `Instant` |

#### Способы получить `BuildConfig` (commonMain)

**1. JSON + `loadPem`** — типично для Android/iOS:

```kotlin
val cfg = BuildConfigFactory.parseConfig(configJsonText)
val buildConfig = BuildConfigFactory.toBuildConfig(cfg) { path ->
    // Android: context.assets.open(path).use { it.readBytes() }
    // iOS: readMainBundleResource(path)  — com.atom.sgwregistry.util (iosMain)
    loadPem(path)
}
```

Подробные iOS-примеры (4 варианта, add/remove): [iOS — BuildConfigFactory](#ios--buildconfigfactory-и-загрузка-ресурсов).

**2. JSON с inline PEM** — ответ бэкенда:

```kotlin
val buildConfig = BuildConfigFactory.toBuildConfigFromInlinePem(cfg)
```

**3. Прямо из `ByteArray`** — без JSON:

```kotlin
val buildConfig = BuildConfigFactory.toBuildConfig(
    vin = "EAY2AT0MPS2013376",
    uid = "client@example.com",
    verTimestamp = Instant.parse("2024-01-01T00:00:00Z"),
    verVersion = 100,
    signerCertPem = signerCertBytes,
    signerKeyPem = signerKeyBytes,
    safeBags = listOf(SafeBagPemInput(...)),
)
```

```kotlin
data class SafeBagPemInput(
    val certPem: ByteArray,
    val roleName: String,
    val roleNotBefore: Instant,
    val roleNotAfter: Instant,
    val localKeyId: ByteArray? = null,
)
```

См. раздел [Примеры для мобильных платформ](#примеры-для-мобильных-платформ-android--ios--commonmain).

### `ConfigLoader` — только JVM (desktop/CLI)

Читает `config.json` с диска и делегирует в `BuildConfigFactory`. На Android/iOS **не используется** — там только `BuildConfigFactory` + `loadPem`.

### Модели JSON (`RegistryConfig` — commonMain)

```kotlin
data class RegistryConfig(
    val signerCert: String = "",
    val signerKey: String = "",
    val signerCertPem: String? = null,
    val signerKeyPem: String? = null,
    val vin: String = "",
    val verTimestamp: String = "",
    val verVersion: Int = 0,
    val uid: String = "",
    val safeBags: List<SafeBagConfigEntry> = emptyList(),
)

data class SafeBagConfigEntry(
    val cert: String = "",
    val certPem: String? = null,
    val roleName: String = "",
    val roleNotBefore: String = "",
    val roleNotAfter: String = "",
    val localKeyID: String? = null,
)
```

Относительные пути в JSON разрешаются через `loadPem` (на JVM — от каталога config.json).

### Методы ConfigLoader только для JVM

| Метод | Описание |
|-------|----------|
| `readConfig(configPath: String)` | Чтение и десериализация JSON |
| `resolvePath(configDir, path)` | Абсолютный или относительный путь к файлу |
| `validateConfig(cfg, configDir)` | Проверка обязательных полей и существования PEM |
| `toBuildConfig(cfg, configDir)` | Валидация → загрузка PEM → `BuildConfig` |
| `decodeLocalKeyId(s)` | Hex → `ByteArray?` (допускает `0x`, `-`, `:`) |
| `parseRfc3339(s)` | RFC3339 → `Instant` (пустая строка → `EPOCH`) |

### Пример

```kotlin
val configPath = "config.json"
val configDir = Path.of(configPath).parent?.toString() ?: "."
val cfg = ConfigLoader.readConfig(configPath)
val buildCfg = ConfigLoader.toBuildConfig(cfg, configDir)
val p12 = RegistryBuilder.buildRegistry(buildCfg)
```

---

## Crypto — `PemEncoding` (commonMain)

Пакет: `com.atom.sgwregistry.crypto` — **все платформы**, без JCA.

```kotlin
object PemEncoding
```

| Метод | Описание |
|-------|----------|
| `isPem(data)` | Проверка PEM-заголовка |
| `detectPemLabel(pem)` | Метка блока (`CERTIFICATE`, `EC PRIVATE KEY`, `CERTIFICATE REQUEST`, …) |
| `decodePemOrDer(pemOrDer)` | PEM или сырой DER → `ByteArray` |
| `decodePemBlock(pem, label)` | Извлечь и декодировать PEM-блок |
| `certToPem(certDer)` | DER → PEM `CERTIFICATE` |
| `cmsToPem(cmsDer)` | DER → PEM `CMS` |
| `csrToPem(csrDer)` | DER → PEM `CERTIFICATE REQUEST` (Ownership CSR) |
| `decodeSkidHex(hex)` | Hex SKID → bytes |
| `skidToHex(skid)` | bytes → hex |

Используйте на Android/iOS вместо `PemUtils` для работы с PEM/DER и SKID.

---

## Crypto — `PlatformCrypto` и `SigningKey`

Пакет: `com.atom.sgwregistry.crypto` — `expect/actual` по платформам.

```kotlin
expect class SigningKey   // opaque: JCA PrivateKey (JVM/Android) или SecKeyRef (iOS)

object PlatformCrypto {
    fun sha256(data: ByteArray): ByteArray
    fun parseCertificate(der: ByteArray): PlatformCertificate
    fun parseEcPrivateKey(pemOrDer: ByteArray): SigningKey
    fun getSubjectKeyId(cert: PlatformCertificate): ByteArray
    fun signHashEcdsaDer(key: SigningKey, hash: ByteArray): ByteArray
    fun verifyHashEcdsaDer(cert: PlatformCertificate, hash: ByteArray, sigDer: ByteArray): Boolean
}
```

| Платформа | Реализация |
|-----------|------------|
| JVM / Android | JCA: `NONEwithECDSA` над SHA-256 digest |
| iOS | `SecKeyCreateSignature` / `SecKeyVerifySignature` с `kSecKeyAlgorithmECDSASignatureDigestX962SHA256` |

`SigningKey.native` — платформенный объект (`PrivateKey` или `SecKeyRef`); в common-коде не используйте.

Пример загрузки ключа подписанта (commonMain):

```kotlin
val signerKey = PlatformCrypto.parseEcPrivateKey(pemBytes)  // PEM или DER SEC1 / PKCS#8
val signerCertDer = PemEncoding.decodePemOrDer(certPemBytes)
```

---

## Crypto — `PemUtils` (JVM)

Пакет: `com.atom.sgwregistry.crypto` — **только jvmMain** (JCA + `java.io`)

```kotlin
object PemUtils
```

| Метод | Описание |
|-------|----------|
| `loadCertificate(pemOrDer)` | PEM или DER → `X509Certificate` |
| `loadCertificateFromFile(path)` | Файл → сертификат |
| `loadPrivateKey(path)` / `loadPrivateKeyFromPem(pem)` | Приватный ключ EC |
| `loadKeyPair(path)` / `loadKeyPairFromPem(pem)` | `KeyPair` (EC PRIVATE KEY / PKCS#8) |
| `loadFirstPemBlock(path, label)` | Первый PEM-блок → DER |
| `loadFirstPemBlockFromString(pem, label)` | То же из строки |
| `certToPem(certDer)` | DER → PEM-строка |
| `getSubjectKeyId(cert)` | Расширение 2.5.29.14 → bytes |
| `decodeSkidHex(hex)` | Hex SKID → bytes |
| `skidToHex(skid)` | bytes → hex |
| `signHashEcdsaDer(privateKey, hash)` | ECDSA подпись (внутреннее) |
| `verifyHashEcdsaDer(cert, hash, signatureDer)` | ECDSA проверка (внутреннее) |

---

## VER — `VerAttribute`

Пакет: `com.atom.sgwregistry.builder`

```kotlin
object VerAttribute
```

Формат текста: `yyyy-MM-dd HH:mm:ss:V{n}` (пример: `2026-01-19 12:00:00:V102`).

| Метод | Описание |
|-------|----------|
| `formatText(timestamp, version)` | `Instant` + version → строка |
| `parseText(value)` | Строка → `Pair<Instant, Int>`; n > 0 |
| `requirePresent(attrs)` | VER обязателен перед подписью |
| `bumpForRegistryUpdate(attrs)` | V{n} → V{n+1}, timestamp = now UTC |
| `resolveForRegistryUpdate(container, override?)` | Извлечь VER из `.p12`, merge VIN/UID, bump |

---

## Converters — `RegistryConverters`

Пакет: `com.atom.sgwregistry.builder`

```kotlin
object RegistryConverters
```

| Метод | Описание |
|-------|----------|
| `safeBagInfosToInputs(infos)` | `SafeBagInfo` → `SafeBagInput` |
| `bagMatchesSkid(bag, subjectKeyId, certCache?)` | Сопоставление SafeBag по SKID |
| `skidHex(subjectKeyId)` | bytes → hex |
| `extractSignerAttrs(container)` | VIN/UID/VER из authenticatedAttributes |

---

## Фасад — `SgwRegistry`

Пакет: `com.atom.sgwregistry.api`

```kotlin
object SgwRegistry :
    RegistryParserService,
    RegistryBuilderService,
    SignatureVerifierService,
    RegistryAnalyzerService
```

Делегирует вызовы соответствующим object-ам. Подходит для DI и тестов (можно подменить через интерфейсы).

Интерфейсы:
- `RegistryParserService`
- `RegistryBuilderService`
- `SignatureVerifierService`
- `RegistryAnalyzerService`

Дополнительно (mob-dev `cloud_configuration` + invitation → TBOX):

| Метод | Описание |
|-------|----------|
| `parseMobDevCloudConfig(bytes\|text)` | JSON → `MobDevCloudConfigResponse` |
| `parseCloudConfigPem(pemOrDer)` | `cloud_config_pem` → `CloudConfigCmsContainer` |
| `verifyCloudConfigPem(pemOrDer)` | Проверка CMS |
| `verifyCloudConfiguration(dto)` | JSON + CMS end-to-end |
| `requireCloudConfigIdentity(dto, vin, ownerId)` | vin / owner_id |
| `requireCloudConfigOwnerIdInSigner(dto)` | owner_id в UID subject |
| `requireCloudConfigOwnerIdBinding(dto, requireEku=true)` | owner_id ↔ FQDN ↔ SAN URI ↔ EKU Email Protection |
| `requireCloudConfigSignerEku(certDer)` | EKU = Email Protection (не TLS Client Auth) |
| `resignCloudConfigPem(request)` | Переподпись → PEM (eContent из JSON) |
| `resignCloudConfigOnly(container, request)` | Переподпись без пересборки eContent |
| `resignCloudConfiguration(dto, cert, key)` | DTO + новый PEM из JSON |
| `resignCloudConfigurationOnly(dto, cert, key)` | Только `cloud_config_pem` |
| `cloudConfigToText(dto)` | Отчёт для лога/UI |
| `parseInvitationContext(bytes\|text)` | `resp-context.json` → `InvitationContextResponse` |
| `buildCloudConfigurationFromContext(...)` | invitation → signed DTO (CES FQDN + CMS) |
| `buildOwnershipCsr(request, key, publicKeySpki)` | PKCS#10 Ownership CSR → `OwnershipCsrResult` |
| `buildOwnershipCsrFromEcPrivateKeyPem(request, pemOrDer)` | CSR из SEC1/PKCS#8 EC key (нужен `publicKey [1]`) |
| `verifyOwnershipRegistry(cmsList, ownerId, vin)` | Цепочка ownership statements → `Boolean` |
| `tryVerifyOwnershipRegistry(cmsList, ownerId, vin)` | То же → `OwnershipVerifyResult` |
| `verifyOwnershipLedger(response, ownerId, vin?)` | `OwnershipLedgerResponse` → verify (`vin` default = `response.vin`) |
| `tryVerifyOwnershipLedger(response, ownerId, vin?)` | То же → `OwnershipVerifyResult` |
| `parseOwnershipLedger(bytes\|text)` | `ownership-resp.json` → `OwnershipLedgerResponse` |

Подробнее: [Ownership CSR — `OwnershipCsr`](#ownership-csr--ownershipcsr), [Ownership ledger — `OwnershipRegistryVerifier`](#ownership-ledger--ownershipregistryverifier).

---

## ATOM OID (справочно)

| Имя | OID | Назначение |
|-----|-----|------------|
| `atomVin` | `1.3.6.1.4.1.99999.1.1` | VIN в authenticatedAttributes |
| `atomVer` | `1.3.6.1.4.1.99999.1.2` | Версия реестра (GeneralizedTime + INTEGER) |
| `atomUid` | `1.3.6.1.4.1.99999.1.3` | UID |
| `atomRoleName` | `1.3.6.1.4.1.99999.1.4` | Имя роли в SafeBag |
| `atomRoleValidityPeriod` | `1.3.6.1.4.1.99999.1.5` | Период действия роли |

Полный реестр: `com.atom.sgwregistry.asn1.Oids`.

---

## Cloud config — `CloudConfigCms` (mob-dev)

Пакет: `com.atom.sgwregistry.cloudconfig`  
Модели: `com.atom.sgwregistry.model` (`CloudConfigurationDto`, `CloudConfigResignRequest`, …)

Ответ mob-dev (`mob-dev-cloud_config.json` в корне репозитория):

```json
{
  "cloud_configuration": {
    "cloud_config_json": "{...}",
    "cloud_config_pem": "-----BEGIN CMS-----\\n...",
    "vin": "...",
    "owner_id": "..."
  }
}
```

`cloud_config_pem` — CMS SignedData с eContent = байты `cloud_config_json`. Подписант — owner certificate (`issuerAndSerial`, DER ECDSA).

### `CloudConfigurationDto` (mob-dev envelope)

| Поле JSON | Kotlin | Описание |
|-----------|--------|----------|
| `cloud_config_json` | `cloudConfigJson` | camelCase payload (eContent) |
| `cloud_config_pem` | `cloudConfigPem` | CMS PEM |
| `vin` / `owner_id` | `vin` / `ownerId` | identity |
| `root_cas` | `rootCas` | trust anchors брокера (не цепочка CMS-leaf) |
| `base_domain` | `baseDomain` | в envelope; в TBOX FQDN — внутри JSON |

### `CloudConfigCms`

```kotlin
object CloudConfigCms
```

| Метод | Описание |
|-------|----------|
| `parseMobDevResponse(bytes\|text)` | JSON → `MobDevCloudConfigResponse` |
| `parsePem(pem\|pemOrDer)` | CMS → `CloudConfigCmsContainer` |
| `verify(container)` | Проверка CMS-подписи |
| `verifyPem(pemOrDer)` | parse + verify |
| `tryVerify(container)` | `Pair<Boolean, String?>` |
| `verifyJsonMatchesEContent(container, json)` | JSON == eContent |
| `verifyCloudConfiguration(dto)` | json match + CMS verify |
| `requireIdentity(dto, vin, ownerId)` | vin / owner_id == ожидаемые |
| `requireOwnerIdInSigner(dto)` | owner_id в UID subject подписанта |
| `requireOwnerIdBinding(dto\|ownerId, baseDomain, certDer)` | owner_id в FQDN + SAN `atombus:/user/{id}` + EKU Email Protection |
| `requireSignerEkuForCms(certDer)` | EKU must include `1.3.6.1.5.5.7.3.4` (не Client Auth) |
| `extractSanUris` / `extractEkuOids` | SAN URI / EKU OID из leaf DER |
| `resign(request)` | Новый CMS DER |
| `resignToPem(request)` | Новый PEM (`-----BEGIN CMS-----`) — **пересборка eContent из JSON** |
| `resignConfiguration(dto, cert, key)` | DTO с новым `cloud_config_pem` (из JSON) |
| `resignOnly(container, request)` | Переподпись **без пересборки** eContent (байты из CMS) |
| `resignOnlyToPem(...)` | То же → PEM |
| `resignConfigurationOnly(dto, cert, key)` | Только `cloud_config_pem`; JSON не меняется |
| `toText(container\|dto)` | Отчёт для лога/UI |

### `CloudConfigFromContext`

Пакет: `com.atom.sgwregistry.cloudconfig`  
Модели invitation / TBOX: `InvitationContextResponse`, `VehicleCloudConfigurationDraft`, `CloudBrokerConfigPayload`, …

Вход invitation (`resp-context.json`):

```json
{
  "id": "...",
  "vin": "EAY1F1C56T2000014",
  "tenant_id": "2281305f-4b16-4a49-989a-9abeeac2df20",
  "context": {
    "ownership_registry": "-----BEGIN CMS-----...-----END CMS-----",
    "vehicle_cloud_configuration": {
      "current_version": 1,
      "cloud_broker": {
        "root_cas": [ "-----BEGIN CERTIFICATE-----..." ],
        "endpoint": {
          "base_domain": "mqtt.atom.auto",
          "fqdn_constr_alg": 1
        }
      }
    }
  }
}
```

`ownership_registry` на практике часто **PFX v3** (метка `BEGIN CMS`, внутри INTEGER 3 + SignedData), не standalone ContentInfo как у `cloud_config_pem`.

```kotlin
object CloudConfigFromContext
```

| Метод | Описание |
|-------|----------|
| `parseInvitationResponse(bytes\|text)` | JSON → `InvitationContextResponse` |
| `extractOwnerIdFromOwnershipCms(pem)` | UID leaf из `ownership_registry` |
| `extractUidFromSubject(subject)` | UID=… из DN string |
| `buildCloudConfigJson(draft, payloadVersion?, vin?, fqdnIdentityId?)` | snake_case → compact camelCase; при alg=1 — CES FQDN |
| `buildUnsignedConfiguration(response, …, fqdnIdentityId?, fqdnIdentitySource?)` | DTO без `cloud_config_pem` |
| `buildAndSign(…, fqdnIdentitySource?, requireOwnerBinding?)` | payload + CMS; FQDN из `owner_id` / `tenant_id` |
| `resolveFqdnIdentityId(…, fqdnIdentitySource?)` | выбор id для сегмента FQDN |
| `encodeTboxPayload(dto, pretty?)` | только `{ "v", "cloudBroker" }` для TBOX |
| `encodeMobDevResponse(dto)` | `{ "cloud_configuration": … }` |
| `signTboxPayload(json, cert, key, vin?, fqdnIdentityId?, ownerId?)` | TBOX JSON → compact eContent + CMS PEM |
| `toMobDevResponse(dto)` | обёртка `MobDevCloudConfigResponse` |

**`CloudConfigFqdnIdentitySource`:** `OwnerId` (default) · `TenantId` · `OwnerIdThenTenantId` · `TenantIdThenOwnerId`.  
Явный `fqdnIdentityId` перекрывает source. При `TenantId` и `requireOwnerBinding=true` tenant должен совпадать с `owner_id` в FQDN/SAN.

**Выход TBOX (payload):**

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

`cloud_config_json` / eContent CMS — **компактная** сериализация того же объекта.  
`encodeTboxPayload(pretty=true)` — для файла/передачи; байты ≠ eContent, если pretty.

**FQDN по умолчанию в `buildAndSign`:** `tenant_id` из invitation (если непустой), иначе ownership UID.  
Поле DTO `owner_id` всегда = UID leaf из `ownership_registry` (для trust).

### `CloudBrokerFqdn` (CES Vehicle cloud configuration 2.1.2 §5)

```kotlin
object CloudBrokerFqdn {
    const val ALG_HASH_B_VIN_OWNER = 1
}
```

| Метод | Описание |
|-------|----------|
| `hashB(vin)` | SHA-1(ASCII VIN) → последние 4 hex lowercase |
| `buildFqdn(vin, identityId, domainSuffix, alg=1)` | полный FQDN |
| `resolveBaseDomain(vin, identityId, domainOrFqdn, alg=1)` | суффикс → FQDN; уже готовый FQDN не трогает |

Правило `fqdnConstrAlg = 1`:

```
FQDN = hashB(VIN) + "-" + identityId + "." + domainSuffix
```

| Пример CES | Значение |
|------------|----------|
| VIN | `1GNDT13S532183584` |
| hashB | `c602` |
| ownerID | `bdb79393-a9e3-4024-86a8-5f372df9121f` |
| FQDN | `c602-bdb79393-a9e3-4024-86a8-5f372df9121f.mqtt.atom.auto` |

Invitation-пример (`resp-context.json`):  
`hashB(EAY1F1C56T2000014)` = `d06e`, `tenant_id` = `2281305f-…` →  
`d06e-2281305f-4b16-4a49-989a-9abeeac2df20.mqtt.atom.auto`.

В signed / TBOX JSON поле `endpoint.baseDomain` хранит **полный FQDN** (не только `mqtt.atom.auto`).

### Модели invitation / TBOX

| Тип | Назначение |
|-----|------------|
| `InvitationContextResponse` | корень `resp-context.json` (`vin`, `tenant_id`, `context`) |
| `InvitationContextDto` | `ownership_registry`, `vehicle_cloud_configuration`, … |
| `VehicleCloudConfigurationDraft` | snake_case draft брокера |
| `CloudBrokerConfigPayload` | camelCase eContent / TBOX (`v`, `cloudBroker`) |
| `CloudBrokerConfigBody` / `CloudBrokerEndpointPayload` | `rootCAs`, `fqdnConstrAlg`, `baseDomain` |

Парсер: `InvitationContextJson.parse` / `CloudConfigFromContext.parseInvitationResponse`.

### `CloudConfigResignRequest` — пересборка из JSON

```kotlin
data class CloudConfigResignRequest(
    val jsonPayload: String,
    val signerCertDer: ByteArray,
    val signerKey: SigningKey,
    val includeSigningTime: Boolean = true,
    val includeSigningCertificateV2: Boolean = true,
    val useIssuerAndSerialSid: Boolean = true,
)
```

Используйте, когда нужно подписать строку `cloud_config_json` заново (encode UTF-8 → eContent).

### `CloudConfigResignOnlyRequest` — только переподпись

```kotlin
data class CloudConfigResignOnlyRequest(
    val signerCertDer: ByteArray,
    val signerKey: SigningKey,
    val includeSigningTime: Boolean = true,
    val includeSigningCertificateV2: Boolean = true,
    val useIssuerAndSerialSid: Boolean = true,
)
```

eContent берётся из уже разобранного `cloud_config_pem` **как есть** — без `jsonPayload.encodeToByteArray()`.

```kotlin
val container = CloudConfigCms.parsePem(dto.cloudConfigPem)
val newPem = CloudConfigCms.resignOnlyToPem(
    container,
    CloudConfigResignOnlyRequest(signerCertDer, signerKey),
)

// или для всего DTO:
val updated = CloudConfigCms.resignConfigurationOnly(dto, signerCertDer, signerKey)
```

### Типичный сценарий (commonMain — все платформы)

```kotlin
// 1. Parse JSON от backend
val dto = MobDevCloudConfigJson.parse(responseBytes).cloudConfiguration

// 2. Лог / UI
println(CloudConfigCms.toText(dto))

// 3. Verify перед использованием конфигурации
CloudConfigCms.verifyCloudConfiguration(dto)

// 4. Resign — только переподпись CMS (eContent без изменений)
val updated = CloudConfigCms.resignConfigurationOnly(
    dto = dto,
    signerCertDer = ownerCertDer,
    signerKey = signingKey,
)

// Альтернатива: пересборка eContent из JSON (если json менялся)
// CloudConfigCms.resignConfiguration(dto, ownerCertDer, signingKey)
```

### Invitation context → TBOX + CMS

```kotlin
val invitation = CloudConfigFromContext.parseInvitationResponse(respContextBytes)
// endpoint.baseDomain = hashB(vin)-tenant_id.mqtt… (alg=1); owner_id = ownership UID
val signed = CloudConfigFromContext.buildAndSign(
    response = invitation,
    signerCertDer = ownerCertDer,
    signerKey = ownerKey,
    payloadVersion = 5,
)
CloudConfigCms.verifyCloudConfiguration(signed)
CloudConfigCms.requireIdentity(signed, invitation.vin, signed.ownerId)

// для TBOX — только camelCase payload
val tboxJson = CloudConfigFromContext.encodeTboxPayload(signed)

// или подписать уже готовый TBOX-файл:
val (compact, pem) = CloudConfigFromContext.signTboxPayload(
    tboxJson = tboxFileText,
    signerCertDer = ownerCertDer,
    signerKey = ownerKey,
    vin = invitation.vin,
    fqdnIdentityId = invitation.tenantId,
)
```

Через фасад:

```kotlin
import com.atom.sgwregistry.csr.OwnershipCsrRequest

SgwRegistry.parseMobDevCloudConfig(jsonBytes)
SgwRegistry.verifyCloudConfiguration(dto)
SgwRegistry.cloudConfigToText(dto)
SgwRegistry.resignCloudConfigPem(request)
SgwRegistry.resignCloudConfiguration(dto, ownerCertDer, ownerKey)
SgwRegistry.parseInvitationContext(respContextBytes)
SgwRegistry.buildCloudConfigurationFromContext(
    invitation, ownerCertDer, ownerKey,
    payloadVersion = 5,
    fqdnIdentityId = invitation.tenantId, // optional; default = tenant_id / ownership UID
)
SgwRegistry.buildOwnershipCsrFromEcPrivateKeyPem(
    OwnershipCsrRequest(ownerId = "d231b684-…"),
    ecPrivateKeyPem,
)
```

### Cloud config на iOS / Android

- Parse/verify/resign — через `CloudConfigCms` (commonMain).
- Invitation → TBOX / CES FQDN — `CloudConfigFromContext` + `CloudBrokerFqdn` (commonMain).
- Ownership CSR — `OwnershipCsr` (commonMain); на Android/iOS удобнее `build(request, key, publicKeySpki)` с ключом из Keystore/Keychain и SPKI из enrollment.
- `signerKey` — из Keystore (Android) или Keychain (iOS); **не** использовать raw 64-byte P1363 подпись.
- JSON и PEM — из API/backend как `ByteArray` / `String`.

Unit-тесты: `CloudConfigCmsTest`, `CloudConfigFromContextTest`, `CloudBrokerFqdnTest`, `OwnershipCsrTest`.

| Fixture (корень репо) | Назначение |
|-----------------------|------------|
| `mob-dev-cloud_config.json` | OK: owner_id = FQDN = SAN, EKU Email Protection |
| `cloud-config.json` | OK (тот же контракт) |
| `resp-context.json` | invitation → `buildAndSign` / CES FQDN |
| `a1-cloud-config-signed.json` | FAIL: owner_id/UID ≠ UID в `baseDomain` |
| `a-cloud-config-signed.json` | FAIL: EKU = TLS Client Auth (+ mismatch FQDN) |

Перед подписью (`buildAndSign` / `signTboxPayload`, `requireOwnerBinding=true`) библиотека отклоняет mismatch owner_id ↔ FQDN ↔ SAN и неверный EKU.

### Ownership CSR — `OwnershipCsr`

Пакет: `com.atom.sgwregistry.csr`  
Платформы: **commonMain** (JVM / Android / iOS). ASN.1 — `AsnWriter`, подпись — `PlatformCrypto` (**без BouncyCastle**).

PKCS#10 CSR для выдачи Ownership leaf в Cloud PKI. Запрашивает расширения, нужные для последующей подписи CMS `cloud_config_pem` и проверки `requireOwnerIdBinding`.

#### Что попадает в CSR

| Поле | Значение по умолчанию |
|------|------------------------|
| Subject | `O=ATOM`, `OU=Customers`, `OU=EnhancedAuth`, `UID={ownerId}` (PrintableString) |
| KeyUsage | `digitalSignature` (critical) |
| EKU | **Email Protection** `1.3.6.1.5.5.7.3.4` (`clientAuth` выкл.) |
| SAN | `URI:atombus:/user/{ownerId}` |
| Signature | ECDSA-SHA256 (P-256), parameters ABSENT |

> CA может **игнорировать** запрошенный EKU/SAN. После enroll всегда проверяйте leaf: `requireSignerEkuForCms` / `requireOwnerIdBinding`.

#### API

```kotlin
object OwnershipCsr {
    fun buildFromEcPrivateKeyPem(request: OwnershipCsrRequest, ecPrivateKeyPemOrDer: ByteArray): OwnershipCsrResult
    fun build(request: OwnershipCsrRequest, key: SigningKey, publicKeySpki: ByteArray): OwnershipCsrResult
    fun buildToPem(request: OwnershipCsrRequest, ecPrivateKeyPemOrDer: ByteArray): String
}
```

| Тип | Поля |
|-----|------|
| `OwnershipCsrRequest` | `ownerId`, `organization`=`ATOM`, `organizationalUnits`=`[Customers, EnhancedAuth]`, `includeEmailProtectionEku`=`true`, `includeClientAuthEku`=`false`, `includeKeyUsageDigitalSignature`=`true` |
| `OwnershipCsrResult` | `csrDer`, `csrPem` (`BEGIN CERTIFICATE REQUEST`), `publicKeySpki`, `ownerId`, `sanUri` |

Вспомогательно: `EcSpkiEncoding.spkiFromEcPrivateKeyPemOrDer` — SPKI из SEC1/PKCS#8.  
SEC1 `EC PRIVATE KEY` **должен** содержать `publicKey [1]` (как у OpenSSL с именованной кривой).

#### Пример

```kotlin
import com.atom.sgwregistry.csr.OwnershipCsr
import com.atom.sgwregistry.csr.OwnershipCsrRequest
import com.atom.sgwregistry.cloudconfig.CloudConfigCms

val csr = OwnershipCsr.buildFromEcPrivateKeyPem(
    OwnershipCsrRequest(ownerId = "d231b684-82b4-4fdc-83dd-fc9a1861c293"),
    ecPrivateKeyPem,
)
// csr.csrPem → Cloud PKI → Ownership leaf
// После выдачи:
CloudConfigCms.requireSignerEkuForCms(leafCertDer)
// CloudConfigCms.requireOwnerIdBinding(dto)

// через фасад:
SgwRegistry.buildOwnershipCsrFromEcPrivateKeyPem(
    OwnershipCsrRequest(ownerId = "…"),
    ecPrivateKeyPem,
)
```

Проверка артефакта:

```bash
openssl req -in ownership.csr.pem -noout -text -verify
# expect: E-mail Protection + URI:atombus:/user/{ownerId}
```

JVM CLI: [`gen-ownership-csr`](#ownership-csr-gen-ownership-csr).  
Тест: `OwnershipCsrTest`.

### Ownership ledger — `OwnershipRegistryVerifier`

Пакет: `com.atom.sgwregistry.ownership`  
Формат: `context.ownership_registry` = **массив** standalone CMS (fixture `ownership-resp.json`), не один PFX.

Каждый элемент — PEM `-----BEGIN CMS-----` … SignedData; eContent = JSON statement:

```json
{"VIN":"AAABBBCCC3","owner_dn":"UID=…,OU=EnhancedAuth+OU=Customers,O=ATOM","v":1,"p_hash":""}
```

#### Сигнатура API (все аргументы явно)

```kotlin
fun verify(
    ownershipRegistryCms: List<String>, // #1 упорядоченный список CMS PEM
    ownerId: String,                    // #2 UID текущего владельца (последний owner_dn)
    vin: String,                        // #3 VIN автомобиля (единый для цепочки)
): Boolean

fun tryVerify(...): OwnershipVerifyResult
```

Фасад: `SgwRegistry.verifyOwnershipRegistry(cmsList, ownerId, vin)`.

#### Что проверяется

1. Подпись каждого CMS (embedded leaf).
2. `p_hash`: genesis пустой; далее hex(подписи предыдущего CMS).
3. Один `VIN` во всех statements == аргумент `vin`.
4. UID из `owner_dn` **последнего** statement == аргумент `ownerId`.

#### Пример A — структура `ownership-resp.json` → `OwnershipLedgerResponse`

```kotlin
val ledger = OwnershipLedgerJson.parse(ownershipRespBytes)
// или: SgwRegistry.parseOwnershipLedger(bytes)

// vin по умолчанию = ledger.vin (поле верхнего уровня JSON)
val ok = OwnershipRegistryVerifier.verifyLedger(
    response = ledger,
    ownerId = "7f9fc821-a09e-4f96-badc-643daca070c6",
)
// фасад:
SgwRegistry.verifyOwnershipLedger(ledger, ownerId)
```

#### Пример B — только готовый `List<String>` CMS PEM

Когда массив уже есть (API/БД/файлы) — **без** парсинга invitation JSON:

```kotlin
val ownershipRegistryCms: List<String> = listOf(cmsPem0, cmsPem1)

val ok = OwnershipRegistryVerifier.verify(
    ownershipRegistryCms = ownershipRegistryCms,
    ownerId = "7f9fc821-a09e-4f96-badc-643daca070c6",
    vin = "AAABBBCCC3",
)

// фасад:
SgwRegistry.verifyOwnershipRegistry(
    ownershipRegistryCms = ownershipRegistryCms,
    ownerId = "7f9fc821-a09e-4f96-badc-643daca070c6",
    vin = "AAABBBCCC3",
)

// с диагностикой:
val result = OwnershipRegistryVerifier.tryVerify(ownershipRegistryCms, ownerId, vin)
// result.ok / result.reason / result.ownerId / result.vin
```

Модели: `OwnershipStatement`, `OwnershipVerifyResult`, `OwnershipLedgerResponse`.  
CLI: [`ownership-verify`](#ownership-ledger-ownership-verify), [`ownership-verify-list`](#ownership-ledger-ownership-verify-list).  
Тест: `OwnershipRegistryVerifierTest`. Исходник примеров: `OwnershipVerifyExample.kt`.

---

## Типичные сценарии

### Разбор и проверка (commonMain — все платформы)

```kotlin
// p12Der: ByteArray из файла, assets, bundle, сети
val container = RegistryParser.parse(p12Der)
SignatureVerifier.verifyRegistry(p12Der)
println(RegistryAnalyzer.toTextDetailed(container))
```

### Сборка (commonMain — Android / iOS / JVM)

```kotlin
val cfg = BuildConfig(
    signerCertDer = PemEncoding.decodePemOrDer(signerCertPem),
    signerKey = PlatformCrypto.parseEcPrivateKey(signerKeyPem),
    vin = "VIN123",
    verTimestamp = Instant.parse("2024-01-01T00:00:00Z"),
    verVersion = 1,
    uid = "UID456",
    safeBags = listOf(/* SafeBagInput */),
)
val built = RegistryBuilder.buildRegistry(cfg)
SignatureVerifier.verifyRegistry(built)
```

### Сборка из config.json (только JVM)

```kotlin
val dir = Path.of("config.json").parent?.toString() ?: "."
val built = RegistryBuilder.buildRegistry(
    ConfigLoader.toBuildConfig(ConfigLoader.readConfig("config.json"), dir)
)
SignatureVerifier.verifyRegistry(built)
```

### Добавить сертификат (commonMain)

Поля подписанта обычно берутся из `BuildConfig` (см. [BuildConfig](#buildconfig)).

```kotlin
val updated = RegistryBuilder.addCertificateAndResign(
    AddCertificateRequest(
        existingP12 = existing,
        newBag = buildConfig.safeBags.first { /* ещё нет в реестре */ },
        signerCertDer = buildConfig.signerCertDer,
        signerKey = buildConfig.signerKey,
    )
)
```

### Удалить по SKID (commonMain)

```kotlin
val updated = RegistryBuilder.removeCertificateBySkidAndResign(
    RemoveCertificateBySkidRequest(
        existingP12 = existing,
        subjectKeyId = PemEncoding.decodeSkidHex("019c9eff384f76abaf6163d38b3f384b"),
        signerCertDer = buildConfig.signerCertDer,
        signerKey = buildConfig.signerKey,
    )
)
```

### Cloud configuration (mob-dev)

Ответ облачного сервиса mob-dev содержит `cloud_config_json` (UTF-8 JSON) и `cloud_config_pem` (standalone CMS SignedData, не PFX).  
Invitation (`resp-context.json`) → camelCase TBOX + CES FQDN — через `CloudConfigFromContext` / `CloudBrokerFqdn`.  
Ownership leaf: сначала [`OwnershipCsr`](#ownership-csr--ownershipcsr) → Cloud PKI → затем подпись CMS и `requireOwnerIdBinding`.  
Подробнее — раздел [CloudConfigCms](#cloud-config--cloudconfigcms-mob-dev) и примеры `cloud-config*` / `sign-tbox` / `gen-ownership-csr` в `samples/registry-examples`.

```kotlin
import com.atom.sgwregistry.cloudconfig.CloudConfigCms
import com.atom.sgwregistry.csr.OwnershipCsr
import com.atom.sgwregistry.csr.OwnershipCsrRequest
import com.atom.sgwregistry.model.CloudConfigResignRequest
import com.atom.sgwregistry.model.MobDevCloudConfigJson

// 0) CSR для Ownership leaf (до enroll)
val csrPem = OwnershipCsr.buildToPem(
    OwnershipCsrRequest(ownerId = "d231b684-82b4-4fdc-83dd-fc9a1861c293"),
    ecPrivateKeyPem,
)

val dto = MobDevCloudConfigJson.parse(jsonBytes).cloudConfiguration
println(CloudConfigCms.toText(dto))
CloudConfigCms.verifyCloudConfiguration(dto)

val newPem = CloudConfigCms.resignToPem(
    CloudConfigResignRequest(
        jsonPayload = dto.cloudConfigJson,
        signerCertDer = ownerCertDer,
        signerKey = signingKey,
    ),
)
```

JVM-пример: `./gradlew :samples:registry-examples:runCloud-config`  
Invitation → TBOX: `./gradlew :samples:registry-examples:runCloud-config-from-context`  
TBOX → PEM: `./gradlew :samples:registry-examples:runSign-tbox`

---

## JVM-примеры (`registry-examples`)

Модуль `samples/registry-examples` — CLI для отладки API на desktop.  
Зависимость: `implementation(project(":sgw-registry"))` — публикация в Maven не нужна.

Рабочий каталог Gradle: **корень репозитория** (родитель `kotlin/`).  
Gradle передаёт `sgw.registry.repoRoot`; пути в аргументах — относительные от корня.

### Структура CLI

```bash
./gradlew :samples:registry-examples:run --args="<command> [args...]"
```

Первый аргумент в `--args` — **имя команды** (`cloud-config`, `cloud-config-trust`, `parse`, …), не путь к файлу.

| Неправильно | Правильно |
|-------------|-----------|
| `--args="kotlin-out/mob-dev-cloud_config-resigned.json"` | `--args="cloud-config-trust kotlin-out/mob-dev-cloud_config-resigned.json …"` |
| `--args="/abs/path/to/file.json"` | `--args="cloud-config /abs/path/to/file.json"` |

Иначе: `Unknown command: …`.

### Быстрый старт

```bash
cd kotlin
./gradlew :samples:registry-examples:runAll               # .p12 сценарии
./gradlew :samples:registry-examples:runCloud-config        # mob-dev CMS
./gradlew :samples:registry-examples:runCloud-config-trust  # identity → PKIX → CMS
./gradlew :samples:registry-examples:runCloud-config-from-context  # invitation → TBOX
./gradlew :samples:registry-examples:runSign-tbox           # TBOX → cloud_config_pem
./gradlew :samples:registry-examples:runSign-cloud-config   # fixtures → sign + binding
./gradlew :samples:registry-examples:runGen-ownership-csr   # PKCS#10 Ownership CSR (EKU/SAN)
./gradlew :samples:registry-examples:runOwnership-verify      # JSON → List CMS → verify
./gradlew :samples:registry-examples:runOwnership-verify-list # готовая List<String> CMS PEM
./gradlew :samples:registry-examples:runEmpty-owner           # пустой owner.p12
```

### Сокращённые Gradle-задачи

| Gradle-задача | CLI | Сценарий |
|---------------|-----|----------|
| `runParse` | `parse [file.p12]` | Разбор реестра |
| `runVerify` | `verify [file.p12]` | Проверка подписи |
| `runAnalyze` | `analyze [file.p12]` | Отчёт + экспорт |
| `runConfig` | `config [config.json]` | ConfigLoader |
| `runBuild` | `build [config.json] [out.p12]` | Сборка .p12 |
| `runEmpty-owner` | `empty-owner [cfg] [out] [vin] [uid] [verTs] [verN]` | пустой подписанный .p12 |
| `runEmpty-owner-unsigned` | `empty-owner-unsigned [outPrefix] …` | SafeContents + header draft |
| `runAdd-cert` | `add-cert [in] [cfg] [out] [idx]` | add + resign |
| `runRemove-cert` | `remove-cert [in] [cfg] [out] [skid]` | remove + resign |
| `runUpdate-registry` | `update-registry [in] [cfg] [added] [final]` | add → remove round-trip |
| `runCloud-config` | `cloud-config [mob.json] [cfg] [out]` | mob-dev CMS |
| `runCloud-config-trust` | `cloud-config-trust [mob.json] [vin] [owner_id] [ownership-ca.pem]` | identity → PKIX → CMS |
| `runCloud-config-from-context` | `cloud-config-from-context [resp.json] [cfg] [v] [out]` | invitation → TBOX JSON |
| `runSign-tbox` | `sign-tbox [tbox.json] [cfg] [outPrefix] [vin] [fqdnId] [owner_id]` | TBOX → CMS PEM |
| `runSign-cloud-config` | `sign-cloud-config [good.json] [resp-context.json] [cfg] [outPrefix] [bad.json]` | фикстуры: binding + resign + from-context + negative a1 |
| `runGen-ownership-csr` | `gen-ownership-csr [ownerId] [key.pem] [out.csr.pem]` | Ownership PKCS#10 (EKU Email Protection + SAN) |
| `runOwnership-verify` | `ownership-verify [ownership-resp.json] [ownerId] [vin]` | JSON → List CMS → verify(cms, ownerId, vin) |
| `runOwnership-verify-list` | `ownership-verify-list [ownerId] [vin] [cms0.pem…]` | готовая `List<String>` CMS PEM → verify |
| `runAll` | `all [file.p12]` | все .p12 (**без** cloud-config) |

С сокращённой задачей (`runCloud-config`, `runCloud-config-trust`, …) в `--args` можно передать **только пути** — имя команды подставится автоматически:

```bash
./gradlew :samples:registry-examples:runCloud-config --args="mob-dev-cloud_config.json config.json"
./gradlew :samples:registry-examples:runCloud-config-trust --args="kotlin-out/mob-dev-cloud_config-resigned.json"
```

С общей задачей `run` имя команды в `--args` **обязательно**.

### `.p12` реестры

```bash
./gradlew :samples:registry-examples:run --args="parse demo-original-container.p12"
./gradlew :samples:registry-examples:run --args="build config.json kotlin-out/my.p12"
./gradlew :samples:registry-examples:run --args="add-cert demo-original-container.p12 config.json kotlin-out/updated.p12 0"
./gradlew :samples:registry-examples:run --args="remove-cert kotlin-out/registry-with-added-cert.p12 config.json kotlin-out/after-remove.p12"
```

### Cloud configuration (`cloud-config`)

```bash
# parse + verify
./gradlew :samples:registry-examples:runCloud-config

# свой JSON
./gradlew :samples:registry-examples:run --args="cloud-config mob-dev-cloud_config.json"

# + resign (resignConfigurationOnly — eContent из CMS без пересборки)
./gradlew :samples:registry-examples:run --args="cloud-config mob-dev-cloud_config.json config.json"

# + запись out.json
./gradlew :samples:registry-examples:run --args="cloud-config mob-dev-cloud_config.json config.json kotlin-out/mob-dev-cloud_config-resigned.json"
```

| Аргумент | По умолчанию |
|----------|--------------|
| mob-dev JSON | `mob-dev-cloud_config.json` |
| config.json | опционально (для resign) |
| out.json | `kotlin-out/mob-dev-cloud_config-resigned.json` |

> **Оригинал vs resign.** `mob-dev-cloud_config.json` при resign **не перезаписывается**. Результат пишется в `out.json` (по умолчанию `kotlin-out/mob-dev-cloud_config-resigned.json`).  
> Resign в примере берёт signer из `config.json` → обычно `certs/signer.pem` (`CN=Owner Registry Signer`, self-signed). Это проверка API resign/verify, **не** цепочки ATOM Ownership.  
> В resigned CMS меняется только `cloud_config_pem`; `cloud_config_json` / `vin` / `owner_id` / `root_cas` остаются как в исходнике.  
> Цепочка PKIX после resign проходит **только если** новый `signerCert` выдан Ownership CA (и есть ROOT ext как trust anchor). Локальный test signer → подпись OK, PKIX к Ownership/ROOT ext — FAIL.

Исходник: `samples/registry-examples/.../CloudConfigExample.kt`.

### Cloud config trust (`cloud-config-trust`)

```bash
./gradlew :samples:registry-examples:runCloud-config-trust

# оригинал (owner-leaf от ATOM Ownership CA)
./gradlew :samples:registry-examples:run --args="cloud-config-trust mob-dev-cloud_config.json 79079999999 d231b684-82b4-4fdc-83dd-fc9a1861c293"

# переподписанный артефакт
./gradlew :samples:registry-examples:run --args="cloud-config-trust kotlin-out/mob-dev-cloud_config-resigned.json 79079999999 d231b684-82b4-4fdc-83dd-fc9a1861c293"

# свой Ownership CA PEM (иначе автопоиск certs/ATOM Ownership CA.pem)
./gradlew :samples:registry-examples:run --args="cloud-config-trust mob-dev-cloud_config.json 79079999999 d231b684-82b4-4fdc-83dd-fc9a1861c293 path/to/ownership-ca.pem"
```

Шаги:

1. identity — `vin` / `owner_id` совпадают с ожидаемыми  
2a. `owner_id` есть в UID subject подписанта  
2b. PKIX: leaf → Ownership CA (intermediate) → ROOT ext (+ `root_cas` как доп. anchors)  
3. CMS: `json == eContent` + проверка подписи сертификатом подписанта  

> **Цепочка CMS-подписанта.** В `cloud_config_pem` обычно только leaf. Путь: leaf → **ATOM Ownership CA** → **ATOM ROOT ext CA**.  
> В `root_cas` — ATOM ROOT / Tenant (ветка брокера; к CMS-leaf сами по себе не ведут). Пример подхватывает `certs/ATOM Ownership CA.pem` и `certs/ATOM ROOT ext CA.pem`.  
> Stage-leaf часто короткоживущий (~1 ч). Если уже истёк «по часам», PKIX в примере идёт на `leaf.notBefore`.  
> После resign локальным `certs/signer.pem`: шаг 2a/2b для Ownership-цепочки, как правило, **FAIL**; шаг 3 (подпись) может быть OK.

Исходник: `CloudConfigTrustExample.kt`, PKIX — `JvmCertificateTrust.kt`.

### Invitation → TBOX (`cloud-config-from-context`)

```bash
./gradlew :samples:registry-examples:runCloud-config-from-context

./gradlew :samples:registry-examples:run --args="cloud-config-from-context resp-context.json config.json 5"

# свой путь выхода
./gradlew :samples:registry-examples:run --args="cloud-config-from-context resp-context.json config.json 5 kotlin-out/my-tbox.json"
```

| Аргумент | По умолчанию |
|----------|--------------|
| invitation JSON | `resp-context.json` |
| config.json | `config.json` (demo signer) |
| `v` | `5` |
| out TBOX JSON | `kotlin-out/cloud-config-tbox.json` |

Пишет:

| Файл | Содержимое |
|------|------------|
| `*.json` (out) | TBOX payload `{ v, cloudBroker }` с CES FQDN |
| `*.envelope.json` | mob-dev envelope + CMS (для trust / отладки) |

FQDN: `hashB(vin)-{tenant_id}.mqtt.atom.auto` (если `tenant_id` пуст — ownership UID).  
Demo signer из `config.json` → CMS OK; `requireOwnerIdInSigner` может быть skipped.

Исходник: `CloudConfigFromContextExample.kt`.

### Подпись TBOX (`sign-tbox`)

```bash
./gradlew :samples:registry-examples:runSign-tbox

# vin + fqdnId(tenant_id) + owner_id
./gradlew :samples:registry-examples:run --args="sign-tbox \
  kotlin-out/cloud-config-tbox.json config.json kotlin-out/cloud-config-tbox-signed \
  EAY1F1C56T2000014 2281305f-4b16-4a49-989a-9abeeac2df20 9c1dc2f4-a015-46b7-b88f-a9e30d0a9f86"
```

| Аргумент | Смысл |
|----------|--------|
| tbox.json | вход `{ v, cloudBroker }` |
| config.json | signer |
| outPrefix | без расширения → `{prefix}.pem` + `{prefix}.envelope.json` |
| vin | hashB + envelope |
| fqdnId | id после `hashB(VIN)-` (tenant_id или owner UID) |
| owner_id | для envelope / `cloud-config-trust` |

`.pem` = аналог поля `cloud_config_pem` (`-----BEGIN CMS-----`).  
Pretty TBOX нормализуется в compact eContent перед подписью; при vin+fqdnId — CES resolve `baseDomain`.

Исходник: `SignTboxCloudConfigExample.kt`.

### Ownership CSR (`gen-ownership-csr`)

PKCS#10 Ownership CSR (EKU Email Protection + SAN) из EC private key.

```bash
./gradlew :samples:registry-examples:runGen-ownership-csr

# ownerId + key + out
./gradlew :samples:registry-examples:run --args="gen-ownership-csr \
  d231b684-82b4-4fdc-83dd-fc9a1861c293 \
  certs/signer-key.pem \
  kotlin-out/ownership.csr.pem"
```

| Аргумент | По умолчанию |
|----------|--------------|
| ownerId | `d231b684-82b4-4fdc-83dd-fc9a1861c293` |
| key.pem | `certs/signer-key.pem` (SEC1 с `publicKey [1]`) |
| out.csr.pem | `kotlin-out/ownership.csr.pem` (+ рядом `.der`) |

```bash
openssl req -in kotlin-out/ownership.csr.pem -noout -text -verify
# verify OK; E-mail Protection; URI:atombus:/user/{ownerId}
```

API: [`OwnershipCsr`](#ownership-csr--ownershipcsr). Исходник: `GenOwnershipCsrExample.kt`.

### Ownership ledger (`ownership-verify`)

Сценарий A: структура `ownership-resp.json` → `OwnershipLedgerResponse` → `verifyLedger`.

```bash
./gradlew :samples:registry-examples:runOwnership-verify

./gradlew :samples:registry-examples:run --args="ownership-verify \
  ownership-resp.json \
  7f9fc821-a09e-4f96-badc-643daca070c6"
```

| Аргумент | По умолчанию |
|----------|--------------|
| JSON | `ownership-resp.json` (envelope invitation) |
| ownerId | `7f9fc821-a09e-4f96-badc-643daca070c6` (UID последнего `owner_dn`) |
| vin | `response.vin` из JSON (опциональный override 3-м аргументом) |

Исходник: `OwnershipVerifyExample.run` / `runFromLedger`. API: [`OwnershipRegistryVerifier`](#ownership-ledger--ownershipregistryverifier).

### Ownership ledger list (`ownership-verify-list`)

Сценарий B: готовая структура `List<String>` CMS PEM → `verify(cms, ownerId, vin)` (без парсинга JSON).

```bash
./gradlew :samples:registry-examples:runOwnership-verify-list

# свои PEM (порядок = порядок statements, genesis первым):
./gradlew :samples:registry-examples:run --args="ownership-verify-list \
  7f9fc821-a09e-4f96-badc-643daca070c6 \
  AAABBBCCC3 \
  kotlin-out/ownership-stmt-0.pem \
  kotlin-out/ownership-stmt-1.pem"
```

| Аргумент | По умолчанию |
|----------|--------------|
| ownerId | `7f9fc821-a09e-4f96-badc-643daca070c6` |
| vin | `AAABBBCCC3` |
| cms*.pem | `kotlin-out/ownership-stmt-0.pem` … (создаются из `ownership-resp.json` при отсутствии) |

Эквивалент в коде:

```kotlin
val ownershipRegistryCms: List<String> = listOf(
    Files.readString(Path.of("kotlin-out/ownership-stmt-0.pem")),
    Files.readString(Path.of("kotlin-out/ownership-stmt-1.pem")),
)
OwnershipRegistryVerifier.verify(
    ownershipRegistryCms = ownershipRegistryCms,
    ownerId = "7f9fc821-a09e-4f96-badc-643daca070c6",
    vin = "AAABBBCCC3",
)
// или: SgwRegistry.verifyOwnershipRegistry(ownershipRegistryCms, ownerId, vin)
```

Исходник: `OwnershipVerifyExample.runFromCmsList` / `runFromPemFiles`.

### Empty owner.p12 (`empty-owner` / `empty-owner-unsigned`)

```bash
# подписанный пустой реестр (0 SafeBag) + VIN/UID/VER
./gradlew :samples:registry-examples:run --args="empty-owner owner-empty-config.json kotlin-out/owner.p12"

# произвольные заголовочные attrs
./gradlew :samples:registry-examples:run --args="empty-owner owner-empty-config.json kotlin-out/owner.p12 CUSTOM-VIN 'CN=Demo' 2026-03-01T08:30:00Z 7"

# без подписи: SafeContents.der + header.json
./gradlew :samples:registry-examples:run --args="empty-owner-unsigned kotlin-out/owner-unsigned"
```

| Команда | Результат |
|---------|-----------|
| `empty-owner` | валидный PFX v3 + CMS, `safeBags: []`, `verifyRegistry` OK |
| `empty-owner-unsigned` | только `*.safecontents.der` + `*.header.json` (черновик VIN/UID/VER) |

Конфиг: `owner-empty-config.json` (`"safeBags": []`).  
Исходники: `EmptyOwnerP12Example.kt`, `EmptyOwnerUnsignedExample.kt`.

### Необходимые файлы (корень репозитория)

| Файл | Назначение |
|------|------------|
| `demo-original-container.p12` | .p12 примеры |
| `config.json`, `certs/` | build, add/remove, resign, sign-tbox, gen-ownership-csr |
| `certs/signer-key.pem` | EC key для demo CSR / resign (должен содержать publicKey) |
| `mob-dev-cloud_config.json` | исходный cloud-config (owner-leaf) |
| `resp-context.json` | invitation → TBOX |
| `owner-empty-config.json` | empty-owner |
| `certs/ATOM Ownership CA.pem` | intermediate для PKIX CMS |
| `certs/ATOM ROOT ext CA.pem` | extra trust anchor для PKIX CMS |
| `kotlin-out/cloud-config-tbox.json` | TBOX payload |
| `kotlin-out/cloud-config-tbox-signed.pem` | CMS PEM после sign-tbox |
| `ownership-resp.json` | fixture ownership ledger (`ownership_registry[]` CMS) |
| `kotlin-out/ownership.csr.pem` | Ownership CSR после `gen-ownership-csr` |
| `kotlin-out/ownership-stmt-*.pem` | CMS statements после `ownership-verify` / для `ownership-verify-list` |
| `kotlin-out/mob-dev-cloud_config-resigned.json` | результат `cloud-config` + resign (test signer) |

### Тесты (JVM / iOS / Android)

```bash
./gradlew :sgw-registry:jvmTest
./gradlew :sgw-registry:iosSimulatorArm64Test
./gradlew :sgw-registry:testDebugUnitTest
```

---

## Примеры для мобильных платформ (Android / iOS / commonMain)

На мобильных платформах **нет**  `ConfigLoader`, `PemUtils` и `RegistryAnalyzerJvm`. Все операции — через `ByteArray` (assets, bundle, API, secure storage).

JVM-аналоги тех же сценариев — модуль `samples/registry-examples/` (`./gradlew :samples:registry-examples:runAll`).

### Структура ресурсов

В качестве примера: структура катлогов для `config.json` и каталога `certs/` из корня репозитория — одинаково на Android (assets) и iOS (bundle):

```
config.json
certs/
  signer.pem          ← config.signerCert
  signer-key.pem      ← config.signerKey
  driver.pem          ← config.safeBags[0].cert
  passenger.pem
  ivi.pem
  mobile-driver.pem
```

### Parse — `RegistryParser` + `ParseOptions`

```kotlin
import com.atom.sgwregistry.api.ParseOptions
import com.atom.sgwregistry.parser.RegistryParser

// p12: ByteArray из assets / bundle / сети
val container = RegistryParser.parse(p12)
val strict = RegistryParser.parse(p12, ParseOptions(strict = true))  // warnings → exception

// через фасад
val viaFacade = SgwRegistry.parse(p12)
```

### Verify — `SignatureVerifier`

```kotlin
import com.atom.sgwregistry.verifier.SignatureVerifier

SignatureVerifier.verifyRegistry(p12)
SignatureVerifier.verifyContainer(container)

val (ok, message) = SignatureVerifier.tryVerifyRegistry(p12)

// фасад
SgwRegistry.verifyRegistry(p12)
```

### Analyze — `RegistryAnalyzer` (без export на диск)

```kotlin
import com.atom.sgwregistry.analyzer.RegistryAnalyzer

val c = RegistryParser.parse(p12)
RegistryAnalyzer.verifyRegistry(p12)           // делегирует SignatureVerifier
val text = RegistryAnalyzer.toText(c)
val detailed = RegistryAnalyzer.toTextDetailed(c, skipVerify = false)
val json = RegistryAnalyzer.toJson(c)          // ByteArray UTF-8
val allPem = RegistryAnalyzer.toPem(c)
val bagsPem = RegistryAnalyzer.toSafeBagsPem(c)
val signerPem = RegistryAnalyzer.signerCertPem(c)
val attrs = RegistryAnalyzer.parseAuthenticatedAttributes(c.authenticatedAttributesSetBytes)
```

На JVM для записи PEM на диск используйте `RegistryAnalyzerJvm` — на Android/iOS только `ByteArray`.

### Config — `BuildConfigFactory` (вместо ConfigLoader)

```kotlin
import com.atom.sgwregistry.config.BuildConfigFactory
import com.atom.sgwregistry.config.SafeBagPemInput

// 1) JSON с путями + loadPem (как assets/certs/signer.pem)
// Android: context.assets.open(path).readBytes()
// iOS: readMainBundleResource(path) — com.atom.sgwregistry.util (iosMain)
val cfg = BuildConfigFactory.parseConfig(configJsonText)
val buildCfg = BuildConfigFactory.toBuildConfig(cfg) { path ->
    loadPemFromAssets(path)  // Android: assets.open(path)
}

// 2) JSON с inline PEM (ответ бэкенда)
val buildCfgInline = BuildConfigFactory.toBuildConfigFromInlinePem(cfg)

// 3) Прямая сборка без JSON
val buildCfgDirect = BuildConfigFactory.toBuildConfig(
    vin = "EAY2AT0MPS2013376",
    uid = "client@example.com",
    verTimestamp = Instant.parse("2024-01-01T00:00:00Z"),
    verVersion = 100,
    signerCertPem = signerCertBytes,
    signerKeyPem = signerKeyBytes,
    safeBags = listOf(
        SafeBagPemInput(
            certPem = roleCertBytes,
            roleName = "dast-agent",
            roleNotBefore = Instant.parse("2026-01-15T17:40:20Z"),
            roleNotAfter = Instant.parse("2027-01-15T17:40:20Z"),
            localKeyId = PemEncoding.decodeSkidHex("019c9eff384f76abaf6163d38b3f384b"),
        ),
    ),
)

val p12 = RegistryBuilder.buildRegistry(buildCfg)
```

### Build — `RegistryBuilder`

```kotlin
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.model.BuildConfig
import com.atom.sgwregistry.model.SafeBagInput

val cfg = BuildConfig(
    signerCertDer = PemEncoding.decodePemOrDer(signerCertPem),
    signerKey = PlatformCrypto.parseEcPrivateKey(signerKeyPem),
    vin = "VIN123",
    verTimestamp = Instant.parse("2024-01-01T00:00:00Z"),
    verVersion = 1,
    uid = "UID456",
    safeBags = listOf(
        SafeBagInput(
            certDer = PemEncoding.decodePemOrDer(roleCertPem),
            roleName = "driver",
            roleNotBefore = Instant.parse("2026-01-01T00:00:00Z"),
            roleNotAfter = Instant.parse("2027-01-01T00:00:00Z"),
        ),
    ),
)
val built = RegistryBuilder.buildRegistry(cfg)
val safeContentsOnly = RegistryBuilder.buildSafeContents(cfg.safeBags)
```

### Update — добавить / удалить сертификат

```kotlin
import com.atom.sgwregistry.model.AddCertificateRequest
import com.atom.sgwregistry.model.RemoveCertificateBySkidRequest

// buildConfig — из BuildConfigFactory или ConfigLoader (JVM)
val withNewBag = RegistryBuilder.addCertificateAndResign(
    AddCertificateRequest(
        existingP12 = existing,
        newBag = buildConfig.safeBags.first { /* ещё нет в реестре */ },
        signerCertDer = buildConfig.signerCertDer,
        signerKey = buildConfig.signerKey,
    ),
)

val withoutBag = RegistryBuilder.removeCertificateBySkidAndResign(
    RemoveCertificateBySkidRequest(
        existingP12 = withNewBag,
        subjectKeyId = PemEncoding.decodeSkidHex("019c9eff384f76abaf6163d38b3f384b"),
        signerCertDer = buildConfig.signerCertDer,
        signerKey = buildConfig.signerKey,
    ),
)
```

### Фасад — `SgwRegistry`

```kotlin
import com.atom.sgwregistry.api.SgwRegistry

val c = SgwRegistry.parse(p12)
SgwRegistry.verifyRegistry(p12)
println(SgwRegistry.toTextDetailed(c))

val updated = SgwRegistry.addCertificateAndResign(
    AddCertificateRequest(existingP12 = p12, newBag = bag, signerCertDer = certDer, signerKey = key),
)
SgwRegistry.removeCertificateBySkidAndResign(
    RemoveCertificateBySkidRequest(existingP12 = updated, subjectKeyId = skid, signerCertDer = certDer, signerKey = key),
)
```

### VER и конвертеры

```kotlin
import com.atom.sgwregistry.builder.VerAttribute
import com.atom.sgwregistry.builder.RegistryConverters
import com.atom.sgwregistry.analyzer.RegistryAnalyzer

val verStr = RegistryAnalyzer.parseAuthenticatedAttributes(container.authenticatedAttributesSetBytes)
    .firstOrNull { it.first == "VER" }?.second
val (ts, version) = VerAttribute.parseText(verStr!!)
val attrs = RegistryConverters.extractSignerAttrs(container)
val skidHex = PemEncoding.skidToHex(
    PlatformCrypto.getSubjectKeyId(PlatformCrypto.parseCertificate(certDer)),
)
```

### Crypto — `PemEncoding` и `PlatformCrypto`

```kotlin
val der = PemEncoding.decodePemOrDer(pemOrDerBytes)
val isPem = PemEncoding.isPem(bytes)
val pemOut = PemEncoding.certToPem(certDer)
val skid = PemEncoding.decodeSkidHex("019c9eff384f76abaf6163d38b3f384b")

val key = PlatformCrypto.parseEcPrivateKey(keyPemBytes)
val cert = PlatformCrypto.parseCertificate(certDer)
val hash = PlatformCrypto.sha256(data)
```

### Android — Cloud PKI + Keystore

Сценарий: ключ в **Android Keystore** → [`OwnershipCsr.build`](#ownership-csr--ownershipcsr) (EKU Email Protection + SAN) → Cloud PKI → сертификат; **тот же** ключ подписывает `.p12` и `cloud_config_pem`.  
Сертификат от PKI передаётся **и** как `signerCertDer`, **и** в `SafeBag` (например роль `owner`). После enroll — `requireSignerEkuForCms` / `requireOwnerIdBinding`.

Пакет: `com.atom.sgwregistry.crypto` (только **androidMain** / Android-артефакт):

```kotlin
import com.atom.sgwregistry.crypto.signingKeyFromAndroidKeyStore
import com.atom.sgwregistry.crypto.signingKeyFromPrivateKey
import com.atom.sgwregistry.csr.OwnershipCsr
import com.atom.sgwregistry.csr.OwnershipCsrRequest

val signerKey = signingKeyFromAndroidKeyStore(keystoreAlias) // тот же alias, что для CSR
// или: signingKeyFromPrivateKey(keyStore.getKey(alias, null) as PrivateKey)

// CSR: нужен SPKI публичного ключа из Keystore (X.509 SubjectPublicKeyInfo DER)
val csr = OwnershipCsr.build(
    OwnershipCsrRequest(ownerId = ownerId),
    key = signerKey,
    publicKeySpki = publicKeySpkiDer,
)

val pkiCertDer: ByteArray = ... // ответ PKI (DER или PemEncoding.decodePemOrDer)

val ownerBag = SafeBagInput(
    certDer = pkiCertDer,
    roleName = "owner",
    roleNotBefore = ...,
    roleNotAfter = ...,
)

RegistryBuilder.addCertificateAndResign(
    AddCertificateRequest(
        existingP12 = existingP12,
        newBag = ownerBag,
        signerCertDer = pkiCertDer,
        signerKey = signerKey,
    ),
)
```

`PlatformCrypto.parseEcPrivateKey` — только для PEM/DER в памяти; для hardware-bound ключей используйте `signingKeyFromAndroidKeyStore`.

Полный пример: `sgw-registry/src/androidMain/kotlin/com/atom/sgwregistry/android/example/AndroidRegistryKeystoreExample.kt`

### Android — загрузка из assets

Положите в `assets/` ту же структуру, что `config.json` + `certs/` в корне репозитория.

```kotlin
import com.atom.sgwregistry.config.BuildConfigFactory
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.model.AddCertificateRequest
import com.atom.sgwregistry.verifier.SignatureVerifier

fun loadBuildConfig(context: Context): BuildConfig {
    val configJson = context.assets.open("config.json").use { it.readBytes() }
    val cfg = BuildConfigFactory.parseConfig(configJson.decodeToString())
    return BuildConfigFactory.toBuildConfig(cfg) { path ->
        context.assets.open(path).use { it.readBytes() }
    }
}

fun updateRegistryOnAndroid(context: Context) {
    val buildConfig = loadBuildConfig(context)
    val existingP12 = context.assets.open("demo-original-container.p12").use { it.readBytes() }
    // val existingP12 = File(context.filesDir, "registry.p12").readBytes()

    val newBag = buildConfig.safeBags.first { bag ->
        existingP12.let { RegistryParser.parse(it) }.safeBagInfos
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
    File(context.filesDir, "registry-updated.p12").writeBytes(updated)
}
```

### iOS — `BuildConfigFactory` и загрузка ресурсов

`BuildConfigFactory` **уже реализован** в `commonMain` — на iOS его не пишут заново. Задача iOS-приложения: отдать `ByteArray` (`config.json`, PEM) и передать функцию `loadPem` в фабрику.

```
NSBundle / API / Documents / Keychain
        │  ByteArray
        ▼
loadPem(path)  ──►  BuildConfigFactory.toBuildConfig(cfg, loadPem)
        │                    │
        │                    ▼
        │              BuildConfig (commonMain)
        │                    │
        └──────────► RegistryBuilder.buildRegistry / add / remove
```

**Зависимость** (KMP-приложение):

```kotlin
// shared/build.gradle.kts
kotlin {
    iosArm64()
    iosSimulatorArm64()
    sourceSets {
        commonMain.dependencies {
            implementation("com.atom:sgw-registry:2.6.0")
        }
    }
}
```

`readMainBundleResource` — в **iosMain** артефакта `sgw-registry` (`com.atom.sgwregistry.util`). Из `commonMain` приложения напрямую не вызывается: обёртка в `iosMain` приложения или свой `expect/actual loadPem`.

**Структура в Xcode** (зеркало корня репозитория):

```
config.json
certs/                    ← Folder Reference (синяя папка!)
  signer.pem
  signer-key.pem
  driver.pem
  passenger.pem
  ...
demo-original-container.p12   ← опционально, для демо add/remove
```

| Вариант | Когда использовать | API |
|---------|-------------------|-----|
| 1. Bundle + `loadPem` | Файлы в app bundle | `toBuildConfig(cfg, ::readMainBundleResource)` |
| 2. Свой `loadPem` | Documents, кэш API, смешанные источники | `toBuildConfig(cfg) { path -> ... }` |
| 3. Inline PEM | Ответ backend с PEM в JSON | `toBuildConfigFromInlinePem(cfg)` |
| 4. Без JSON | Все байты уже в памяти | `toBuildConfig(vin, uid, …, safeBags)` |

#### Вариант 1 — файлы в app bundle

Хелпер библиотеки: `readMainBundleResource(relativePath)` — `com.atom.sgwregistry.util` (iosMain).

```kotlin
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.config.BuildConfigFactory
import com.atom.sgwregistry.model.BuildConfig
import com.atom.sgwregistry.util.readMainBundleResource
import com.atom.sgwregistry.verifier.SignatureVerifier

fun loadBuildConfigFromBundle(): BuildConfig {
    val configJson = readMainBundleResource("config.json")
    val cfg = BuildConfigFactory.parseConfig(configJson.decodeToString())
    return BuildConfigFactory.toBuildConfig(cfg, ::readMainBundleResource)
}

fun buildRegistryFromBundle(): ByteArray {
    val p12 = RegistryBuilder.buildRegistry(loadBuildConfigFromBundle())
    SignatureVerifier.verifyRegistry(p12)
    return p12
}
```

Для пути `certs/signer.pem` из `config.json` фабрика вызовет `loadPem("certs/signer.pem")` → `readMainBundleResource`.

#### Вариант 2 — обёртка в iosMain (свой источник)

```kotlin
// iosMain/.../RegistryConfigLoader.ios.kt
import com.atom.sgwregistry.config.BuildConfigFactory
import com.atom.sgwregistry.model.BuildConfig
import com.atom.sgwregistry.util.readMainBundleResource

object RegistryConfigLoader {
    fun fromBundle(): BuildConfig {
        val json = readMainBundleResource("config.json").decodeToString()
        val cfg = BuildConfigFactory.parseConfig(json)
        return BuildConfigFactory.toBuildConfig(cfg) { path ->
            readMainBundleResource(path)
        }
    }

    /** config.json и PEM из Documents / кэша после API */
    fun fromDownloadedFiles(configJson: ByteArray, pemLoader: (String) -> ByteArray): BuildConfig {
        val cfg = BuildConfigFactory.parseConfig(configJson.decodeToString())
        return BuildConfigFactory.toBuildConfig(cfg, pemLoader)
    }
}
```

`pemLoader` возвращает `ByteArray` по тем же относительным путям, что в JSON (`certs/signer.pem`, …).

#### Вариант 3 — JSON с inline PEM (ответ backend)

Без файлов в bundle — PEM в теле JSON (`signerCertPem`, `signerKeyPem`, `certPem`):

```kotlin
val cfg = BuildConfigFactory.parseConfig(apiResponseJson)
val buildConfig = BuildConfigFactory.toBuildConfigFromInlinePem(cfg)
val p12 = RegistryBuilder.buildRegistry(buildConfig)
```

#### Вариант 4 — без JSON, только байты

```kotlin
import com.atom.sgwregistry.config.BuildConfigFactory
import com.atom.sgwregistry.config.SafeBagPemInput
import com.atom.sgwregistry.util.readMainBundleResource
import kotlinx.datetime.Instant

val buildConfig = BuildConfigFactory.toBuildConfig(
    vin = "EAY2AT0MPS2013376",
    uid = "client@example.com",
    verTimestamp = Instant.parse("2024-01-01T00:00:00Z"),
    verVersion = 100,
    signerCertPem = readMainBundleResource("certs/signer.pem"),
    signerKeyPem = readMainBundleResource("certs/signer-key.pem"),
    safeBags = listOf(
        SafeBagPemInput(
            certPem = readMainBundleResource("certs/driver.pem"),
            roleName = "dast-agent",
            roleNotBefore = Instant.parse("2026-01-15T17:40:20Z"),
            roleNotAfter = Instant.parse("2027-01-15T17:40:20Z"),
        ),
    ),
)
```

#### Add / Remove на iOS

`BuildConfig` целиком в add/remove **не передаётся** — берутся `signerCertDer`, `signerKey` и элемент `safeBags`:

```kotlin
import com.atom.sgwregistry.builder.RegistryBuilder
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
    val buildConfig = loadBuildConfigFromBundle()

    // .p12 из bundle, Documents или ответа API
    val existingP12 = readMainBundleResource("demo-original-container.p12")

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

    // сохранить в Documents
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

В проде **ключ подписанта** (`signer-key.pem`) часто хранят в **Keychain**, а не в bundle — тогда в `loadPem` для `cfg.signerKey` читайте из Keychain, для `certs/*.pem` — из bundle или API.

> **Не путать** с Android Gradle `BuildConfig`. На iOS **не используется** `ConfigLoader` (только JVM).

---

## Проверка опубликованного пакета (тесты и примеры)

После `publishLibrary` или JVM-публикации в Maven можно проверить артефакт **как внешний потребитель** — через модули `samples/` в этом репозитории.

### Зависимость в примерах

**Локальная разработка (по умолчанию):**

```kotlin
// samples/registry-examples/build.gradle.kts
dependencies {
    implementation(project(":sgw-registry"))
}
```

**Проверка Maven-артефакта** (внешний потребитель): замените на `com.atom:sgw-registry:2.6.0` и опубликуйте в `kotlin/dist/maven/`:

```kotlin
dependencies {
    implementation("com.atom:sgw-registry:2.6.0")
}
```

Gradle резолвит KMP metadata → JVM variant:

```
com.atom:sgw-registry:2.6.0
  └── com.atom:sgw-registry-jvm:2.6.0
```

### Публикация перед тестами

```bash
cd kotlin

# JVM + metadata (достаточно для samples):
./gradlew :sgw-registry:publishJvmPublicationToMavenLocal \
          :sgw-registry:publishKotlinMultiplatformPublicationToMavenLocal

# Все платформы (нужны Android SDK и Xcode для AAR/klib):
./gradlew :sgw-registry:publishLibrary
```

### Команды проверки

| Команда | Что проверяет |
|---------|---------------|
| `:sgw-registry:jvmTest` | unit-тесты (`.p12` + `CloudConfigCmsTest`) |
| `:sgw-registry:iosSimulatorArm64Test` | те же тесты на iOS |
| `:sgw-registry:testDebugUnitTest` | те же тесты на Android |
| `:samples:registry-examples:runAll` | .p12 сценарии через CLI |
| `:samples:registry-examples:runCloud-config` | mob-dev cloud_configuration |
| `:samples:build-registry-example:run` | CLI-сборка `.p12` |
| `:samples:build-registry-example:runUpdateAdd` | add-cert + VER bump |
| `:samples:build-registry-example:runUpdateRemove` | remove-cert + VER bump |

Полный smoke-тест:

```bash
./gradlew :sgw-registry:jvmTest \
          :sgw-registry:iosSimulatorArm64Test \
          :sgw-registry:testDebugUnitTest \
          :samples:registry-examples:runAll \
          :samples:registry-examples:runCloud-config
```

Проверка резолва зависимости:

```bash
./gradlew :samples:registry-examples:dependencies --configuration runtimeClasspath
```

### Данные для тестов

Файлы в **корне проекта** (родитель `kotlin/`):

| Файл | Назначение |
|------|------------|
| `config.json` | build, add/remove cert |
| `certs/` | PEM из config.json |
| `demo-original-container.p12` | parse, verify, VER bump |
| `mob-dev-cloud_config.json` | CloudConfigCms parse/verify/resign |
| `spas-delegate.p12` | неподписанный контейнер (unit-тесты) |

Рабочий каталог примеров: корень проекта (`workingDir` в Gradle).

---

## Сводка исключений

| API | Типичные исключения |
|-----|---------------------|
| `RegistryParser.parse` | `IllegalArgumentException`, `IllegalStateException` |
| `RegistryBuilder.build*` | `IllegalArgumentException`, `IllegalStateException` |
| `SignatureVerifier` | `IllegalStateException` |
| `ConfigLoader` | `IllegalArgumentException`, `IllegalStateException` (**JVM**) |
| `PemUtils` | `IllegalArgumentException` (**JVM**) |
| `VerAttribute.parseText` | `IllegalArgumentException` |
| `PemEncoding.decodeSkidHex` | `IllegalArgumentException` |
| `PemUtils.decodeSkidHex` | `IllegalArgumentException` (**JVM**) |
| `CloudConfigCms.verify*` | `IllegalStateException`, `IllegalArgumentException` |
| `CloudConfigFromContext.*` | `IllegalArgumentException`, `IllegalStateException` |
| `MobDevCloudConfigJson.parse` / `InvitationContextJson.parse` | `SerializationException` (kotlinx.serialization) |

---

**Версия документа:** 2.6.0 (KMP: jvm, android, iosArm64, iosSimulatorArm64)  
**ATOM SA Team 2026**
