# SgwRegistry — справочник API

Документация API библиотеки **com.atom:sgw-registry:2.5.0** (Kotlin Multiplatform).

**Артефакты:** `kotlin/dist/maven/` (KMP: metadata + `-jvm` / `-android` / `-iosarm64` / `-iossimulatorarm64`)  
или плоский JVM JAR `dist/sgw-registry-2.5.0.jar` (только desktop).

## Обзор

Библиотека реализует формат **ATOM-PKCS12-REGISTRY** — PKCS#12 v3 контейнер с CMS SignedData (без macData/пароля), подписанный ECDSA-SHA256.

| Возможность | Описание | Платформы |
|-------------|----------|-----------|
| Parse | Разбор `.p12` → `RegistryContainer` | commonMain (все) |
| Build | Сборка `.p12` из `BuildConfig` | commonMain (все) |
| Verify | Проверка CMS-подписи и messageDigest | commonMain (все) |
| Analyze | Текстовые/JSON отчёты, PEM | commonMain (все) |
| Update | Добавление/удаление SafeBag с auto-bump VER | commonMain (все) |
| Cloud config | mob-dev `cloud_configuration`: parse/verify/resign `cloud_config_pem` | commonMain (все) |
| Config JSON | `config.json` → `BuildConfig` | **JVM:** `ConfigLoader`; **mobile:** `BuildConfigFactory` + `loadPem` |
| File export | Экспорт PEM на диск | **только JVM** (`RegistryAnalyzerJvm`) для мобильных платфром, хранение данных реестра зависит от мобильной платфромы |

**Требования:** Kotlin 2.0+, JDK 21+ (JVM), Android SDK (Android), Xcode (iOS).  
**Зависимости (common):** `kotlinx-serialization-json`, `kotlinx-datetime`.  
**Криптография:** `expect/actual PlatformCrypto` — JCA на JVM/Android, Security.framework на iOS (`kSecKeyAlgorithmECDSASignatureDigestX962SHA256` для NONEwithECDSA над digest); ASN.1/DER — собственный код в commonMain (**без Bouncy Castle**).

### Kotlin Multiplatform — таргеты и артефакты

| Gradle target | Maven publication | Формат |
|---------------|-------------------|--------|
| `jvm` | `com.atom:sgw-registry-jvm:2.5.0` | JAR |
| `android` | `com.atom:sgw-registry-android:2.5.0` | AAR |
| `iosArm64` | `com.atom:sgw-registry-iosarm64:2.5.0` | `.klib` |
| `iosSimulatorArm64` | `com.atom:sgw-registry-iossimulatorarm64:2.5.0` | `.klib` |
| metadata | `com.atom:sgw-registry:2.5.0` | `.module` + common metadata |

В KMP-проекте зависимость объявляется **один раз** в `commonMain`:

```kotlin
commonMain.dependencies {
    implementation("com.atom:sgw-registry:2.5.0")
}
```

### Распределение API по source sets

| API | commonMain | jvmMain | androidMain | iosMain |
|-----|:----------:|:-------:|:-----------:|:-------:|
| `RegistryParser`, `RegistryBuilder`, `SignatureVerifier`, `RegistryAnalyzer` | ✓ | ✓ | ✓ | ✓ |
| `SgwRegistry`, `PemEncoding`, `VerAttribute`, модели (`BuildConfig`, …) | ✓ | ✓ | ✓ | ✓ |
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
            implementation("com.atom:sgw-registry:2.5.0")
        }
    }
}
```

```kotlin
// JVM-only
dependencies {
    implementation("com.atom:sgw-registry:2.5.0")
}
```

```kotlin
// Импорты — commonMain (все платформы)
import com.atom.sgwregistry.api.SgwRegistry
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.verifier.SignatureVerifier
import com.atom.sgwregistry.analyzer.RegistryAnalyzer
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

Пакеты `com.atom.sgwregistry.internal.*` и низкоуровневый ASN.1 (`asn1.*`) предназначены для внутреннего использования; стабильный контракт — пакеты `api`, `model`, `parser`, `builder`, `verifier`, `analyzer`, `crypto`.

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
| `detectPemLabel(pem)` | Метка блока (`CERTIFICATE`, `EC PRIVATE KEY`, …) |
| `decodePemOrDer(pemOrDer)` | PEM или сырой DER → `ByteArray` |
| `decodePemBlock(pem, label)` | Извлечь и декодировать PEM-блок |
| `certToPem(certDer)` | DER → PEM-строка |
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

Дополнительно (mob-dev `cloud_configuration`):

| Метод | Описание |
|-------|----------|
| `parseMobDevCloudConfig(bytes\|text)` | JSON → `MobDevCloudConfigResponse` |
| `parseCloudConfigPem(pemOrDer)` | `cloud_config_pem` → `CloudConfigCmsContainer` |
| `verifyCloudConfigPem(pemOrDer)` | Проверка CMS |
| `verifyCloudConfiguration(dto)` | JSON + CMS end-to-end |
| `resignCloudConfigPem(request)` | Переподпись → PEM |
| `resignCloudConfigOnly(container, request)` | Переподпись без пересборки eContent |
| `resignCloudConfigurationOnly(dto, cert, key)` | Только `cloud_config_pem` |
| `cloudConfigToText(dto)` | Отчёт для лога/UI |

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
Подробнее — раздел [CloudConfigCms](#cloud-config--cloudconfigcms-mob-dev) и пример `samples/registry-examples/.../CloudConfigExample.kt`.

```kotlin
import com.atom.sgwregistry.cloudconfig.CloudConfigCms
import com.atom.sgwregistry.model.CloudConfigResignRequest
import com.atom.sgwregistry.model.MobDevCloudConfigJson

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
| `resign(request)` | Новый CMS DER |
| `resignToPem(request)` | Новый PEM (`-----BEGIN CMS-----`) — **пересборка eContent из JSON** |
| `resignConfiguration(dto, cert, key)` | DTO с новым `cloud_config_pem` (из JSON) |
| `resignOnly(container, request)` | Переподпись **без пересборки** eContent (байты из CMS) |
| `resignOnlyToPem(...)` | То же → PEM |
| `resignConfigurationOnly(dto, cert, key)` | Только `cloud_config_pem`; JSON не меняется |
| `toText(container\|dto)` | Отчёт для лога/UI |

### `CloudConfigFromContext`

```kotlin
object CloudConfigFromContext
```

| Метод | Описание |
|-------|----------|
| `parseInvitationResponse(bytes\|text)` | `resp-context.json` → `InvitationContextResponse` |
| `extractOwnerIdFromOwnershipCms(pem)` | UID leaf из `ownership_registry` (PFX v3 или CMS) |
| `buildCloudConfigJson(draft, payloadVersion?)` | snake_case draft → camelCase `cloud_config_json` |
| `buildUnsignedConfiguration(...)` | DTO без `cloud_config_pem` |
| `buildAndSign(..., signerCert, key, payloadVersion?)` | payload + CMS (`resignToPem`) |
| `encodeMobDevResponse(dto)` | JSON `{ "cloud_configuration": ... }` |

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

### Invitation context → signed cloud_configuration

```kotlin
val invitation = CloudConfigFromContext.parseInvitationResponse(respContextBytes)
val signed = CloudConfigFromContext.buildAndSign(
    response = invitation,
    signerCertDer = ownerCertDer,
    signerKey = ownerKey,
    payloadVersion = 5, // поле "v" в cloud_config_json
)
CloudConfigCms.verifyCloudConfiguration(signed)
CloudConfigCms.requireIdentity(signed, invitation.vin, signed.ownerId)
```

Через фасад:

```kotlin
SgwRegistry.parseMobDevCloudConfig(jsonBytes)
SgwRegistry.verifyCloudConfiguration(dto)
SgwRegistry.cloudConfigToText(dto)
SgwRegistry.resignCloudConfigPem(request)
SgwRegistry.parseInvitationContext(respContextBytes)
SgwRegistry.buildCloudConfigurationFromContext(invitation, ownerCertDer, ownerKey, payloadVersion = 5)
```

### JVM-примеры (`registry-examples`)

Модуль `samples/registry-examples` — CLI для отладки API на desktop.  
Зависимость: `implementation(project(":sgw-registry"))` — публикация в Maven не нужна.

Рабочий каталог Gradle: **корень репозитория** (родитель `kotlin/`).  
Gradle передаёт `sgw.registry.repoRoot`; пути в аргументах — относительные от корня.

#### Структура CLI

```bash
./gradlew :samples:registry-examples:run --args="<command> [args...]"
```

Первый аргумент в `--args` — **имя команды** (`cloud-config`, `cloud-config-trust`, `parse`, …), не путь к файлу.

| Неправильно | Правильно |
|-------------|-----------|
| `--args="kotlin-out/mob-dev-cloud_config-resigned.json"` | `--args="cloud-config-trust kotlin-out/mob-dev-cloud_config-resigned.json …"` |
| `--args="/abs/path/to/file.json"` | `--args="cloud-config /abs/path/to/file.json"` |

Иначе: `Unknown command: …`.

#### Быстрый старт

```bash
cd kotlin
./gradlew :samples:registry-examples:runAll               # .p12 сценарии
./gradlew :samples:registry-examples:runCloud-config        # mob-dev CMS
./gradlew :samples:registry-examples:runCloud-config-trust  # identity → PKIX → CMS
```

#### Сокращённые Gradle-задачи

| Gradle-задача | CLI | Сценарий |
|---------------|-----|----------|
| `runParse` | `parse [file.p12]` | Разбор реестра |
| `runVerify` | `verify [file.p12]` | Проверка подписи |
| `runAnalyze` | `analyze [file.p12]` | Отчёт + экспорт |
| `runConfig` | `config [config.json]` | ConfigLoader |
| `runBuild` | `build [config.json] [out.p12]` | Сборка .p12 |
| `runAdd-cert` | `add-cert [in] [cfg] [out] [idx]` | add + resign |
| `runRemove-cert` | `remove-cert [in] [cfg] [out] [skid]` | remove + resign |
| `runUpdate-registry` | `update-registry [in] [cfg] [added] [final]` | add → remove round-trip |
| `runCloud-config` | `cloud-config [mob.json] [cfg] [out]` | mob-dev CMS |
| `runCloud-config-trust` | `cloud-config-trust [mob.json] [vin] [owner_id] [ownership-ca.pem]` | identity → PKIX → CMS |
| `runAll` | `all [file.p12]` | все .p12 (**без** cloud-config) |

С сокращённой задачей (`runCloud-config`, `runCloud-config-trust`, …) в `--args` можно передать **только пути** — имя команды подставится автоматически:

```bash
./gradlew :samples:registry-examples:runCloud-config --args="mob-dev-cloud_config.json config.json"
./gradlew :samples:registry-examples:runCloud-config-trust --args="kotlin-out/mob-dev-cloud_config-resigned.json"
```

С общей задачей `run` имя команды в `--args` **обязательно**.

#### `.p12` реестры

```bash
./gradlew :samples:registry-examples:run --args="parse demo-original-container.p12"
./gradlew :samples:registry-examples:run --args="build config.json kotlin-out/my.p12"
./gradlew :samples:registry-examples:run --args="add-cert demo-original-container.p12 config.json kotlin-out/updated.p12 0"
./gradlew :samples:registry-examples:run --args="remove-cert kotlin-out/registry-with-added-cert.p12 config.json kotlin-out/after-remove.p12"
```

#### Cloud configuration (`cloud-config`)

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

#### Cloud config trust (`cloud-config-trust`)

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

#### Необходимые файлы (корень репозитория)

| Файл | Назначение |
|------|------------|
| `demo-original-container.p12` | .p12 примеры |
| `config.json`, `certs/` | build, add/remove, resign |
| `mob-dev-cloud_config.json` | исходный cloud-config (owner-leaf) |
| `certs/ATOM Ownership CA.pem` | intermediate для PKIX CMS |
| `certs/ATOM ROOT ext CA.pem` | extra trust anchor для PKIX CMS |
| `kotlin-out/mob-dev-cloud_config-resigned.json` | результат `cloud-config` + resign (test signer) |
#### Тесты (JVM / iOS / Android)

```bash
./gradlew :sgw-registry:jvmTest
./gradlew :sgw-registry:iosSimulatorArm64Test
./gradlew :sgw-registry:testDebugUnitTest
```

### iOS / Android

- Parse/verify/resign — через `CloudConfigCms` (commonMain).
- `signerKey` — из Keystore (Android) или Keychain (iOS); **не** использовать raw 64-byte P1363 подпись.
- JSON и PEM — из API/backend как `ByteArray` / `String`.

Unit-тесты: `CloudConfigCmsTest` (fixture `mob-dev-cloud_config.json`).

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

Сценарий: ключ в **Android Keystore** → CSR → Cloud PKI → сертификат; **тот же** ключ подписывает `.p12`.  
Сертификат от PKI передаётся **и** как `signerCertDer`, **и** в `SafeBag` (например роль `owner`).

Пакет: `com.atom.sgwregistry.crypto` (только **androidMain** / Android-артефакт):

```kotlin
import com.atom.sgwregistry.crypto.signingKeyFromAndroidKeyStore
import com.atom.sgwregistry.crypto.signingKeyFromPrivateKey

val signerKey = signingKeyFromAndroidKeyStore(keystoreAlias) // тот же alias, что для CSR
// или: signingKeyFromPrivateKey(keyStore.getKey(alias, null) as PrivateKey)

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
            implementation("com.atom:sgw-registry:2.5.0")
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

**Проверка Maven-артефакта** (внешний потребитель): замените на `com.atom:sgw-registry:2.5.0` и опубликуйте в `kotlin/dist/maven/`:

```kotlin
dependencies {
    implementation("com.atom:sgw-registry:2.5.0")
}
```

Gradle резолвит KMP metadata → JVM variant:

```
com.atom:sgw-registry:2.5.0
  └── com.atom:sgw-registry-jvm:2.5.0
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
| `MobDevCloudConfigJson.parse` | `SerializationException` (kotlinx.serialization) |

---

**Версия документа:** 2.5.0 (KMP: jvm, android, iosArm64, iosSimulatorArm64)  
**ATOM SA Team 2026**
