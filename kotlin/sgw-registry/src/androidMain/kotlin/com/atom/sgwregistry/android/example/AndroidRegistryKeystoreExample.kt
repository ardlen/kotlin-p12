/**
 * Пример интеграции **sgw-registry** с **Android Keystore** и Cloud PKI.
 *
 * Сценарий (прод):
 * 1. Создать EC P-256 ключ в Android Keystore (non-exportable).
 * 2. Подписать CSR этим ключом → отправить в Cloud PKI.
 * 3. Получить сертификат от доверенного CA.
 * 4. Добавить сертификат в реестр `.p12` **и** как подписант CMS, **и** как SafeBag (роль owner).
 * 5. Переподписать реестр **тем же** Keystore-ключом.
 * 6. Проверить: [com.atom.sgwregistry.verifier.SignatureVerifier.verifyRegistry].
 *
 * Скопируйте нужные функции в `androidMain` вашего KMP-приложения.
 * Этот файл — справочник; не вызывается библиотекой автоматически.
 */
package com.atom.sgwregistry.android.example

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.crypto.signingKeyFromAndroidKeyStore
import com.atom.sgwregistry.crypto.signingKeyFromPrivateKey
import com.atom.sgwregistry.model.AddCertificateRequest
import com.atom.sgwregistry.model.BuildConfig
import com.atom.sgwregistry.model.SafeBagInput
import com.atom.sgwregistry.verifier.SignatureVerifier
import kotlinx.datetime.Instant
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.Certificate
import java.security.cert.X509Certificate

/** Alias ключа в Android Keystore — один на весь жизненный цикл: CSR + подпись реестра. */
const val REGISTRY_SIGNER_KEY_ALIAS = "atom_registry_signer"

object AndroidRegistryKeystoreExample {

    // ─────────────────────────────────────────────────────────────────────────
    // Шаг 0. Подготовка ключа (выполняется один раз при онбординге / первом запуске)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Создаёт пару EC P-256 в **Android Keystore**, если ещё не существует.
     *
     * Требования ATOM-PKCS12-REGISTRY:
     * - кривая **secp256r1** (P-256);
     * - назначение ключа — **подпись** (для CSR и для CMS SignerInfo).
     *
     * Ключ **не экспортируется** — байты приватного ключа никогда не покидают TEE/StrongBox.
     * Библиотека sgw-registry подписывает через JCA `Signature.initSign(privateKey)` поверх
     * готового SHA-256 digest (`NONEwithECDSA`).
     */
    fun ensureRegistrySignerKeyExists(alias: String = REGISTRY_SIGNER_KEY_ALIAS) {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (ks.containsAlias(alias)) return

        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN,
        )
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            // DIGEST_NONE — для sgw-registry (`NONEwithECDSA` над готовым SHA-256 digest).
            // DIGEST_SHA256 — для CSR / внешнего SHA256withECDSA, если нужно.
            .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
            // При необходимости: .setIsStrongBoxBacked(true) на поддерживаемых устройствах
            .setUserAuthenticationRequired(false)
            .build()

        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            .apply { initialize(spec) }
            .generateKeyPair()
    }

    /**
     * Загрузка [com.atom.sgwregistry.crypto.SigningKey] для commonMain API.
     *
     * Используйте **этот** объект как `signerKey` в `BuildConfig` / `AddCertificateRequest`.
     * Не вызывайте [com.atom.sgwregistry.crypto.PlatformCrypto.parseEcPrivateKey] — для
     * Keystore-ключей PEM недоступен.
     */
    fun loadRegistrySigningKey(alias: String = REGISTRY_SIGNER_KEY_ALIAS) =
        signingKeyFromAndroidKeyStore(alias)

    /**
     * Альтернатива: если [PrivateKey] уже получен (например, для подписи CSR в вашем PKI-клиенте),
     * оберните его в [com.atom.sgwregistry.crypto.SigningKey] тем же способом.
     */
    fun loadRegistrySigningKey(privateKey: PrivateKey) =
        signingKeyFromPrivateKey(privateKey)

    // ─────────────────────────────────────────────────────────────────────────
    // Шаг 1. CSR → Cloud PKI (выполняется в вашем PKI/Enrollment-модуле)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Получить [PrivateKey] и публичный сертификат цепочки для формирования CSR.
     *
     * ```kotlin
     * val (privateKey, _) = getKeyMaterialForCsr()
     * val csrDer = yourPkiClient.buildCsr(privateKey, subject, san, ...)
     * val pkiCertPem = yourPkiClient.enroll(csrDer) // HTTP → Cloud PKI
     * ```
     *
     * Важно: для подписи реестра позже используйте **тот же** [REGISTRY_SIGNER_KEY_ALIAS].
     */
    fun getKeyMaterialForCsr(alias: String = REGISTRY_SIGNER_KEY_ALIAS): Pair<PrivateKey, Certificate?> {
        ensureRegistrySignerKeyExists(alias)
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val privateKey = ks.getKey(alias, null) as PrivateKey
        val cert = ks.getCertificate(alias) // появится после импорта ответа PKI, до этого может быть null
        return privateKey to cert
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Шаг 2. Декодирование сертификата от PKI
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Сертификат от облака — PEM или DER. В реестр нужен **DER** ([ByteArray]).
     */
    fun decodePkiCertificate(pemOrDer: ByteArray): ByteArray =
        PemEncoding.decodePemOrDer(pemOrDer)

    /**
     * Опционально: убедиться, что сертификат PKI соответствует ключу в Keystore **до** подписи реестра.
     *
     * Проверка через probe-подпись тем же алгоритмом, что и sgw-registry (`NONEwithECDSA` над SHA-256).
     * Если probe не проходит — `verifyRegistry` тоже упадёт с `Signature verification failed`.
     */
    fun assertPkiCertMatchesKeystoreKey(
        pkiCertDer: ByteArray,
        alias: String = REGISTRY_SIGNER_KEY_ALIAS,
    ) {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val privateKey = ks.getKey(alias, null) as? PrivateKey
            ?: throw IllegalStateException("No private key for alias=$alias")

        val x509 = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(pkiCertDer.inputStream()) as X509Certificate

        // Если в Keystore уже привязан cert — быстрое сравнение публичных ключей
        val entryCert = ks.getCertificate(alias) as? X509Certificate
        if (entryCert != null && entryCert.publicKey != x509.publicKey) {
            throw IllegalStateException(
                "PKI certificate public key does not match Keystore entry for alias=$alias",
            )
        }

        // Probe: подписать фиксированный digest и проверить публичным ключом из PKI-сертификата
        val probeDigest = ByteArray(32) { 0x01 }
        val probeSignature = Signature.getInstance("NONEwithECDSA").apply {
            initSign(privateKey)
            update(probeDigest)
        }.sign()

        val ok = Signature.getInstance("NONEwithECDSA").apply {
            initVerify(x509.publicKey)
            update(probeDigest)
        }.verify(probeSignature)

        if (!ok) {
            throw IllegalStateException(
                "PKI certificate is not a key pair for Keystore alias=$alias (probe ECDSA verify failed)",
            )
        }
    }

    /**
     * После получения сертификата от PKI можно привязать его к ключу в Keystore
     * (удобно для последующих CSR/renew и для [assertPkiCertMatchesKeystoreKey]).
     */
    fun importPkiCertificateIntoKeyStore(
        pkiCertDer: ByteArray,
        alias: String = REGISTRY_SIGNER_KEY_ALIAS,
    ) {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val privateKey = ks.getKey(alias, null) as PrivateKey
        val cert = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(pkiCertDer.inputStream())
        ks.setKeyEntry(alias, privateKey, null, arrayOf(cert))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Шаг 3. Добавить сертификат PKI в реестр и переподписать
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Основной сценарий: существующий `.p12` + новый сертификат от PKI.
     *
     * Сертификат PKI используется **дважды** (один и тот же DER):
     * - [AddCertificateRequest.signerCertDer] → CMS `certificates`, SKID в SignerInfo;
     * - [SafeBagInput.certDer] → роль внутри реестра (например `owner`).
     *
     * Подпись — Keystore-ключ с alias [keystoreAlias] (тот же, что для CSR).
     * VER автоматически увеличивается на 1 ([com.atom.sgwregistry.builder.VerAttribute]).
     */
    fun addPkiCertAndResignRegistry(
        existingP12: ByteArray,
        pkiSignerCertDer: ByteArray,
        keystoreAlias: String = REGISTRY_SIGNER_KEY_ALIAS,
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
            // localKeyID можно не задавать — библиотека возьмёт SKID из сертификата
        )

        val updated = RegistryBuilder.addCertificateAndResign(
            AddCertificateRequest(
                existingP12 = existingP12,
                newBag = ownerBag,
                signerCertDer = pkiSignerCertDer,
                signerKey = signerKey,
            ),
        )

        // Криптопроверка: подпись CMS + messageDigest SafeContents
        SignatureVerifier.verifyRegistry(updated)
        return updated
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Шаг 3 (альтернатива). Первая сборка реестра с нуля
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Если `.p12` ещё нет — собрать первый реестр с сертификатом PKI в SafeBag и CMS.
     */
    fun buildInitialRegistryWithPkiCert(
        pkiSignerCertDer: ByteArray,
        keystoreAlias: String = REGISTRY_SIGNER_KEY_ALIAS,
        vin: String,
        uid: String,
        verTimestamp: Instant,
        verVersion: Int,
        roleName: String = "owner",
        roleNotBefore: Instant,
        roleNotAfter: Instant,
    ): ByteArray {
        require(verVersion >= 1) { "VER version must be >= 1 (V$verVersion)" }

        val signerKey = signingKeyFromAndroidKeyStore(keystoreAlias)

        val cfg = BuildConfig(
            signerCertDer = pkiSignerCertDer,
            signerKey = signerKey,
            vin = vin,
            uid = uid,
            verTimestamp = verTimestamp,
            verVersion = verVersion,
            safeBags = listOf(
                SafeBagInput(
                    certDer = pkiSignerCertDer,
                    roleName = roleName,
                    roleNotBefore = roleNotBefore,
                    roleNotAfter = roleNotAfter,
                ),
            ),
        )

        val p12 = RegistryBuilder.buildRegistry(cfg)
        SignatureVerifier.verifyRegistry(p12)
        return p12
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Шаг 4. Сохранение и чтение `.p12` на устройстве
    // ─────────────────────────────────────────────────────────────────────────

    /** Сохранить реестр во внутреннее хранилище приложения (не world-readable). */
    fun saveRegistry(context: Context, p12: ByteArray, fileName: String = "registry.p12") {
        File(context.filesDir, fileName).writeBytes(p12)
    }

    fun loadRegistry(context: Context, fileName: String = "registry.p12"): ByteArray =
        File(context.filesDir, fileName).readBytes()

    // ─────────────────────────────────────────────────────────────────────────
    // Полный пайплайн (псевдокод для Activity / ViewModel)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * ```
     * // Онбординг (один раз):
     * ensureRegistrySignerKeyExists()
     * val (privateKey, _) = getKeyMaterialForCsr()
     * val pkiPem = cloudPki.enroll(buildCsr(privateKey, ...))
     * val pkiDer = decodePkiCertificate(pkiPem)
     * importPkiCertificateIntoKeyStore(pkiDer)
     *
     * // Обновление реестра:
     * val existing = loadRegistry(context) // или с API
     * val updated = addPkiCertAndResignRegistry(
     *     existingP12 = existing,
     *     pkiSignerCertDer = pkiDer,
     *     roleNotBefore = ...,
     *     roleNotAfter = ...,
     * )
     * saveRegistry(context, updated)
     * ```
     */
    @Suppress("unused")
    private fun fullPipelineDocumentation() = Unit
}
