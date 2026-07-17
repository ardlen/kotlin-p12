/**
 * Реестр OID (Object Identifier), используемых в ATOM-PKCS12-REGISTRY.
 *
 * OID представлены как IntArray для удобного сравнения и кодирования в DER.
 */
package com.atom.sgwregistry.asn1

object Oids {
    // --- PKCS#7 / CMS ---
    /** 1.2.840.113549.1.7.2 — signedData (обёртка CMS). */
    val pkcs7SignedData = intArrayOf(1, 2, 840, 113549, 1, 7, 2)
    /** 1.2.840.113549.1.7.1 — data (тип eContent / EncapsulatedContentInfo). */
    val pkcs7Data = intArrayOf(1, 2, 840, 113549, 1, 7, 1)

    // --- PKCS#9 атрибуты ---
    /** contentType в authenticatedAttributes. */
    val pkcs9ContentType = intArrayOf(1, 2, 840, 113549, 1, 9, 3)
    /** messageDigest — хеш eContent (SHA-256). */
    val pkcs9MessageDigest = intArrayOf(1, 2, 840, 113549, 1, 9, 4)
    /** localKeyId в атрибутах SafeBag. */
    val pkcs9LocalKeyId = intArrayOf(1, 2, 840, 113549, 1, 9, 21)
    /** signingTime в authenticatedAttributes. */
    val pkcs9SigningTime = intArrayOf(1, 2, 840, 113549, 1, 9, 5)
    /** signingCertificateV2 (ESS). */
    val pkcs9SigningCertificateV2 = intArrayOf(1, 2, 840, 113549, 1, 9, 52)
    /** friendlyName (альтернатива roleName в некоторых контейнерах). */
    val pkcs9FriendlyName = intArrayOf(1, 2, 840, 113549, 1, 9, 20)

    // --- PKCS#12 ---
    /** certBag — тип SafeBag для X.509 сертификата. */
    val certBag = intArrayOf(1, 2, 840, 113549, 1, 12, 10, 1, 3)
    /** x509Certificate — тип CertValue внутри certBag. */
    val x509Certificate = intArrayOf(1, 2, 840, 113549, 1, 9, 22, 1)

    // --- ATOM (предприятие 99999) ---
    /** VIN в authenticatedAttributes. */
    val atomVin = intArrayOf(1, 3, 6, 1, 4, 1, 99999, 1, 1)
    /** Версия реестра: GeneralizedTime + INTEGER. */
    val atomVer = intArrayOf(1, 3, 6, 1, 4, 1, 99999, 1, 2)
    /** UID реестра. */
    val atomUid = intArrayOf(1, 3, 6, 1, 4, 1, 99999, 1, 3)
    /** Имя роли в SafeBag. */
    val atomRoleName = intArrayOf(1, 3, 6, 1, 4, 1, 99999, 1, 4)
    /** Период действия роли: notBefore + notAfter. */
    val atomRoleValidityPeriod = intArrayOf(1, 3, 6, 1, 4, 1, 99999, 1, 5)

    // --- Алгоритмы ---
    /** SHA-256 (digestAlgorithm). */
    val sha256 = intArrayOf(2, 16, 840, 1, 101, 3, 4, 2, 1)
    /** ECDSA с SHA-256 (signatureAlgorithm, P-256). */
    val ecdsaWithSha256 = intArrayOf(1, 2, 840, 10045, 4, 3, 2)

    /** Сравнение двух OID-массивов поэлементно. */
    fun oidEquals(a: IntArray?, b: IntArray?): Boolean {
        if (a == null || b == null) return a === b
        return a.contentEquals(b)
    }

    /** Сравнение строкового OID (из ASN.1) с IntArray. */
    fun oidEquals(str: String?, oid: IntArray?): Boolean =
        !str.isNullOrEmpty() && oid != null && str == oidString(oid)

    /** Преобразование IntArray в строку «1.2.840.…». */
    fun oidString(oid: IntArray?): String = oid?.joinToString(".") ?: ""

    /** Разбор строки OID в IntArray; при ошибке — null. */
    fun parseOidToIntArray(oidStr: String?): IntArray? {
        if (oidStr.isNullOrBlank()) return null
        return try {
            oidStr.split('.').map { it.toInt() }.toIntArray()
        } catch (_: NumberFormatException) {
            null
        }
    }
}
