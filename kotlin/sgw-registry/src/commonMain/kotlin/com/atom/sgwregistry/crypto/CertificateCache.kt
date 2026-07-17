package com.atom.sgwregistry.crypto

/** Кэш [PlatformCertificate] по ссылке на DER-буфер в рамках одного parse(). */
class CertificateCache {
    private val byDer = mutableMapOf<ByteArray, PlatformCertificate>()

    fun load(certDer: ByteArray): PlatformCertificate =
        byDer.getOrPut(certDer) { PlatformCrypto.parseCertificate(certDer) }

    fun tryLoad(certDer: ByteArray): PlatformCertificate? = try {
        load(certDer)
    } catch (_: Exception) {
        null
    }
}
