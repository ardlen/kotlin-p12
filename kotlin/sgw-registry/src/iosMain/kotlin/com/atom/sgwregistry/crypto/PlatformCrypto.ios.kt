@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package com.atom.sgwregistry.crypto

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi

actual class SigningKey internal constructor(
    internal val secKey: SecKeyRef,
) {
    actual val native: Any get() = secKey as Any

    override fun equals(other: Any?): Boolean = other is SigningKey && secKeysEqual(secKey, other.secKey)

    override fun hashCode(): Int = secKey.hashCode()
}

actual object PlatformCrypto {
    actual fun sha256(data: ByteArray): ByteArray = sha256Digest(data)

    actual fun parseCertificate(der: ByteArray): PlatformCertificate =
        X509DerParser.parse(PemEncoding.decodePemOrDer(der))

    actual fun parseEcPrivateKey(pemOrDer: ByteArray): SigningKey =
        SigningKey(parseEcPrivateKeyDer(pemOrDer))

    actual fun getSubjectKeyId(cert: PlatformCertificate): ByteArray =
        if (cert.subjectKeyId.isNotEmpty()) cert.subjectKeyId else X509DerParser.parse(cert.der).subjectKeyId

    actual fun signHashEcdsaDer(key: SigningKey, hash: ByteArray): ByteArray =
        signDigestEcdsaDer(key.secKey, hash)

    actual fun verifyHashEcdsaDer(cert: PlatformCertificate, hash: ByteArray, sigDer: ByteArray): Boolean {
        val publicKey = createPublicSecKeyFromSpki(cert.publicKeyDer)
        return verifyDigestEcdsaDer(publicKey, hash, sigDer)
    }
}
