package com.atom.sgwregistry.crypto

import com.atom.sgwregistry.internal.contentEqualsNullable
import kotlinx.datetime.Instant

/** Opaque platform signing key (JCA PrivateKey on JVM/Android, native key on iOS). */
expect class SigningKey {
    internal val native: Any
}

/** Parsed X.509 certificate used across platforms. */
data class PlatformCertificate(
    val subject: String = "",
    val issuer: String = "",
    val serialHex: String = "",
    val serialBytes: ByteArray = byteArrayOf(),
    val issuerDer: ByteArray = byteArrayOf(),
    val notBefore: Instant,
    val notAfter: Instant,
    val keyAlgorithm: String = "",
    val der: ByteArray,
    val publicKeyDer: ByteArray = byteArrayOf(),
    val subjectKeyId: ByteArray = byteArrayOf(),
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PlatformCertificate) return false
        return subject == other.subject &&
            issuer == other.issuer &&
            serialHex == other.serialHex &&
            serialBytes.contentEquals(other.serialBytes) &&
            issuerDer.contentEquals(other.issuerDer) &&
            notBefore == other.notBefore &&
            notAfter == other.notAfter &&
            keyAlgorithm == other.keyAlgorithm &&
            der.contentEquals(other.der) &&
            publicKeyDer.contentEquals(other.publicKeyDer) &&
            subjectKeyId.contentEquals(other.subjectKeyId)
    }

    override fun hashCode(): Int {
        var result = subject.hashCode()
        result = 31 * result + issuer.hashCode()
        result = 31 * result + serialHex.hashCode()
        result = 31 * result + serialBytes.contentHashCode()
        result = 31 * result + issuerDer.contentHashCode()
        result = 31 * result + notBefore.hashCode()
        result = 31 * result + notAfter.hashCode()
        result = 31 * result + keyAlgorithm.hashCode()
        result = 31 * result + der.contentHashCode()
        result = 31 * result + publicKeyDer.contentHashCode()
        result = 31 * result + subjectKeyId.contentHashCode()
        return result
    }
}
