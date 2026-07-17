/**
 * Доменные модели ATOM-PKCS12-REGISTRY.
 */
package com.atom.sgwregistry.model

import com.atom.sgwregistry.crypto.SigningKey
import com.atom.sgwregistry.internal.contentEqualsNullable
import com.atom.sgwregistry.internal.copyImmutable
import com.atom.sgwregistry.internal.copyImmutableList
import com.atom.sgwregistry.internal.copySafeBagInfos
import com.atom.sgwregistry.util.EPOCH_INSTANT
import kotlinx.datetime.Instant

data class SafeBagInput(
    val certDer: ByteArray,
    val roleName: String = "",
    val roleNotBefore: Instant = EPOCH_INSTANT,
    val roleNotAfter: Instant = EPOCH_INSTANT,
    val localKeyId: ByteArray? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SafeBagInput) return false
        return certDer.contentEquals(other.certDer) &&
            roleName == other.roleName &&
            roleNotBefore == other.roleNotBefore &&
            roleNotAfter == other.roleNotAfter &&
            localKeyId.contentEqualsNullable(other.localKeyId)
    }

    override fun hashCode(): Int {
        var result = certDer.contentHashCode()
        result = 31 * result + roleName.hashCode()
        result = 31 * result + roleNotBefore.hashCode()
        result = 31 * result + roleNotAfter.hashCode()
        result = 31 * result + (localKeyId?.contentHashCode() ?: 0)
        return result
    }
}

data class SignerAttrs(
    val vin: String = "",
    val verTimestamp: Instant = EPOCH_INSTANT,
    val verVersion: Int = 0,
    val uid: String = "",
)

data class BuildConfig(
    val signerCertDer: ByteArray,
    val signerKey: SigningKey,
    val vin: String = "",
    val verTimestamp: Instant = EPOCH_INSTANT,
    val verVersion: Int = 0,
    val uid: String = "",
    val safeBags: List<SafeBagInput> = emptyList(),
) {
    companion object {}
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BuildConfig) return false
        return signerCertDer.contentEquals(other.signerCertDer) &&
            signerKey == other.signerKey &&
            vin == other.vin &&
            verTimestamp == other.verTimestamp &&
            verVersion == other.verVersion &&
            uid == other.uid &&
            safeBags == other.safeBags
    }

    override fun hashCode(): Int {
        var result = signerCertDer.contentHashCode()
        result = 31 * result + signerKey.hashCode()
        result = 31 * result + vin.hashCode()
        result = 31 * result + verTimestamp.hashCode()
        result = 31 * result + verVersion.hashCode()
        result = 31 * result + uid.hashCode()
        result = 31 * result + safeBags.hashCode()
        return result
    }
}

data class AddCertificateRequest(
    val existingP12: ByteArray,
    val newBag: SafeBagInput,
    val signerCertDer: ByteArray,
    val signerKey: SigningKey,
    val signerAttrs: SignerAttrs? = null,
    val rejectDuplicateCert: Boolean = true,
) {
    companion object {}
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AddCertificateRequest) return false
        return existingP12.contentEquals(other.existingP12) &&
            newBag == other.newBag &&
            signerCertDer.contentEquals(other.signerCertDer) &&
            signerKey == other.signerKey &&
            signerAttrs == other.signerAttrs &&
            rejectDuplicateCert == other.rejectDuplicateCert
    }

    override fun hashCode(): Int {
        var result = existingP12.contentHashCode()
        result = 31 * result + newBag.hashCode()
        result = 31 * result + signerCertDer.contentHashCode()
        result = 31 * result + signerKey.hashCode()
        result = 31 * result + (signerAttrs?.hashCode() ?: 0)
        result = 31 * result + rejectDuplicateCert.hashCode()
        return result
    }
}

data class RemoveCertificateBySkidRequest(
    val existingP12: ByteArray,
    val subjectKeyId: ByteArray,
    val signerCertDer: ByteArray,
    val signerKey: SigningKey,
    val signerAttrs: SignerAttrs? = null,
    val removeAllMatches: Boolean = false,
) {
    companion object {}
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RemoveCertificateBySkidRequest) return false
        return existingP12.contentEquals(other.existingP12) &&
            subjectKeyId.contentEquals(other.subjectKeyId) &&
            signerCertDer.contentEquals(other.signerCertDer) &&
            signerKey == other.signerKey &&
            signerAttrs == other.signerAttrs &&
            removeAllMatches == other.removeAllMatches
    }

    override fun hashCode(): Int {
        var result = existingP12.contentHashCode()
        result = 31 * result + subjectKeyId.contentHashCode()
        result = 31 * result + signerCertDer.contentHashCode()
        result = 31 * result + signerKey.hashCode()
        result = 31 * result + (signerAttrs?.hashCode() ?: 0)
        result = 31 * result + removeAllMatches.hashCode()
        return result
    }
}

data class CertSummary(
    val subject: String = "",
    val issuer: String = "",
    val serial: String = "",
    val notBefore: String = "",
    val notAfter: String = "",
    val keyAlg: String = "",
)

data class SafeBagInfo(
    val roleName: String = "",
    val roleNotBefore: Instant = EPOCH_INSTANT,
    val roleNotAfter: Instant = EPOCH_INSTANT,
    val localKeyId: ByteArray? = null,
    val certValueDer: ByteArray? = null,
    val certSummary: CertSummary? = null,
    val bagId: String = "",
    val certId: String = "",
    val certTypeName: String = "",
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SafeBagInfo) return false
        return roleName == other.roleName &&
            roleNotBefore == other.roleNotBefore &&
            roleNotAfter == other.roleNotAfter &&
            localKeyId.contentEqualsNullable(other.localKeyId) &&
            certValueDer.contentEqualsNullable(other.certValueDer) &&
            certSummary == other.certSummary &&
            bagId == other.bagId &&
            certId == other.certId &&
            certTypeName == other.certTypeName
    }

    override fun hashCode(): Int {
        var result = roleName.hashCode()
        result = 31 * result + roleNotBefore.hashCode()
        result = 31 * result + roleNotAfter.hashCode()
        result = 31 * result + (localKeyId?.contentHashCode() ?: 0)
        result = 31 * result + (certValueDer?.contentHashCode() ?: 0)
        result = 31 * result + (certSummary?.hashCode() ?: 0)
        result = 31 * result + bagId.hashCode()
        result = 31 * result + certId.hashCode()
        result = 31 * result + certTypeName.hashCode()
        return result
    }
}

data class RegistryContainer(
    val pfxVersion: Int = 0,
    val contentType: String = "",
    val certificatesDer: List<ByteArray> = emptyList(),
    val safeBagInfos: List<SafeBagInfo> = emptyList(),
    val signerCertDer: ByteArray? = null,
    val eContentBytes: ByteArray? = null,
    val authenticatedAttributesSetBytes: ByteArray? = null,
    val encryptedDigest: ByteArray? = null,
    val digestAlgorithmOid: IntArray? = null,
    val signatureAlgorithmOid: IntArray? = null,
    val firstSignerSidTag: Int = 0,
    val signerCertResolved: Boolean = false,
    val parseWarnings: List<String> = emptyList(),
) {
    companion object {
        fun immutable(c: RegistryContainer): RegistryContainer = c.copy(
            certificatesDer = c.certificatesDer.copyImmutableList(),
            safeBagInfos = copySafeBagInfos(c.safeBagInfos),
            signerCertDer = c.signerCertDer.copyImmutable(),
            eContentBytes = c.eContentBytes.copyImmutable(),
            authenticatedAttributesSetBytes = c.authenticatedAttributesSetBytes.copyImmutable(),
            encryptedDigest = c.encryptedDigest.copyImmutable(),
            digestAlgorithmOid = c.digestAlgorithmOid?.copyOf(),
            signatureAlgorithmOid = c.signatureAlgorithmOid?.copyOf(),
            parseWarnings = c.parseWarnings.toList(),
        )
    }
}
