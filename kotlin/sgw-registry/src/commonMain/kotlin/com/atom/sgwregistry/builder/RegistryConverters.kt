package com.atom.sgwregistry.builder

import com.atom.sgwregistry.asn1.AttributeDecoder
import com.atom.sgwregistry.crypto.CertificateCache
import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.model.RegistryContainer
import com.atom.sgwregistry.model.SafeBagInfo
import com.atom.sgwregistry.model.SafeBagInput
import com.atom.sgwregistry.model.SignerAttrs
import com.atom.sgwregistry.util.EPOCH_INSTANT

object RegistryConverters {
    fun safeBagInfosToInputs(infos: List<SafeBagInfo>): List<SafeBagInput> =
        infos.mapNotNull { info ->
            val der = info.certValueDer ?: return@mapNotNull null
            SafeBagInput(
                certDer = der,
                roleName = info.roleName,
                roleNotBefore = info.roleNotBefore,
                roleNotAfter = info.roleNotAfter,
                localKeyId = info.localKeyId?.copyOf(),
            )
        }

    fun bagMatchesSkid(
        bag: SafeBagInput,
        subjectKeyId: ByteArray,
        certCache: CertificateCache? = null,
    ): Boolean {
        if (subjectKeyId.isEmpty()) return false
        bag.localKeyId?.let { if (it.contentEquals(subjectKeyId)) return true }
        if (bag.certDer.isEmpty()) return false
        val cert = certCache?.tryLoad(bag.certDer)
            ?: try {
                PlatformCrypto.parseCertificate(bag.certDer)
            } catch (_: Exception) {
                return false
            }
        return PlatformCrypto.getSubjectKeyId(cert).contentEquals(subjectKeyId)
    }

    fun skidHex(subjectKeyId: ByteArray): String = PemEncoding.skidToHex(subjectKeyId)

    fun extractSignerAttrs(container: RegistryContainer): SignerAttrs {
        val attrs = AttributeDecoder.parseAuthenticatedAttributes(container.authenticatedAttributesSetBytes)
        if (attrs.isEmpty()) {
            throw IllegalStateException("Cannot extract SignerAttrs: authenticatedAttributes missing or empty")
        }
        var vin = ""
        var uid = ""
        var verTimestamp = EPOCH_INSTANT
        var verVersion = 0
        var verPresent = false
        for ((name, value) in attrs) {
            when (name) {
                "VIN" -> vin = value
                "UID" -> uid = value
                "VER" -> {
                    val (ts, ver) = VerAttribute.parseText(value)
                    verTimestamp = ts
                    verVersion = ver
                    verPresent = true
                }
            }
        }
        require(verPresent) {
            "VER attribute required in registry (format yyyy-MM-dd HH:mm:ss:Vn)"
        }
        require(vin.isNotEmpty() || uid.isNotEmpty()) {
            "Cannot extract SignerAttrs: VIN and UID are both empty"
        }
        return SignerAttrs(vin, verTimestamp, verVersion, uid)
    }
}
