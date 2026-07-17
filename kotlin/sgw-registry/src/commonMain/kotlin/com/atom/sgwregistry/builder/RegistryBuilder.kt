/**
 * Сборка ATOM-PKCS12-REGISTRY (PFX v3 + CMS SignedData).
 */
package com.atom.sgwregistry.builder

import com.atom.sgwregistry.api.RegistryBuilderService
import com.atom.sgwregistry.asn1.AsnWriter
import com.atom.sgwregistry.asn1.DerUtils
import com.atom.sgwregistry.asn1.Oids
import com.atom.sgwregistry.crypto.CertificateCache
import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.crypto.SigningKey
import com.atom.sgwregistry.model.AddCertificateRequest
import com.atom.sgwregistry.model.BuildConfig
import com.atom.sgwregistry.model.RegistryContainer
import com.atom.sgwregistry.model.RemoveCertificateBySkidRequest
import com.atom.sgwregistry.model.SafeBagInput
import com.atom.sgwregistry.model.SignerAttrs
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.util.EPOCH_INSTANT
import com.atom.sgwregistry.util.isEpoch
import kotlinx.datetime.Instant

object RegistryBuilder : RegistryBuilderService {
    override fun buildRegistry(cfg: BuildConfig): ByteArray {
        val eContent = buildSafeContents(cfg.safeBags)
        return buildPfxFromContent(
            eContent,
            cfg.signerCertDer,
            cfg.signerKey,
            SignerAttrs(cfg.vin, cfg.verTimestamp, cfg.verVersion, cfg.uid),
        )
    }

    override fun buildSafeContents(safeBags: List<SafeBagInput>): ByteArray {
        val w = AsnWriter()
        val certCache = CertificateCache()
        w.pushSequence()
        for (bag in safeBags) writeSafeBag(w, bag, certCache)
        w.popSequence()
        return w.encode()
    }

    override fun addCertificateAndResign(request: AddCertificateRequest): ByteArray {
        require(request.existingP12.isNotEmpty()) { "existingP12 is empty" }
        val container = RegistryParser.parse(request.existingP12)
        return addCertificateAndResign(container, request)
    }

    override fun addCertificateAndResign(container: RegistryContainer, request: AddCertificateRequest): ByteArray {
        val attrs = VerAttribute.resolveForRegistryUpdate(container, request.signerAttrs)
        val existingBags = RegistryConverters.safeBagInfosToInputs(container.safeBagInfos)
        if (request.rejectDuplicateCert &&
            existingBags.any { it.certDer.contentEquals(request.newBag.certDer) }
        ) {
            throw IllegalArgumentException("Certificate already present in registry SafeContents")
        }
        return resignWithSafeBags(
            safeBags = existingBags + request.newBag,
            signerCertDer = request.signerCertDer,
            signerKey = request.signerKey,
            attrs = attrs,
        )
    }

    override fun removeCertificateBySkidAndResign(request: RemoveCertificateBySkidRequest): ByteArray {
        require(request.existingP12.isNotEmpty()) { "existingP12 is empty" }
        require(request.subjectKeyId.isNotEmpty()) { "subjectKeyId is empty" }
        val container = RegistryParser.parse(request.existingP12)
        return removeCertificateBySkidAndResign(container, request)
    }

    override fun removeCertificateBySkidAndResign(
        container: RegistryContainer,
        request: RemoveCertificateBySkidRequest,
    ): ByteArray {
        require(request.subjectKeyId.isNotEmpty()) { "subjectKeyId is empty" }
        val attrs = VerAttribute.resolveForRegistryUpdate(container, request.signerAttrs)
        val existingBags = RegistryConverters.safeBagInfosToInputs(container.safeBagInfos)
        val skid = request.subjectKeyId
        val certCache = CertificateCache()
        val matchCount = existingBags.count { RegistryConverters.bagMatchesSkid(it, skid, certCache) }
        when {
            matchCount == 0 -> throw IllegalArgumentException(
                "No SafeBag with SubjectKeyIdentifier ${RegistryConverters.skidHex(skid)}",
            )
            matchCount > 1 && !request.removeAllMatches -> throw IllegalArgumentException(
                "Multiple SafeBags ($matchCount) match SKID ${RegistryConverters.skidHex(skid)}; " +
                    "set removeAllMatches=true to remove all",
            )
        }
        val remaining = existingBags.filterNot { RegistryConverters.bagMatchesSkid(it, skid, certCache) }
        return resignWithSafeBags(
            safeBags = remaining,
            signerCertDer = request.signerCertDer,
            signerKey = request.signerKey,
            attrs = attrs,
        )
    }

    fun removeCertificateBySkidAndResign(
        existingP12: ByteArray,
        subjectKeyIdHex: String,
        signerCertDer: ByteArray,
        signerKey: SigningKey,
        signerAttrs: SignerAttrs? = null,
        removeAllMatches: Boolean = false,
    ): ByteArray = removeCertificateBySkidAndResign(
        RemoveCertificateBySkidRequest(
            existingP12 = existingP12,
            subjectKeyId = PemEncoding.decodeSkidHex(subjectKeyIdHex),
            signerCertDer = signerCertDer,
            signerKey = signerKey,
            signerAttrs = signerAttrs,
            removeAllMatches = removeAllMatches,
        ),
    )

    fun resignWithSafeBags(
        safeBags: List<SafeBagInput>,
        signerCertDer: ByteArray,
        signerKey: SigningKey,
        attrs: SignerAttrs,
    ): ByteArray {
        VerAttribute.requirePresent(attrs)
        val eContent = buildSafeContents(safeBags)
        return buildPfxFromContent(eContent, signerCertDer, signerKey, attrs)
    }

    private fun writeSafeBag(w: AsnWriter, input: SafeBagInput, certCache: CertificateCache) {
        w.pushSequence()
        w.writeObjectIdentifier(Oids.certBag)
        w.pushSequence(0)
        writeCertBag(w, input.certDer)
        w.popSequence()
        writeBagAttributes(w, input, certCache)
        w.popSequence()
    }

    private fun writeCertBag(w: AsnWriter, certDer: ByteArray) {
        w.pushSequence()
        w.writeObjectIdentifier(Oids.x509Certificate)
        w.pushSequence(0)
        w.writeOctetString(certDer)
        w.popSequence()
        w.popSequence()
    }

    private fun writeBagAttributes(w: AsnWriter, input: SafeBagInput, certCache: CertificateCache) {
        val attrs = ArrayList<ByteArray>()
        if (input.roleName.isNotEmpty()) {
            attrs.add(encodeAttribute(Oids.atomRoleName, encodeUtf8(input.roleName)))
        }
        if (!isEpoch(input.roleNotBefore) || !isEpoch(input.roleNotAfter)) {
            attrs.add(encodeAttribute(Oids.atomRoleValidityPeriod, encodeRoleValidity(input.roleNotBefore, input.roleNotAfter)))
        }
        var localKeyId = input.localKeyId
        if (localKeyId == null && input.certDer.isNotEmpty()) {
            localKeyId = certCache.tryLoad(input.certDer)?.let { PlatformCrypto.getSubjectKeyId(it) }
        }
        if (localKeyId != null && localKeyId.isNotEmpty()) {
            attrs.add(encodeAttribute(Oids.pkcs9LocalKeyId, encodeOctet(localKeyId)))
        }
        if (attrs.isEmpty()) return
        attrs.sortWith { a, b -> DerUtils.compareDer(a, b) }
        w.pushSetOf()
        for (a in attrs) w.writeEncodedValue(a)
        w.popSequence()
    }

    private fun buildPfxFromContent(
        eContent: ByteArray,
        signerCertDer: ByteArray,
        signerKey: SigningKey,
        attrs: SignerAttrs,
    ): ByteArray {
        VerAttribute.requirePresent(attrs)
        val contentDigest = PlatformCrypto.sha256(eContent)
        val authAttrsDer = marshalAuthenticatedAttributes(contentDigest, attrs)
        val canonicalSet = DerUtils.canonicalSetDer(authAttrsDer)
            ?: throw IllegalStateException("Cannot build canonical SET for signing")
        val digestToSign = PlatformCrypto.sha256(canonicalSet)
        val signatureDer = PlatformCrypto.signHashEcdsaDer(signerKey, digestToSign)

        val encap = buildEncapsulatedContentInfo(eContent)
        val certSet = marshalCertificateSet(arrayOf(signerCertDer))
        val signerCert = PlatformCrypto.parseCertificate(signerCertDer)
        val skid = PlatformCrypto.getSubjectKeyId(signerCert)
        val sidDer = marshalSubjectKeyIdentifier(skid)
        val signerInfo = buildSignerInfoDer(sidDer, authAttrsDer, signatureDer)
        val signedData = buildSignedDataDer(encap, certSet, signerInfo)
        val contentInfo = buildContentInfoDer(signedData)
        return buildPfx(contentInfo)
    }

    private fun marshalAuthenticatedAttributes(contentDigest: ByteArray, attrs: SignerAttrs): ByteArray {
        val list = ArrayList<ByteArray>()
        list.add(encodeAttribute(Oids.pkcs9ContentType, encodeOidValue(Oids.pkcs7Data)))
        if (attrs.vin.isNotEmpty()) list.add(encodeAttribute(Oids.atomVin, encodeUtf8(attrs.vin)))
        if (!isEpoch(attrs.verTimestamp) || attrs.verVersion != 0) {
            list.add(encodeAttribute(Oids.atomVer, encodeVerValue(attrs.verTimestamp, attrs.verVersion)))
        }
        if (attrs.uid.isNotEmpty()) list.add(encodeAttribute(Oids.atomUid, encodeUtf8(attrs.uid)))
        list.add(encodeAttribute(Oids.pkcs9MessageDigest, encodeOctet(contentDigest)))
        list.sortWith { a, b -> DerUtils.compareDer(a, b) }
        val w = AsnWriter()
        w.pushSetOf()
        for (a in list) w.writeEncodedValue(a)
        w.popSequence()
        return w.encode()
    }

    private fun encodeAttribute(oid: IntArray, value: ByteArray): ByteArray {
        val w = AsnWriter()
        w.pushSequence()
        w.writeObjectIdentifier(oid)
        w.pushSetOf()
        w.writeEncodedValue(value)
        w.popSequence()
        w.popSequence()
        return w.encode()
    }

    private fun encodeUtf8(s: String): ByteArray {
        val w = AsnWriter()
        w.writeUtf8String(s)
        return w.encode()
    }

    private fun encodeOctet(b: ByteArray): ByteArray {
        val w = AsnWriter()
        w.writeOctetString(b)
        return w.encode()
    }

    private fun encodeOidValue(oid: IntArray): ByteArray {
        val w = AsnWriter()
        w.writeObjectIdentifier(oid)
        return w.encode()
    }

    private fun encodeVerValue(ts: Instant, ver: Int): ByteArray {
        val w = AsnWriter()
        w.pushSequence()
        w.writeGeneralizedTime(ts)
        w.writeInteger(ver)
        w.popSequence()
        return w.encode()
    }

    private fun encodeRoleValidity(nb: Instant, na: Instant): ByteArray {
        val w = AsnWriter()
        w.pushSequence()
        w.writeGeneralizedTime(nb)
        w.writeGeneralizedTime(na)
        w.popSequence()
        return w.encode()
    }

    private fun buildEncapsulatedContentInfo(eContent: ByteArray): ByteArray {
        val w = AsnWriter()
        w.pushSequence()
        w.writeObjectIdentifier(Oids.pkcs7Data)
        w.pushSequence(0)
        w.writeOctetString(eContent)
        w.popSequence()
        w.popSequence()
        return w.encode()
    }

    private fun marshalCertificateSet(certsRaw: Array<ByteArray>): ByteArray {
        val list = certsRaw.map { raw ->
            val ow = AsnWriter()
            ow.writeOctetString(raw)
            ow.encode()
        }.sortedWith { a, b -> DerUtils.compareDer(a, b) }
        val w = AsnWriter()
        w.pushSetOf()
        for (c in list) w.writeEncodedValue(c)
        w.popSequence()
        return w.encode()
    }

    private fun marshalSubjectKeyIdentifier(ski: ByteArray): ByteArray {
        require(ski.isNotEmpty()) { "SubjectKeyIdentifier required" }
        val octet = AsnWriter().also { it.writeOctetString(ski) }.encode()
        return DerUtils.prependTlv(0xA0, octet)
    }

    private fun buildSignerInfoDer(sidDer: ByteArray, authAttrsDer: ByteArray, signatureDer: ByteArray): ByteArray {
        val w = AsnWriter()
        w.pushSequence()
        w.writeInteger(1)
        w.writeEncodedValue(sidDer)
        w.pushSequence()
        w.writeObjectIdentifier(Oids.sha256)
        w.writeNull()
        w.popSequence()
        w.pushSequence(0)
        w.writeEncodedValue(authAttrsDer)
        w.popSequence()
        w.pushSequence()
        w.writeObjectIdentifier(Oids.ecdsaWithSha256)
        w.writeNull()
        w.popSequence()
        w.writeOctetString(signatureDer)
        w.pushSequence(1)
        w.writeEncodedValue(byteArrayOf(0x31, 0x00))
        w.popSequence()
        w.popSequence()
        return w.encode()
    }

    private fun buildSignedDataDer(encap: ByteArray, certSet: ByteArray, signerInfo: ByteArray): ByteArray {
        val w = AsnWriter()
        w.pushSequence()
        w.writeInteger(1)
        w.pushSetOf()
        w.pushSequence()
        w.writeObjectIdentifier(Oids.sha256)
        w.writeNull()
        w.popSequence()
        w.popSequence()
        w.writeEncodedValue(encap)
        w.pushSequence(0)
        w.writeEncodedValue(certSet)
        w.popSequence()
        w.pushSetOf()
        w.writeEncodedValue(signerInfo)
        w.popSequence()
        w.popSequence()
        return w.encode()
    }

    private fun buildContentInfoDer(signedData: ByteArray): ByteArray {
        val w = AsnWriter()
        w.pushSequence()
        w.writeObjectIdentifier(Oids.pkcs7SignedData)
        w.pushSequence(0)
        w.writeEncodedValue(signedData)
        w.popSequence()
        w.popSequence()
        return w.encode()
    }

    private fun buildPfx(contentInfo: ByteArray): ByteArray {
        val w = AsnWriter()
        w.pushSequence()
        w.writeInteger(3)
        w.writeEncodedValue(contentInfo)
        w.popSequence()
        return w.encode()
    }
}
