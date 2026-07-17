/**
 * Сборка CMS SignedData для mob-dev `cloud_config_pem`.
 */
package com.atom.sgwregistry.cloudconfig

import com.atom.sgwregistry.asn1.AsnWriter
import com.atom.sgwregistry.asn1.DerUtils
import com.atom.sgwregistry.asn1.Oids
import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.model.CloudConfigCmsContainer
import com.atom.sgwregistry.model.CloudConfigResignOnlyRequest
import com.atom.sgwregistry.model.CloudConfigResignRequest
import com.atom.sgwregistry.util.EPOCH_INSTANT
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

object CloudConfigCmsBuilder {
    fun resign(request: CloudConfigResignRequest): ByteArray {
        val eContent = request.jsonPayload.encodeToByteArray()
        return buildCmsDer(
            eContent = eContent,
            signerCertDer = request.signerCertDer,
            signerKey = request.signerKey,
            signingTime = if (request.includeSigningTime) Clock.System.now() else null,
            includeSigningCertificateV2 = request.includeSigningCertificateV2,
            useIssuerAndSerialSid = request.useIssuerAndSerialSid,
        )
    }

    fun resignToPem(request: CloudConfigResignRequest): String =
        PemEncoding.cmsToPem(resign(request))

    /**
     * Переподпись существующего CMS: eContent берётся из [container] как есть,
     * без повторного `jsonPayload.encodeToByteArray()` (без «пересборки» JSON).
     */
    fun resignOnly(
        container: CloudConfigCmsContainer,
        request: CloudConfigResignOnlyRequest,
    ): ByteArray {
        val eContent = container.eContentBytes
            ?: throw IllegalStateException("CMS eContent is absent")
        return buildCmsDer(
            eContent = eContent,
            signerCertDer = request.signerCertDer,
            signerKey = request.signerKey,
            signingTime = if (request.includeSigningTime) Clock.System.now() else null,
            includeSigningCertificateV2 = request.includeSigningCertificateV2,
            useIssuerAndSerialSid = request.useIssuerAndSerialSid,
        )
    }

    fun resignOnlyToPem(
        container: CloudConfigCmsContainer,
        request: CloudConfigResignOnlyRequest,
    ): String = PemEncoding.cmsToPem(resignOnly(container, request))

    fun buildCmsDer(
        eContent: ByteArray,
        signerCertDer: ByteArray,
        signerKey: com.atom.sgwregistry.crypto.SigningKey,
        signingTime: Instant? = Clock.System.now(),
        includeSigningCertificateV2: Boolean = true,
        useIssuerAndSerialSid: Boolean = true,
    ): ByteArray {
        val contentDigest = PlatformCrypto.sha256(eContent)
        val authAttrsDer = marshalAuthenticatedAttributes(
            contentDigest = contentDigest,
            signerCertDer = signerCertDer,
            signingTime = signingTime,
            includeSigningCertificateV2 = includeSigningCertificateV2,
        )
        val canonicalSet = DerUtils.canonicalSetDer(authAttrsDer)
            ?: throw IllegalStateException("Cannot build canonical SET for signing")
        val digestToSign = PlatformCrypto.sha256(canonicalSet)
        val signatureDer = PlatformCrypto.signHashEcdsaDer(signerKey, digestToSign)

        val signerCert = PlatformCrypto.parseCertificate(signerCertDer)
        val sidDer = if (useIssuerAndSerialSid) {
            marshalIssuerAndSerial(signerCert.issuerDer, signerCert.serialBytes)
        } else {
            val skid = PlatformCrypto.getSubjectKeyId(signerCert)
            require(skid.isNotEmpty()) { "SubjectKeyIdentifier required for SKID SID" }
            marshalSubjectKeyIdentifier(skid)
        }

        val encap = buildEncapsulatedContentInfo(eContent)
        val certSet = marshalCertificateSet(arrayOf(signerCertDer))
        val signerInfo = buildSignerInfoDer(sidDer, authAttrsDer, signatureDer)
        val signedData = buildSignedDataDer(encap, certSet, signerInfo)
        return buildContentInfoDer(signedData)
    }

    private fun marshalAuthenticatedAttributes(
        contentDigest: ByteArray,
        signerCertDer: ByteArray,
        signingTime: Instant?,
        includeSigningCertificateV2: Boolean,
    ): ByteArray {
        val list = ArrayList<ByteArray>()
        list.add(encodeAttribute(Oids.pkcs9ContentType, encodeOidValue(Oids.pkcs7Data)))
        list.add(encodeAttribute(Oids.pkcs9MessageDigest, encodeOctet(contentDigest)))
        if (signingTime != null && signingTime != EPOCH_INSTANT) {
            list.add(encodeAttribute(Oids.pkcs9SigningTime, encodeUtcTime(signingTime)))
        }
        if (includeSigningCertificateV2) {
            list.add(
                encodeAttribute(
                    Oids.pkcs9SigningCertificateV2,
                    encodeSigningCertificateV2(signerCertDer),
                ),
            )
        }
        list.sortWith { a, b -> DerUtils.compareDer(a, b) }
        val w = AsnWriter()
        w.pushSetOf()
        for (a in list) w.writeEncodedValue(a)
        w.popSequence()
        return w.encode()
    }

  private fun encodeSigningCertificateV2(signerCertDer: ByteArray): ByteArray {
        val certHash = PlatformCrypto.sha256(signerCertDer)
        val w = AsnWriter()
        w.pushSequence()
        w.pushSequence()
        w.pushSequence()
        w.writeObjectIdentifier(Oids.sha256)
        w.writeNull()
        w.popSequence()
        w.writeOctetString(certHash)
        w.popSequence()
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

    private fun encodeOidValue(oid: IntArray): ByteArray {
        val w = AsnWriter()
        w.writeObjectIdentifier(oid)
        return w.encode()
    }

    private fun encodeOctet(b: ByteArray): ByteArray {
        val w = AsnWriter()
        w.writeOctetString(b)
        return w.encode()
    }

    private fun encodeUtcTime(ts: Instant): ByteArray {
        val w = AsnWriter()
        w.writeUtcTime(ts)
        return w.encode()
    }

    private fun marshalSubjectKeyIdentifier(ski: ByteArray): ByteArray {
        val octet = AsnWriter().also { it.writeOctetString(ski) }.encode()
        return DerUtils.prependTlv(0xA0, octet)
    }

    private fun marshalIssuerAndSerial(issuerDer: ByteArray, serialBytes: ByteArray): ByteArray {
        val inner = AsnWriter()
        inner.pushSequence()
        inner.writeEncodedValue(issuerDer)
        inner.writeIntegerBytes(serialBytes)
        inner.popSequence()
        return DerUtils.prependTlv(0xA1, inner.encode())
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
}
