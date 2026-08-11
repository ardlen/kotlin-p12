package com.atom.sgwregistry.csr

import com.atom.sgwregistry.asn1.AsnWriter
import com.atom.sgwregistry.asn1.Oids
import com.atom.sgwregistry.cloudconfig.CloudConfigCms
import com.atom.sgwregistry.crypto.EcSpkiEncoding
import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.crypto.SigningKey

/**
 * PKCS#10 CSR для Ownership leaf — без BouncyCastle.
 *
 * Собирает `extensionRequest` с SAN `atombus:/user/{ownerId}` и EKU Email Protection,
 * подписывает ECDSA-SHA256 через [PlatformCrypto].
 */
object OwnershipCsr {
    /**
     * CSR из EC private key PEM/DER (SEC1 должен содержать publicKey [1]).
     */
    fun buildFromEcPrivateKeyPem(
        request: OwnershipCsrRequest,
        ecPrivateKeyPemOrDer: ByteArray,
    ): OwnershipCsrResult {
        val spki = EcSpkiEncoding.spkiFromEcPrivateKeyPemOrDer(ecPrivateKeyPemOrDer)
        val key = PlatformCrypto.parseEcPrivateKey(ecPrivateKeyPemOrDer)
        return build(request, key, spki)
    }

    /**
     * CSR из уже разобранного ключа + SPKI (SubjectPublicKeyInfo DER).
     */
    fun build(
        request: OwnershipCsrRequest,
        key: SigningKey,
        publicKeySpki: ByteArray,
    ): OwnershipCsrResult {
        require(request.ownerId.isNotBlank()) { "ownerId is blank" }
        require(request.includeEmailProtectionEku || request.includeClientAuthEku) {
            "at least one EKU required (emailProtection recommended for cloud_config CMS)"
        }
        val sanUri = CloudConfigCms.OWNER_SAN_URI_PREFIX + request.ownerId.trim()
        val infoDer = encodeCertificationRequestInfo(request, publicKeySpki, sanUri)
        val digest = PlatformCrypto.sha256(infoDer)
        val signatureDer = PlatformCrypto.signHashEcdsaDer(key, digest)
        val csrDer = encodeCertificationRequest(infoDer, signatureDer)
        return OwnershipCsrResult(
            csrDer = csrDer,
            csrPem = PemEncoding.csrToPem(csrDer),
            publicKeySpki = publicKeySpki.copyOf(),
            ownerId = request.ownerId.trim(),
            sanUri = sanUri,
        )
    }

    fun buildToPem(request: OwnershipCsrRequest, ecPrivateKeyPemOrDer: ByteArray): String =
        buildFromEcPrivateKeyPem(request, ecPrivateKeyPemOrDer).csrPem

    private fun encodeCertificationRequestInfo(
        request: OwnershipCsrRequest,
        publicKeySpki: ByteArray,
        sanUri: String,
    ): ByteArray {
        val w = AsnWriter()
        w.pushSequence()
        w.writeInteger(0) // version v1
        w.writeEncodedValue(encodeSubject(request))
        w.writeEncodedValue(publicKeySpki)
        // attributes [0] IMPLICIT SET OF Attribute
        w.pushSequence(0)
        w.writeEncodedValue(encodeExtensionRequestAttribute(request, sanUri))
        w.popSequence()
        w.popSequence()
        return w.encode()
    }

    private fun encodeCertificationRequest(infoDer: ByteArray, signatureDer: ByteArray): ByteArray {
        val w = AsnWriter()
        w.pushSequence()
        w.writeEncodedValue(infoDer)
        w.pushSequence()
        w.writeObjectIdentifier(Oids.ecdsaWithSha256)
        // ECDSA algorithm params ABSENT (no NULL), как в OpenSSL / RFC 5758
        w.popSequence()
        w.writeBitString(signatureDer, unusedBits = 0)
        w.popSequence()
        return w.encode()
    }

    private fun encodeSubject(request: OwnershipCsrRequest): ByteArray {
        val w = AsnWriter()
        w.pushSequence() // RDNSequence
        w.writeEncodedValue(rdn(Oids.attrOrganizationName, request.organization))
        for (ou in request.organizationalUnits) {
            if (ou.isNotBlank()) {
                w.writeEncodedValue(rdn(Oids.attrOrganizationalUnitName, ou))
            }
        }
        w.writeEncodedValue(rdn(Oids.attrUid, request.ownerId.trim()))
        w.popSequence()
        return w.encode()
    }

    private fun rdn(oid: IntArray, value: String): ByteArray {
        val w = AsnWriter()
        w.pushSetOf()
        w.pushSequence()
        w.writeObjectIdentifier(oid)
        // PrintableString — как у ATOM Ownership leaf (C/O/OU/UID)
        w.writePrintableString(value)
        w.popSequence()
        w.popSequence()
        return w.encode()
    }

    private fun encodeExtensionRequestAttribute(
        request: OwnershipCsrRequest,
        sanUri: String,
    ): ByteArray {
        val extensions = encodeExtensions(request, sanUri)
        val w = AsnWriter()
        w.pushSequence()
        w.writeObjectIdentifier(Oids.pkcs9ExtensionRequest)
        w.pushSetOf()
        w.writeEncodedValue(extensions)
        w.popSequence()
        w.popSequence()
        return w.encode()
    }

    private fun encodeExtensions(request: OwnershipCsrRequest, sanUri: String): ByteArray {
        val w = AsnWriter()
        w.pushSequence() // Extensions ::= SEQUENCE OF Extension
        if (request.includeKeyUsageDigitalSignature) {
            w.writeEncodedValue(encodeExtension(Oids.extensionKeyUsage, critical = true, encodeKeyUsageDigitalSignature()))
        }
        w.writeEncodedValue(
            encodeExtension(
                Oids.extensionExtendedKeyUsage,
                critical = false,
                encodeEku(request),
            ),
        )
        w.writeEncodedValue(
            encodeExtension(
                Oids.extensionSubjectAltName,
                critical = false,
                encodeSanUri(sanUri),
            ),
        )
        w.popSequence()
        return w.encode()
    }

    private fun encodeExtension(oid: IntArray, critical: Boolean, value: ByteArray): ByteArray {
        val w = AsnWriter()
        w.pushSequence()
        w.writeObjectIdentifier(oid)
        if (critical) w.writeBoolean(true)
        w.writeOctetString(value)
        w.popSequence()
        return w.encode()
    }

    /** KeyUsage digitalSignature (bit 0) → BIT STRING unused=7, content=0x80. */
    private fun encodeKeyUsageDigitalSignature(): ByteArray {
        val w = AsnWriter()
        w.writeBitString(byteArrayOf(0x80.toByte()), unusedBits = 7)
        return w.encode()
    }

    private fun encodeEku(request: OwnershipCsrRequest): ByteArray {
        val w = AsnWriter()
        w.pushSequence()
        if (request.includeEmailProtectionEku) {
            w.writeObjectIdentifier(Oids.idKpEmailProtection)
        }
        if (request.includeClientAuthEku) {
            w.writeObjectIdentifier(Oids.idKpClientAuth)
        }
        w.popSequence()
        return w.encode()
    }

    /** GeneralNames: URI [6] IMPLICIT IA5String. */
    private fun encodeSanUri(uri: String): ByteArray {
        val w = AsnWriter()
        w.pushSequence()
        // context-specific primitive [6] = 0x86 + IA5 bytes (IMPLICIT)
        w.writeEncodedValue(com.atom.sgwregistry.asn1.DerUtils.prependTlv(0x86, uri.encodeToByteArray()))
        w.popSequence()
        return w.encode()
    }
}
