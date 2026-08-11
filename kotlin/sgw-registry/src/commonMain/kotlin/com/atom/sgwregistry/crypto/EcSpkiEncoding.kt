package com.atom.sgwregistry.crypto

import com.atom.sgwregistry.asn1.AsnReader
import com.atom.sgwregistry.asn1.AsnWriter
import com.atom.sgwregistry.asn1.DerUtils
import com.atom.sgwregistry.asn1.Oids

/**
 * SubjectPublicKeyInfo (SPKI) для P-256 из SEC1 / PKCS#8 EC private key.
 * Нужен для PKCS#10 CSR без JCA/BouncyCastle.
 */
object EcSpkiEncoding {
    /**
     * Достаёт uncompressed point (0x04‖X‖Y) из EC PRIVATE KEY / PKCS#8 и кодирует SPKI.
     */
    fun spkiFromEcPrivateKeyPemOrDer(pemOrDer: ByteArray): ByteArray {
        val der = PemEncoding.decodePemOrDer(pemOrDer)
        val sec1 = if (PemEncoding.isPem(pemOrDer)) {
            when (PemEncoding.detectPemLabel(pemOrDer.decodeToString())) {
                "EC PRIVATE KEY" -> der
                "PRIVATE KEY" -> unwrapPkcs8(der)
                else -> throw IllegalArgumentException("Expected EC PRIVATE KEY or PRIVATE KEY PEM")
            }
        } else {
            // SEC1 starts with SEQUENCE { INTEGER version, OCTET STRING ... }
            // PKCS#8 also SEQUENCE { INTEGER, SEQUENCE alg, OCTET STRING }
            if (looksLikePkcs8(der)) unwrapPkcs8(der) else der
        }
        val point = extractUncompressedPointFromSec1(sec1)
        return encodeSpkiP256(point)
    }

    fun encodeSpkiP256(uncompressedPoint: ByteArray): ByteArray {
        require(uncompressedPoint.isNotEmpty() && uncompressedPoint[0] == 0x04.toByte()) {
            "Expected uncompressed EC point (0x04‖X‖Y)"
        }
        val w = AsnWriter()
        w.pushSequence()
        w.pushSequence()
        w.writeObjectIdentifier(Oids.ecPublicKey)
        w.writeObjectIdentifier(Oids.prime256v1)
        w.popSequence()
        w.writeBitString(uncompressedPoint, unusedBits = 0)
        w.popSequence()
        return w.encode()
    }

    private fun extractUncompressedPointFromSec1(sec1: ByteArray): ByteArray {
        val seq = AsnReader(sec1).readSequence()
        seq.readInteger()
        seq.readOctetString() // private key
        seq.tryReadContextSpecific(0) // parameters
        val pubCtx = seq.tryReadContextSpecific(1)
            ?: throw IllegalArgumentException("EC PRIVATE KEY must include publicKey [1] for CSR")
        val bitStringTlv = pubCtx.readEncodedValue()
        return readBitStringContent(bitStringTlv)
    }

    private fun unwrapPkcs8(der: ByteArray): ByteArray {
        val seq = AsnReader(der).readSequence()
        seq.readInteger()
        seq.readSequence()
        return seq.readOctetString()
    }

    private fun looksLikePkcs8(der: ByteArray): Boolean {
        return try {
            val seq = AsnReader(der).readSequence()
            seq.readInteger()
            val alg = seq.readSequence()
            val oid = alg.readObjectIdentifierString()
            oid.contains("1.2.840.10045.2.1") || oid.contains("1.2.840.113549.1.1.1")
        } catch (_: Exception) {
            false
        }
    }

    private fun readBitStringContent(tlv: ByteArray): ByteArray {
        require(tlv.isNotEmpty() && (tlv[0].toInt() and 0xFF) == 0x03) { "Expected BIT STRING" }
        val (_, nlen, ok) = DerUtils.parseLength(tlv, 1)
        require(ok) { "Invalid BIT STRING length" }
        val start = 1 + nlen
        require(start < tlv.size) { "Empty BIT STRING" }
        val unused = tlv[start].toInt() and 0xFF
        require(unused == 0) { "Non-zero unused bits in publicKey BIT STRING" }
        return tlv.copyOfRange(start + 1, tlv.size)
    }
}
