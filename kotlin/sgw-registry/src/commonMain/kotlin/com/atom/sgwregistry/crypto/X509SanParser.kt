package com.atom.sgwregistry.crypto

import com.atom.sgwregistry.asn1.AsnReader
import com.atom.sgwregistry.asn1.DerUtils

/**
 * Извлечение URI из X.509 Subject Alternative Name (2.5.29.17).
 *
 * ATOM Ownership leaf: `URI:atombus:/user/{owner_id}`.
 */
internal object X509SanParser {
    private const val OID_SAN = "2.5.29.17"
    /** GeneralName.uniformResourceIdentifier [6] IMPLICIT IA5String */
    private const val TAG_URI = 0x86

    fun extractUris(certDer: ByteArray): List<String> {
        val uris = ArrayList<String>()
        val cert = AsnReader(certDer).readSequence()
        val tbs = cert.readSequence()
        if (tbs.peekTag() == 0xA0) {
            tbs.readContextSpecific(0).readInteger()
        }
        tbs.readIntegerBytes() // serial
        tbs.readSequence() // signature
        tbs.readEncodedValue() // issuer
        tbs.readSequence() // validity
        tbs.readEncodedValue() // subject
        tbs.readEncodedValue() // spki
        val extCtx = tbs.tryReadContextSpecific(3) ?: return emptyList()
        val extensions = extCtx.readSequence()
        while (extensions.hasData()) {
            val ext = extensions.readSequence()
            val oid = ext.readObjectIdentifierString()
            if (ext.peekTag() == 0x01) ext.readEncodedValue() // critical BOOL
            if (oid != OID_SAN) {
                while (ext.hasData()) ext.readEncodedValue()
                continue
            }
            var value = ext.readOctetString()
            while (value.isNotEmpty() && value[0].toInt() == DerUtils.TAG_OCTET_STRING) {
                val next = DerUtils.unwrapOctetString(value) ?: break
                if (next.size >= value.size) break
                value = next
            }
            val names = AsnReader(value).readSequence()
            while (names.hasData()) {
                val tlv = names.readTlv()
                if (tlv.tag == TAG_URI) {
                    uris.add(tlvContent(tlv).decodeToString())
                }
            }
        }
        return uris
    }

    private fun tlvContent(tlv: DerUtils.Tlv): ByteArray {
        val (_, nlen, ok) = DerUtils.parseLength(tlv.tlv, 1)
        if (!ok) return byteArrayOf()
        val start = 1 + nlen
        return tlv.tlv.copyOfRange(start, tlv.tlv.size)
    }
}
