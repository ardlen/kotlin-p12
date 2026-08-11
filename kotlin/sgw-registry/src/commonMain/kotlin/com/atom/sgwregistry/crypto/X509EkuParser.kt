package com.atom.sgwregistry.crypto

import com.atom.sgwregistry.asn1.AsnReader
import com.atom.sgwregistry.asn1.DerUtils

/**
 * Extended Key Usage (2.5.29.37) из X.509 DER.
 *
 * Для CMS cloud_config ожидается Email Protection (`1.3.6.1.5.5.7.3.4`),
 * не TLS Web Client Authentication (`1.3.6.1.5.5.7.3.2`).
 */
internal object X509EkuParser {
    private const val OID_EKU = "2.5.29.37"

    fun extractOids(certDer: ByteArray): List<String> {
        val oids = ArrayList<String>()
        val cert = AsnReader(certDer).readSequence()
        val tbs = cert.readSequence()
        if (tbs.peekTag() == 0xA0) {
            tbs.readContextSpecific(0).readInteger()
        }
        tbs.readIntegerBytes()
        tbs.readSequence()
        tbs.readEncodedValue()
        tbs.readSequence()
        tbs.readEncodedValue()
        tbs.readEncodedValue()
        val extCtx = tbs.tryReadContextSpecific(3) ?: return emptyList()
        val extensions = extCtx.readSequence()
        while (extensions.hasData()) {
            val ext = extensions.readSequence()
            val oid = ext.readObjectIdentifierString()
            if (ext.peekTag() == 0x01) ext.readEncodedValue()
            if (oid != OID_EKU) {
                while (ext.hasData()) ext.readEncodedValue()
                continue
            }
            var value = ext.readOctetString()
            while (value.isNotEmpty() && value[0].toInt() == DerUtils.TAG_OCTET_STRING) {
                val next = DerUtils.unwrapOctetString(value) ?: break
                if (next.size >= value.size) break
                value = next
            }
            val seq = AsnReader(value).readSequence()
            while (seq.hasData()) {
                oids.add(seq.readObjectIdentifierString())
            }
        }
        return oids
    }
}
