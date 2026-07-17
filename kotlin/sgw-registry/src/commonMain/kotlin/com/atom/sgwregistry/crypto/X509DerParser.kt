package com.atom.sgwregistry.crypto

import com.atom.sgwregistry.asn1.AsnReader
import com.atom.sgwregistry.asn1.DerUtils
import com.atom.sgwregistry.internal.bytesToHex
import com.atom.sgwregistry.util.parseGeneralizedTimeUtc
import kotlinx.datetime.Instant

/**
 * Minimal X.509 certificate parser (DER) without platform JCA.
 *
 * Используется на iOS ([com.atom.sgwregistry.crypto.PlatformCrypto.parseCertificate]).
 * На JVM/Android парсинг идёт через JCA; этот класс нужен для Native и для тестов DN.
 */
internal object X509DerParser {
    fun parse(der: ByteArray): PlatformCertificate {
        val cert = AsnReader(der).readSequence()
        val tbs = cert.readSequence()
        if (tbs.peekTag() == 0xA0) {
            tbs.readContextSpecific(0).readInteger()
        }
        val serialBytes = tbs.readIntegerBytes()
        val sigAlg = tbs.readSequence()
        sigAlg.readObjectIdentifierString()
        if (sigAlg.hasData()) sigAlg.readNull()
        val issuerEncoded = tbs.readEncodedValue()
        val issuer = dnToString(issuerEncoded)
        val validity = tbs.readSequence()
        val notBefore = readTime(validity)
        val notAfter = readTime(validity)
        val subjectEncoded = tbs.readEncodedValue()
        val subject = dnToString(subjectEncoded)
        val spkiDer = tbs.readEncodedValue()
        val spki = AsnReader(spkiDer).readSequence()
        val algId = spki.readSequence()
        val algOid = algId.readObjectIdentifierString()
        if (algId.hasData()) algId.readEncodedValue()
        spki.readEncodedValue() // BIT STRING
        val keyAlg = when {
            algOid.contains("1.2.840.10045.2.1") -> "EC"
            algOid.contains("1.2.840.113549.1.1.1") -> "RSA"
            else -> algOid
        }
        val publicKeyDer = spkiDer
        var skid = byteArrayOf()
        tbs.tryReadContextSpecific(3)?.let { extCtx ->
            val extensions = extCtx.readSequence()
            while (extensions.hasData()) {
                val ext = extensions.readSequence()
                val oid = ext.readObjectIdentifierString()
                if (oid == "2.5.29.14") {
                    if (ext.peekTag() == 0x01) ext.readEncodedValue()
                    var value = ext.readOctetString()
                    while (value.isNotEmpty() && value[0].toInt() == DerUtils.TAG_OCTET_STRING) {
                        val next = DerUtils.unwrapOctetString(value) ?: break
                        if (next.size >= value.size) break
                        value = next
                    }
                    skid = value
                } else {
                    while (ext.hasData()) ext.readEncodedValue()
                }
            }
        }
        return PlatformCertificate(
            subject = subject,
            issuer = issuer,
            serialHex = bytesToHex(serialBytes),
            serialBytes = serialBytes,
            issuerDer = issuerEncoded,
            notBefore = notBefore,
            notAfter = notAfter,
            keyAlgorithm = keyAlg,
            der = der,
            publicKeyDer = publicKeyDer,
            subjectKeyId = skid,
        )
    }

    private fun readTime(reader: AsnReader): Instant = when (reader.peekTag()) {
        0x17 -> reader.readUtcTime()
        0x18 -> reader.readGeneralizedTime()
        else -> throw IllegalArgumentException("Unsupported time tag")
    }

    /**
     * Name (RDNSequence) → читаемая строка subject/issuer.
     *
     * Fix (iOS): нельзя вызывать [AsnReader.readUtf8String] для DN AttributeValue.
     * Старый код матчил теги 0x0C/0x13/0x14/0x16, но читал только UTF8String →
     * `IllegalArgumentException: Expected UTF8String` на PrintableString (типично ATOM PKI:
     * `C=RU`, `O=…`, `UID=…`). Падение в `buildPfxFromContent` → `parseCertificate(signerCertDer)`
     * при `addCertificateAndResign` / `removeCertificateBySkidAndResign`.
     *
     * Строковые CHOICE читаются через [AsnReader.readAnyString].
     */
    private fun dnToString(der: ByteArray): String {
        val seq = AsnReader(der).readSequence()
        val parts = ArrayList<String>()
        while (seq.hasData()) {
            val rdn = seq.readSet()
            while (rdn.hasData()) {
                val atv = rdn.readSequence()
                val oid = atv.readObjectIdentifierString()
                val value = when (atv.peekTag()) {
                    // UTF8 / Printable / Teletex / IA5 / Universal / BMP
                    0x0C, 0x13, 0x14, 0x16, 0x1C, 0x1E -> atv.readAnyString()
                    else -> {
                        // Нестроковый AttributeValue: берём содержимое TLV без tag/length
                        val tlv = atv.readEncodedValue()
                        val (_, nlen, ok) = DerUtils.parseLength(tlv, 1)
                        val content =
                            if (ok && 1 + nlen <= tlv.size) tlv.copyOfRange(1 + nlen, tlv.size) else tlv
                        content.decodeToString()
                    }
                }
                val name = when (oid) {
                    "2.5.4.3" -> "CN"
                    "2.5.4.6" -> "C"
                    "2.5.4.7" -> "L"
                    "2.5.4.8" -> "ST"
                    "2.5.4.10" -> "O"
                    "2.5.4.11" -> "OU"
                    "0.9.2342.19200300.100.1.1" -> "UID"
                    "1.2.840.113549.1.9.1" -> "emailAddress"
                    else -> oid
                }
                parts.add("$name=$value")
            }
        }
        return parts.joinToString(", ")
    }
}
