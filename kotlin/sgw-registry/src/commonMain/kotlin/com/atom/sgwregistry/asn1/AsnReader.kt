package com.atom.sgwregistry.asn1

import com.atom.sgwregistry.util.parseGeneralizedTimeUtc
import com.atom.sgwregistry.util.parseUtcTimeUtc
import kotlinx.datetime.Instant

/**
 * Минимальный читатель DER (аналог `System.Formats.Asn1.AsnReader` / Go asn1).
 */
class AsnReader private constructor(
    private val data: ByteArray,
    private var offset: Int,
    private val end: Int,
) {
    constructor(data: ByteArray) : this(data, 0, data.size)

    fun hasData(): Boolean = offset < end

    fun peekTag(): Int? {
        if (!hasData()) return null
        return data[offset].toInt() and 0xFF
    }

    fun remainingBytes(): Int = end - offset

    fun readRemainingBytes(): ByteArray {
        val bytes = data.copyOfRange(offset, end)
        offset = end
        return bytes
    }

    fun readTlv(): DerUtils.Tlv {
        val tlv = DerUtils.readTlv(data, offset) ?: throw IllegalArgumentException("Invalid TLV at offset $offset")
        if (tlv.next > end) throw IllegalArgumentException("TLV exceeds bounds at offset $offset")
        offset = tlv.next
        return tlv
    }

    fun readEncodedValue(): ByteArray = readTlv().tlv

    fun readSequence(): AsnReader {
        val tlv = readTlv()
        require(tlv.tag == DerUtils.TAG_SEQUENCE) { "Expected SEQUENCE, got 0x${tlv.tag.toString(16)}" }
        return child(tlv)
    }

    fun readSet(): AsnReader {
        val tlv = readTlv()
        require(tlv.tag == DerUtils.TAG_SET) { "Expected SET, got 0x${tlv.tag.toString(16)}" }
        return child(tlv)
    }

    fun tryReadContextSpecific(expectedTag: Int): AsnReader? {
        val tag = peekTag() ?: return null
        val ok = tag == (0xA0 or expectedTag) || tag == (0x80 or expectedTag)
        if (!ok) return null
        return child(readTlv())
    }

    fun readContextSpecific(expectedTag: Int): AsnReader {
        val reader = tryReadContextSpecific(expectedTag)
            ?: throw IllegalArgumentException("Expected context [$expectedTag]")
        return reader
    }

    fun readObjectIdentifier(): IntArray {
        val tlv = readTlv()
        require(tlv.tag == 0x06) { "Expected OID" }
        return decodeOid(tlvContent(tlv))
    }

    fun readObjectIdentifierString(): String = Oids.oidString(readObjectIdentifier())

    fun readInteger(): Int {
        val bytes = readIntegerBytes()
        if (bytes.isEmpty()) return 0
        var v = 0
        for (b in bytes) v = (v shl 8) or (b.toInt() and 0xFF)
        val bits = bytes.size * 8
        val signBit = 1 shl (bits - 1)
        if (v and signBit != 0) v -= (1 shl bits)
        return v
    }

    fun readIntegerBytes(): ByteArray {
        val tlv = readTlv()
        require(tlv.tag == 0x02) { "Expected INTEGER" }
        return tlvContent(tlv)
    }

    fun readOctetString(): ByteArray {
        val tlv = readTlv()
        require(tlv.tag == DerUtils.TAG_OCTET_STRING || tlv.tag == DerUtils.TAG_CONSTRUCTED_OCTET_STRING) {
            "Expected OCTET STRING"
        }
        return DerUtils.unwrapOctetString(tlv.tlv) ?: tlvContent(tlv)
    }

    /** Только UTF8String (0x0C). Для DN / DirectoryString используйте [readAnyString]. */
    fun readUtf8String(): String {
        val tlv = readTlv()
        require(tlv.tag == 0x0C) { "Expected UTF8String" }
        return tlvContent(tlv).decodeToString()
    }

    /**
     * Читает ASN.1 string CHOICE (X.509 DirectoryString / DN AttributeValue).
     *
     * Fix (iOS): ранее DN разбирали через [readUtf8String], хотя ATOM PKI обычно кодирует
     * C/O/OU/CN/UID как PrintableString (0x13). На iOS это давало
     * `IllegalArgumentException: Expected UTF8String` в `X509DerParser.dnToString`
     * при `addCertificateAndResign` / `parseCertificate`.
     *
     * Поддерживаемые теги:
     * - 0x0C UTF8String, 0x13 PrintableString, 0x14 TeletexString, 0x16 IA5String
     * - 0x1C UniversalString, 0x1E BMPString
     */
    fun readAnyString(): String {
        val tlv = readTlv()
        val content = tlvContent(tlv)
        return when (tlv.tag) {
            0x0C, 0x13, 0x14, 0x16 -> content.decodeToString()
            0x1E -> decodeBmpString(content)
            0x1C -> decodeUniversalString(content)
            else -> throw IllegalArgumentException(
                "Expected string type, got 0x${tlv.tag.toString(16)}",
            )
        }
    }

    fun readUtcTime(): Instant {
        val tlv = readTlv()
        require(tlv.tag == 0x17) { "Expected UTCTime" }
        val s = tlvContent(tlv).decodeToString().trim()
        return parseUtcTimeUtc(s)
    }

    fun readGeneralizedTime(): Instant {
        val tlv = readTlv()
        require(tlv.tag == 0x18) { "Expected GeneralizedTime" }
        val s = tlvContent(tlv).decodeToString().trim()
        return parseGeneralizedTimeUtc(s)
    }

    fun readNull() {
        val tlv = readTlv()
        require(tlv.tag == 0x05 && tlv.tlv.size == 2) { "Expected NULL" }
    }

    fun readSetOfAttributes(): List<Pair<IntArray, ByteArray>> {
        val set = readSet()
        val list = ArrayList<Pair<IntArray, ByteArray>>()
        while (set.hasData()) {
            val attr = set.readSequence()
            val oid = attr.readObjectIdentifier()
            val values = attr.readSet()
            val valueTlv = values.readEncodedValue()
            list.add(oid to valueTlv)
        }
        return list
    }

    fun eachChild(block: (AsnReader) -> Unit) {
        while (hasData()) block(child(readTlv()))
    }

    private fun child(tlv: DerUtils.Tlv): AsnReader {
        val (_, nlen, ok) = DerUtils.parseLength(tlv.tlv, 1)
        val start = if (ok) 1 + nlen else tlv.tlv.size
        return AsnReader(tlv.tlv, start, tlv.tlv.size)
    }

    private fun tlvContent(tlv: DerUtils.Tlv): ByteArray {
        val (_, nlen, ok) = DerUtils.parseLength(tlv.tlv, 1)
        if (!ok) return byteArrayOf()
        val start = 1 + nlen
        return tlv.tlv.copyOfRange(start, tlv.tlv.size)
    }

    private fun decodeOid(content: ByteArray): IntArray {
        if (content.isEmpty()) return intArrayOf()
        val first = content[0].toInt() and 0xFF
        val parts = ArrayList<Int>()
        parts.add(first / 40)
        parts.add(first % 40)
        var i = 1
        while (i < content.size) {
            var v = 0
            while (i < content.size) {
                val b = content[i++].toInt() and 0xFF
                v = (v shl 7) or (b and 0x7F)
                if (b and 0x80 == 0) break
            }
            parts.add(v)
        }
        return parts.toIntArray()
    }

    /** BMPString (0x1E): UTF-16BE. */
    private fun decodeBmpString(content: ByteArray): String {
        require(content.size % 2 == 0) { "BMPString length must be even" }
        val chars = CharArray(content.size / 2)
        for (i in chars.indices) {
            val code = ((content[i * 2].toInt() and 0xFF) shl 8) or (content[i * 2 + 1].toInt() and 0xFF)
            chars[i] = code.toChar()
        }
        return chars.concatToString()
    }

    /** UniversalString (0x1C): UTF-32BE → UTF-16 (surrogate pairs при необходимости). */
    private fun decodeUniversalString(content: ByteArray): String {
        require(content.size % 4 == 0) { "UniversalString length must be multiple of 4" }
        return buildString(content.size / 4) {
            var i = 0
            while (i < content.size) {
                val cp = ((content[i].toInt() and 0xFF) shl 24) or
                    ((content[i + 1].toInt() and 0xFF) shl 16) or
                    ((content[i + 2].toInt() and 0xFF) shl 8) or
                    (content[i + 3].toInt() and 0xFF)
                if (cp <= 0xFFFF) {
                    append(cp.toChar())
                } else {
                    val v = cp - 0x10000
                    append(((v shr 10) + 0xD800).toChar())
                    append(((v and 0x3FF) + 0xDC00).toChar())
                }
                i += 4
            }
        }
    }
}
