/**
 * Низкоуровневые операции с DER (Distinguished Encoding Rules).
 *
 * Аналог вспомогательных функций из Go-пакета der и .NET DerUtils:
 * чтение TLV, канонизация SET, нормализация нестандартных CMS-структур.
 */
package com.atom.sgwregistry.asn1

object DerUtils {
    /** Тег SEQUENCE (0x30). */
    const val TAG_SEQUENCE: Int = 0x30
    /** Тег SET (0x31). */
    const val TAG_SET: Int = 0x31
    /** Тег OCTET STRING (0x04). */
    const val TAG_OCTET_STRING: Int = 0x04
    /** Тег CONSTRUCTED OCTET STRING (0x24) — составной OCTET STRING. */
    const val TAG_CONSTRUCTED_OCTET_STRING: Int = 0x24

    /**
     * Результат чтения одного TLV-элемента из буфера.
     *
     * @param tag Байт тега ASN.1.
     * @param tlv Полный TLV (tag + length + value).
     * @param next Смещение в data сразу после этого TLV.
     */
    data class Tlv(val tag: Int, val tlv: ByteArray, val next: Int)

    /**
     * Читает один TLV, начиная с offset.
     * Возвращает null при нехватке данных или некорректной длине.
     */
    fun readTlv(data: ByteArray, offset: Int): Tlv? {
        if (offset >= data.size || offset + 2 > data.size) return null
        val tag = data[offset].toInt() and 0xFF
        val (contentLen, numLenBytes, ok) = parseLength(data, offset + 1)
        if (!ok || contentLen < 0) return null
        val contentStart = offset + 1 + numLenBytes
        val totalLen = 1 + numLenBytes + contentLen
        if (contentStart + contentLen > data.size) return null
        val tlv = data.copyOfRange(offset, offset + totalLen)
        return Tlv(tag, tlv, offset + totalLen)
    }

    /**
     * Разбор поля length в DER.
     *
     * @return Triple(длина содержимого, число байт длины, успех).
     * Длина -1 означает неопределённую длину (0x80) — в наших контейнерах не используется.
     */
    fun parseLength(data: ByteArray, offset: Int): Triple<Int, Int, Boolean> {
        if (offset >= data.size) return Triple(0, 0, false)
        val b = data[offset].toInt() and 0xFF
        if (b == 0x80) return Triple(-1, 1, true)
        if (b and 0x80 == 0) return Triple(b, 1, true)
        val nlen = b and 0x7F
        if (offset + 1 + nlen > data.size) return Triple(0, 0, false)
        var len = 0
        for (i in 0 until nlen) {
            len = (len shl 8) + (data[offset + 1 + i].toInt() and 0xFF)
        }
        return Triple(len, 1 + nlen, true)
    }

    /**
     * Снимает обёртку OCTET STRING (в т.ч. вложенную и constructed).
     * Нужно для SKID и eContent, где Java/BC могут вернуть двойную обёртку.
     */
    fun unwrapOctetString(data: ByteArray?): ByteArray? {
        if (data == null || data.size < 2) return data
        if (data[0].toInt() == TAG_CONSTRUCTED_OCTET_STRING) return unwrapConstructedOctetString(data)
        if (data[0].toInt() != TAG_OCTET_STRING) return data
        val (contentLen, numLenBytes, ok) = parseLength(data, 1)
        if (!ok || contentLen < 0) return data
        val start = 1 + numLenBytes
        if (start + contentLen > data.size) return data
        return data.copyOfRange(start, start + contentLen)
    }

    /** Рекурсивно собирает фрагменты constructed OCTET STRING в один массив. */
    private fun unwrapConstructedOctetString(data: ByteArray): ByteArray? {
        val (_, numLenBytes, ok) = parseLength(data, 1)
        if (!ok) return data
        var pos = 1 + numLenBytes
        val list = ArrayList<Byte>()
        while (pos < data.size) {
            val tlv = readTlv(data, pos) ?: break
            if (tlv.tag == TAG_OCTET_STRING || tlv.tag == TAG_CONSTRUCTED_OCTET_STRING) {
                unwrapOctetString(tlv.tlv)?.let { list.addAll(it.asIterable()) }
            }
            pos = tlv.next
        }
        return list.toByteArray()
    }

    /**
     * Канонический DER для SET OF — элементы отсортированы по DER-кодировке.
     *
     * CMS требует подписывать именно канонический SET authenticatedAttributes;
     * без сортировки проверка подписи не пройдёт.
     */
    fun canonicalSetDer(setBytes: ByteArray?): ByteArray? {
        if (setBytes == null || setBytes.isEmpty()) return null
        var content = setBytes
        if (setBytes[0].toInt() == TAG_SET) {
            val (contentLen, numLenBytes, ok) = parseLength(setBytes, 1)
            if (!ok || contentLen <= 0) return null
            content = setBytes.copyOfRange(1 + numLenBytes, 1 + numLenBytes + contentLen)
        }
        val elements = ArrayList<ByteArray>()
        var off = 0
        while (off < content.size) {
            val tlv = readTlv(content, off) ?: return null
            elements.add(tlv.tlv)
            off = tlv.next
        }
        if (elements.isEmpty()) return null
        elements.sortWith { a, b -> compareDer(a, b) }
        val total = elements.sumOf { it.size }
        val lengthBytes = encodeLength(total) ?: return null
        val result = ByteArray(1 + lengthBytes.size + total)
        result[0] = TAG_SET.toByte()
        lengthBytes.copyInto(result, 1)
        var pos = 1 + lengthBytes.size
        for (el in elements) {
            el.copyInto(result, pos)
            pos += el.size
        }
        return result
    }

    /** Кодирование длины DER (короткая и длинная форма до 3 байт длины). */
    fun encodeLength(length: Int): ByteArray? {
        if (length < 0) return null
        return when {
            length < 128 -> byteArrayOf(length.toByte())
            length <= 0xFF -> byteArrayOf(0x81.toByte(), length.toByte())
            length <= 0xFFFF -> byteArrayOf(0x82.toByte(), (length shr 8).toByte(), length.toByte())
            else -> byteArrayOf(
                0x83.toByte(),
                (length shr 16).toByte(),
                (length shr 8).toByte(),
                length.toByte(),
            )
        }
    }

    /** Оборачивает value в TLV с заданным тегом. */
    fun prependTlv(tag: Int, value: ByteArray): ByteArray {
        val lenBytes = encodeLength(value.size) ?: return value
        return ByteArray(1 + lenBytes.size + value.size).also { result ->
            result[0] = tag.toByte()
            lenBytes.copyInto(result, 1)
            value.copyInto(result, 1 + lenBytes.size)
        }
    }

    /**
     * Лексикографическое сравнение двух DER-фрагментов (для сортировки SET).
     * Сравниваются байты как беззнаковые; при равном префиксе — по длине.
     */
    fun compareDer(a: ByteArray, b: ByteArray): Int {
        val c = minOf(a.size, b.size)
        for (i in 0 until c) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    /**
     * Нормализует SignedData: заменяет [1] IMPLICIT обёртку SignerInfos (0xA1 с SET внутри)
     * на «голый» SET (0x31).
     *
     * Ответы ATOM /cms/sign и некоторые внешние CMS используют такую кодировку;
     * парсер Bouncy Castle ожидает стандартный SET на верхнем уровне.
     */
    /** Normalizes ASN.1 INTEGER bytes for equality comparison (strips redundant sign padding). */
    fun normalizeIntegerBytes(bytes: ByteArray): ByteArray {
        if (bytes.isEmpty()) return byteArrayOf(0)
        var start = 0
        while (start < bytes.size - 1) {
            val b = bytes[start].toInt() and 0xFF
            val next = bytes[start + 1].toInt() and 0xFF
            if (b == 0 && next < 0x80) start++
            else if (b == 0xFF && next >= 0x80) start++
            else break
        }
        return bytes.copyOfRange(start, bytes.size)
    }

    fun integerBytesEqual(a: ByteArray, b: ByteArray): Boolean =
        normalizeIntegerBytes(a).contentEquals(normalizeIntegerBytes(b))

    fun normalizeSignerInfosInSignedDataDer(signedDataDer: ByteArray): ByteArray {
        val outer = readTlv(signedDataDer, 0) ?: return signedDataDer
        if (outer.tag != TAG_SEQUENCE) return signedDataDer
        val (contentLen, numLen, ok) = parseLength(signedDataDer, 1)
        if (!ok || contentLen < 0) return signedDataDer
        val contentStart = 1 + numLen
        val contentEnd = contentStart + contentLen
        if (contentEnd > signedDataDer.size) return signedDataDer
        val content = signedDataDer.copyOfRange(contentStart, contentEnd)

        // Пропускаем version, digestAlgorithms, encapContentInfo
        var pos = 0
        repeat(3) {
            val tlv = readTlv(content, pos) ?: return signedDataDer
            pos = tlv.next
        }
        while (pos < content.size) {
            val tag = content[pos].toInt() and 0xFF
            when (tag) {
                0xA0, 0x80 -> {
                    // certificates [0] — пропускаем
                    val tlv = readTlv(content, pos) ?: return signedDataDer
                    pos = tlv.next
                }
                0xA1, 0x81 -> {
                    // SignerInfos в нестандартной обёртке [1]
                    val a1Pos = pos
                    val tlv = readTlv(content, pos) ?: return signedDataDer
                    val inner = tlv.tlv
                    val innerStart = 1 + parseLength(inner, 1).second
                    val innerContent = inner.copyOfRange(innerStart, inner.size)
                    if (innerContent.size >= 2 && innerContent[0].toInt() == TAG_SET) {
                        val setContentLen = parseLength(innerContent, 1).first
                        if (setContentLen == 0) {
                            pos = tlv.next
                            continue
                        }
                        // Подменяем A1+SET на SET напрямую в content SignedData
                        val newContent = ByteArray(content.size - tlv.tlv.size + innerContent.size)
                        content.copyInto(newContent, 0, 0, a1Pos)
                        innerContent.copyInto(newContent, a1Pos)
                        content.copyInto(newContent, a1Pos + innerContent.size, tlv.next, content.size)
                        return prependTlv(TAG_SEQUENCE, newContent)
                    }
                    pos = tlv.next
                }
                TAG_SET -> return signedDataDer // уже стандартная форма
                else -> return signedDataDer
            }
        }
        return signedDataDer
    }
}
