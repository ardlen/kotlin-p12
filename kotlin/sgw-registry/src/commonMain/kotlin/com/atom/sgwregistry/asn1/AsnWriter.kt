/**
 * Минимальный писатель DER с единым растущим буфером.
 */
package com.atom.sgwregistry.asn1

import com.atom.sgwregistry.util.formatGeneralizedTimeUtc
import com.atom.sgwregistry.util.formatUtcTimeUtc
import kotlinx.datetime.Instant

class AsnWriter {
    private sealed class Frame {
        data class Seq(val start: Int, val tag: Int?) : Frame()
        data class Set(val start: Int) : Frame()
    }

    private var buffer = ByteArray(4096)
    private var size = 0
    private val stack = ArrayDeque<Frame>()

    init {
        stack.addLast(Frame.Seq(0, null))
    }

    fun pushSequence(contextTag: Int? = null) {
        stack.addLast(Frame.Seq(size, contextTag))
    }

    fun pushSetOf(contextTag: Int? = null) {
        if (contextTag != null) stack.addLast(Frame.Seq(size, contextTag))
        else stack.addLast(Frame.Set(size))
    }

    fun popSequence() {
        val frame = stack.removeLast()
        val start = when (frame) {
            is Frame.Seq -> frame.start
            is Frame.Set -> frame.start
        }
        val contentLen = size - start
        val header = when (frame) {
            is Frame.Seq -> {
                val tag = if (frame.tag != null) 0xA0 or frame.tag else DerUtils.TAG_SEQUENCE
                tlvHeader(tag, contentLen)
            }
            is Frame.Set -> tlvHeader(DerUtils.TAG_SET, contentLen)
        }
        prependTlvHeaderAt(start, header)
    }

    fun writeObjectIdentifier(oid: IntArray) = writeRaw(encodeOid(oid))

    fun writeObjectIdentifier(oidStr: String) =
        writeObjectIdentifier(Oids.parseOidToIntArray(oidStr) ?: intArrayOf())

    fun writeOctetString(data: ByteArray) =
        writeRaw(DerUtils.prependTlv(DerUtils.TAG_OCTET_STRING, data))

    fun writeInteger(value: Int) {
        val bytes = if (value == 0) byteArrayOf(0) else {
            val buf = ByteArray(4)
            buf[0] = ((value shr 24) and 0xFF).toByte()
            buf[1] = ((value shr 16) and 0xFF).toByte()
            buf[2] = ((value shr 8) and 0xFF).toByte()
            buf[3] = (value and 0xFF).toByte()
            val trimmed = buf.dropWhile { it == 0.toByte() }.toByteArray()
            if (trimmed.isEmpty()) byteArrayOf(0) else trimmed
        }
        writeRaw(DerUtils.prependTlv(0x02, bytes))
    }

    fun writeNull() = writeRaw(byteArrayOf(0x05, 0x00))

    fun writeUtf8String(s: String) =
        writeRaw(DerUtils.prependTlv(0x0C, s.encodeToByteArray()))

    fun writePrintableString(s: String) =
        writeRaw(DerUtils.prependTlv(0x13, s.encodeToByteArray()))

    fun writeIa5String(s: String) =
        writeRaw(DerUtils.prependTlv(0x16, s.encodeToByteArray()))

    fun writeBoolean(value: Boolean) =
        writeRaw(byteArrayOf(0x01, 0x01, if (value) 0xFF.toByte() else 0x00))

    /** BIT STRING: unusedBits + content. */
    fun writeBitString(content: ByteArray, unusedBits: Int = 0) {
        require(unusedBits in 0..7) { "unusedBits must be 0..7" }
        val body = ByteArray(1 + content.size)
        body[0] = unusedBits.toByte()
        content.copyInto(body, 1)
        writeRaw(DerUtils.prependTlv(0x03, body))
    }

    fun writeGeneralizedTime(instant: Instant) {
        val s = formatGeneralizedTimeUtc(instant)
        writeRaw(DerUtils.prependTlv(0x18, s.encodeToByteArray()))
    }

    fun writeUtcTime(instant: Instant) {
        val s = formatUtcTimeUtc(instant)
        writeRaw(DerUtils.prependTlv(0x17, s.encodeToByteArray()))
    }

    fun writeIntegerBytes(bytes: ByteArray) {
        writeRaw(DerUtils.prependTlv(0x02, bytes))
    }

    fun writeEncodedValue(der: ByteArray) = writeRaw(der)

    fun encode(): ByteArray {
        while (stack.size > 1) popSequence()
        return buffer.copyOf(size)
    }

    private fun tlvHeader(tag: Int, contentLength: Int): ByteArray {
        val lenBytes = DerUtils.encodeLength(contentLength) ?: return byteArrayOf(tag.toByte())
        return ByteArray(1 + lenBytes.size).also {
            it[0] = tag.toByte()
            lenBytes.copyInto(it, 1)
        }
    }

    private fun prependTlvHeaderAt(contentStart: Int, header: ByteArray) {
        if (header.isEmpty()) return
        ensureCapacity(size + header.size)
        buffer.copyInto(buffer, contentStart + header.size, contentStart, size)
        header.copyInto(buffer, contentStart)
        size += header.size
    }

    private fun writeRaw(bytes: ByteArray) {
        ensureCapacity(size + bytes.size)
        bytes.copyInto(buffer, size)
        size += bytes.size
    }

    private fun ensureCapacity(min: Int) {
        if (min <= buffer.size) return
        var newSize = buffer.size
        while (newSize < min) newSize *= 2
        buffer = buffer.copyOf(newSize)
    }

    private fun encodeOid(oid: IntArray): ByteArray {
        if (oid.size < 2) return byteArrayOf(0x06, 0x00)
        val body = ArrayList<Int>()
        body.add(oid[0] * 40 + oid[1])
        for (i in 2 until oid.size) {
            var v = oid[i]
            val parts = mutableListOf<Int>()
            parts.add(v and 0x7F)
            v = v ushr 7
            while (v > 0) {
                parts.add(0x80 or (v and 0x7F))
                v = v ushr 7
            }
            parts.asReversed().forEach { body.add(it) }
        }
        return DerUtils.prependTlv(0x06, body.map { it.toByte() }.toByteArray())
    }
}
