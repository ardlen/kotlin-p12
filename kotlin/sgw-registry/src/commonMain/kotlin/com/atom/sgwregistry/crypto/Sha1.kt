package com.atom.sgwregistry.crypto

/**
 * Pure-Kotlin SHA-1 (CES Vehicle cloud configuration §5.2.1 hashB).
 * 20-byte digest; not for new security designs — only FQDN construction.
 */
internal object Sha1 {
    fun digest(message: ByteArray): ByteArray {
        var h0 = 0x67452301
        var h1 = 0xEFCDAB89.toInt()
        var h2 = 0x98BADCFE.toInt()
        var h3 = 0x10325476
        var h4 = 0xC3D2E1F0.toInt()

        val ml = message.size.toLong() * 8
        val withOne = message + byteArrayOf(0x80.toByte())
        val padLen = (56 - withOne.size % 64 + 64) % 64
        val padded = withOne + ByteArray(padLen) + longToBytes(ml)

        var i = 0
        while (i < padded.size) {
            val w = IntArray(80)
            for (t in 0 until 16) {
                val j = i + t * 4
                w[t] = ((padded[j].toInt() and 0xFF) shl 24) or
                    ((padded[j + 1].toInt() and 0xFF) shl 16) or
                    ((padded[j + 2].toInt() and 0xFF) shl 8) or
                    (padded[j + 3].toInt() and 0xFF)
            }
            for (t in 16 until 80) {
                w[t] = rotl(w[t - 3] xor w[t - 8] xor w[t - 14] xor w[t - 16], 1)
            }

            var a = h0
            var b = h1
            var c = h2
            var d = h3
            var e = h4
            for (t in 0 until 80) {
                val (f, k) = when {
                    t <= 19 -> ((b and c) or (b.inv() and d)) to 0x5A827999
                    t <= 39 -> (b xor c xor d) to 0x6ED9EBA1
                    t <= 59 -> ((b and c) or (b and d) or (c and d)) to 0x8F1BBCDC.toInt()
                    else -> (b xor c xor d) to 0xCA62C1D6.toInt()
                }
                val temp = rotl(a, 5) + f + e + k + w[t]
                e = d
                d = c
                c = rotl(b, 30)
                b = a
                a = temp
            }
            h0 += a
            h1 += b
            h2 += c
            h3 += d
            h4 += e
            i += 64
        }

        val out = ByteArray(20)
        writeInt(out, 0, h0)
        writeInt(out, 4, h1)
        writeInt(out, 8, h2)
        writeInt(out, 12, h3)
        writeInt(out, 16, h4)
        return out
    }

    private fun rotl(x: Int, n: Int): Int = (x shl n) or (x ushr (32 - n))

    private fun writeInt(buf: ByteArray, off: Int, v: Int) {
        buf[off] = (v ushr 24).toByte()
        buf[off + 1] = (v ushr 16).toByte()
        buf[off + 2] = (v ushr 8).toByte()
        buf[off + 3] = v.toByte()
    }

    private fun longToBytes(v: Long): ByteArray {
        val b = ByteArray(8)
        for (i in 0 until 8) {
            b[7 - i] = (v ushr (i * 8)).toByte()
        }
        return b
    }
}
