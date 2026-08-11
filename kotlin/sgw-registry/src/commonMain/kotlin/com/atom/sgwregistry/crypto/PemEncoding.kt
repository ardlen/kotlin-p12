package com.atom.sgwregistry.crypto

import com.atom.sgwregistry.internal.bytesToHex
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/** PEM/DER encoding helpers (multiplatform, no JCA). */
@OptIn(ExperimentalEncodingApi::class)
object PemEncoding {
    fun isPem(data: ByteArray): Boolean {
        if (data.size < 11) return false
        return data.decodeToString(0, minOf(27, data.size)).startsWith("-----BEGIN")
    }

    fun detectPemLabel(pem: String): String {
        val begin = "-----BEGIN "
        val i = pem.indexOf(begin, ignoreCase = true)
        val j = pem.indexOf("-----", i + begin.length, ignoreCase = true)
        if (i < 0 || j < 0) throw IllegalArgumentException("PEM begin not found")
        return pem.substring(i + begin.length, j).trim()
    }

    fun extractPemBlock(pem: String, label: String): String {
        val begin = "-----BEGIN $label-----"
        val end = "-----END $label-----"
        val i = pem.indexOf(begin, ignoreCase = true)
        val j = pem.indexOf(end, ignoreCase = true)
        if (i < 0 || j < 0 || j <= i) throw IllegalArgumentException("PEM block $label not found")
        return pem.substring(i + begin.length, j)
            .replace("\r", "")
            .replace("\n", "")
            .replace("\\n", "")
            .replace("\\r", "")
    }

    fun decodePemBlock(pem: String, label: String): ByteArray =
        Base64.decode(extractPemBlock(pem, label))

    fun decodePemOrDer(pemOrDer: ByteArray): ByteArray =
        if (isPem(pemOrDer)) {
            val pem = pemOrDer.decodeToString()
            decodePemBlock(pem, detectPemLabel(pem))
        } else {
            pemOrDer
        }

    fun certToPem(certDer: ByteArray): String {
        val b64 = Base64.encode(certDer)
        return "-----BEGIN CERTIFICATE-----\n${b64.chunked(64).joinToString("\n")}\n-----END CERTIFICATE-----\n"
    }

    fun cmsToPem(cmsDer: ByteArray): String {
        val b64 = Base64.encode(cmsDer)
        return "-----BEGIN CMS-----\n${b64.chunked(64).joinToString("\n")}\n-----END CMS-----\n"
    }

    fun csrToPem(csrDer: ByteArray): String {
        val b64 = Base64.encode(csrDer)
        return "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "${b64.chunked(64).joinToString("\n")}\n" +
            "-----END CERTIFICATE REQUEST-----\n"
    }

    fun decodeSkidHex(hex: String): ByteArray {
        val cleaned = hex.trim()
            .replace("0x", "", ignoreCase = true)
            .replace("-", "")
            .replace(":", "")
        require(cleaned.isNotEmpty() && cleaned.length % 2 == 0) { "Invalid SKID hex: $hex" }
        return cleaned.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    fun skidToHex(skid: ByteArray): String = bytesToHex(skid)
}
