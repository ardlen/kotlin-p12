package com.atom.sgwregistry

import com.atom.sgwregistry.asn1.Oids
import com.atom.sgwregistry.cloudconfig.CloudConfigCms
import com.atom.sgwregistry.csr.OwnershipCsr
import com.atom.sgwregistry.csr.OwnershipCsrRequest
import com.atom.sgwregistry.crypto.PemEncoding
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class OwnershipCsrTest {
    @Test
    fun buildOwnershipCsrContainsEkuSanAndUid() {
        if (!TestFixtures.exists("certs/signer-key.pem")) return
        val ownerId = "d231b684-82b4-4fdc-83dd-fc9a1861c293"
        val keyPem = TestFixtures.readBytes("certs/signer-key.pem")
        val result = OwnershipCsr.buildFromEcPrivateKeyPem(
            OwnershipCsrRequest(ownerId = ownerId),
            keyPem,
        )

        assertEquals(ownerId, result.ownerId)
        assertEquals(CloudConfigCms.OWNER_SAN_URI_PREFIX + ownerId, result.sanUri)
        assertTrue(result.csrPem.contains("BEGIN CERTIFICATE REQUEST"))
        assertEquals(0x30.toByte(), result.csrDer[0])

        val der = result.csrDer
        assertTrue(containsOid(der, Oids.idKpEmailProtection), "CSR must request emailProtection EKU")
        assertTrue(!containsOid(der, Oids.idKpClientAuth), "clientAuth must be off by default")
        assertTrue(containsOid(der, Oids.extensionSubjectAltName), "CSR must include SAN extension")
        assertTrue(containsOid(der, Oids.pkcs9ExtensionRequest), "CSR must include extensionRequest")
        assertTrue(
            der.decodeToString().contains(result.sanUri) ||
                containsAscii(der, result.sanUri),
            "CSR must embed SAN URI $result.sanUri",
        )
        assertTrue(containsAscii(der, ownerId), "CSR subject/SAN must embed ownerId")
        assertTrue(result.publicKeySpki.isNotEmpty() && result.publicKeySpki[0] == 0x30.toByte())

        // Round-trip PEM decode
        val decoded = PemEncoding.decodePemOrDer(result.csrPem.encodeToByteArray())
        assertTrue(decoded.contentEquals(result.csrDer))
    }

    @Test
    fun rejectsBlankOwnerId() {
        if (!TestFixtures.exists("certs/signer-key.pem")) return
        assertFailsWith<IllegalArgumentException> {
            OwnershipCsr.buildFromEcPrivateKeyPem(
                OwnershipCsrRequest(ownerId = "  "),
                TestFixtures.readBytes("certs/signer-key.pem"),
            )
        }
    }

    @Test
    fun rejectsNoEku() {
        if (!TestFixtures.exists("certs/signer-key.pem")) return
        assertFailsWith<IllegalArgumentException> {
            OwnershipCsr.buildFromEcPrivateKeyPem(
                OwnershipCsrRequest(
                    ownerId = "owner-1",
                    includeEmailProtectionEku = false,
                    includeClientAuthEku = false,
                ),
                TestFixtures.readBytes("certs/signer-key.pem"),
            )
        }
    }

    private fun containsOid(der: ByteArray, oid: IntArray): Boolean {
        val encoded = encodeOidBody(oid)
        return indexOf(der, encoded) >= 0
    }

    private fun containsAscii(der: ByteArray, s: String): Boolean =
        indexOf(der, s.encodeToByteArray()) >= 0

    private fun encodeOidBody(oid: IntArray): ByteArray {
        // full TLV via a tiny writer-equivalent: tag 0x06 + length + body
        require(oid.size >= 2)
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
        val content = body.map { it.toByte() }.toByteArray()
        return byteArrayOf(0x06, content.size.toByte()) + content
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        if (needle.isEmpty() || needle.size > haystack.size) return -1
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }
}
