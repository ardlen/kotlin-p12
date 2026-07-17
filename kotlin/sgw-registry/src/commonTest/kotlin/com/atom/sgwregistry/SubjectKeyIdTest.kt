package com.atom.sgwregistry

import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.crypto.X509DerParser
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SubjectKeyIdTest {
    @Test
    fun x509DerParserHandlesSignerUtcTime() {
        val der = PemEncoding.decodePemOrDer(TestFixtures.readBytes("certs/signer.pem"))
        val cert = X509DerParser.parse(der)
        assertEquals("CN=Owner Registry Signer", cert.subject)
        assertEquals(20, cert.subjectKeyId.size)
        assertEquals(
            "bbea92b531747b07a265164962ca7ef7ab3bcab8",
            PemEncoding.skidToHex(cert.subjectKeyId),
        )
    }

    @Test
    fun x509DerParserHandlesPrintableStringDn() {
        // ATOM PKI certs use PrintableString for C/O/OU/CN/UID — not UTF8String.
        // This used to throw IllegalArgumentException("Expected UTF8String") on iOS.
        val der = PemEncoding.decodePemOrDer(TestFixtures.readBytes("infotainment_client.pem"))
        val cert = X509DerParser.parse(der)
        assertTrue(cert.subject.contains("C=RU"), "subject=${cert.subject}")
        assertTrue(cert.subject.contains("CN="), "subject=${cert.subject}")
        assertTrue(cert.issuer.contains("C=RU"), "issuer=${cert.issuer}")
        assertTrue(cert.subjectKeyId.isNotEmpty())
    }

    @Test
    fun signerPemSkidIs20RawBytes() {
        val der = PemEncoding.decodePemOrDer(TestFixtures.readBytes("certs/signer.pem"))
        val cert = PlatformCrypto.parseCertificate(der)
        val skid = PlatformCrypto.getSubjectKeyId(cert)
        assertEquals(20, skid.size)
        assertEquals(
            "bbea92b531747b07a265164962ca7ef7ab3bcab8",
            PemEncoding.skidToHex(skid),
        )
    }
}
