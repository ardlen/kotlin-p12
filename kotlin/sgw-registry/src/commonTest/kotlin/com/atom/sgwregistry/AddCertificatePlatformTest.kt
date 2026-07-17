package com.atom.sgwregistry

import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.crypto.X509DerParser
import com.atom.sgwregistry.model.AddCertificateRequest
import com.atom.sgwregistry.model.RemoveCertificateBySkidRequest
import com.atom.sgwregistry.model.SafeBagInput
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.verifier.SignatureVerifier
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Регрессия iOS/Android: addCertificateAndResign с сертификатами ATOM PKI
 * (DN на PrintableString), которые раньше валили X509DerParser на iOS.
 */
class AddCertificatePlatformTest {
    private fun roleWindow(): Pair<Instant, Instant> {
        val now = Clock.System.now()
        return now to Instant.fromEpochMilliseconds(now.toEpochMilliseconds() + 86_400_000L)
    }

    @Test
    fun nativeX509ParserAcceptsAtomPrintableStringDn() {
        if (!TestFixtures.exists("infotainment_client.pem")) return
        val der = PemEncoding.decodePemOrDer(TestFixtures.readBytes("infotainment_client.pem"))
        // iOS PlatformCrypto.parseCertificate → X509DerParser (не JCA)
        val viaNative = X509DerParser.parse(der)
        val viaPlatform = PlatformCrypto.parseCertificate(der)
        assertTrue(viaNative.subject.contains("C=RU"), viaNative.subject)
        assertTrue(viaNative.issuer.contains("C=RU"), viaNative.issuer)
        assertTrue(viaNative.subjectKeyId.isNotEmpty())
        assertEquals(viaNative.subjectKeyId.toList(), viaPlatform.subjectKeyId.toList())
    }

    @Test
    fun addPrintableStringBagAndResignVerifies() {
        if (!TestBuildConfig.exists()) return
        if (!TestFixtures.exists("infotainment_client.pem")) return
        if (!TestFixtures.exists("demo-original-container.p12")) return

        val buildCfg = TestBuildConfig.load()
        val p12 = TestFixtures.readBytes("demo-original-container.p12")
        val before = RegistryParser.parse(p12)
        val certDer = PemEncoding.decodePemOrDer(TestFixtures.readBytes("infotainment_client.pem"))
        val (nb, na) = roleWindow()

        // Без localKeyId — на iOS библиотека парсит cert через X509DerParser для SKID
        val updated = RegistryBuilder.addCertificateAndResign(
            before,
            AddCertificateRequest(
                existingP12 = p12,
                newBag = SafeBagInput(
                    certDer = certDer,
                    roleName = "infotainment",
                    roleNotBefore = nb,
                    roleNotAfter = na,
                ),
                signerCertDer = buildCfg.signerCertDer,
                signerKey = buildCfg.signerKey,
            ),
        )

        val after = RegistryParser.parse(updated)
        assertEquals(before.safeBagInfos.size + 1, after.safeBagInfos.size)
        SignatureVerifier.verifyRegistry(updated)
    }

    @Test
    fun addThenRemovePrintableStringBagRoundTrip() {
        if (!TestBuildConfig.exists()) return
        if (!TestFixtures.exists("infotainment_client.pem")) return
        if (!TestFixtures.exists("demo-original-container.p12")) return

        val buildCfg = TestBuildConfig.load()
        val p12 = TestFixtures.readBytes("demo-original-container.p12")
        val before = RegistryParser.parse(p12)
        val certDer = PemEncoding.decodePemOrDer(TestFixtures.readBytes("infotainment_client.pem"))
        val skid = PlatformCrypto.getSubjectKeyId(X509DerParser.parse(certDer))
        val (nb, na) = roleWindow()

        val withAdded = RegistryBuilder.addCertificateAndResign(
            before,
            AddCertificateRequest(
                existingP12 = p12,
                newBag = SafeBagInput(
                    certDer = certDer,
                    roleName = "infotainment",
                    roleNotBefore = nb,
                    roleNotAfter = na,
                ),
                signerCertDer = buildCfg.signerCertDer,
                signerKey = buildCfg.signerKey,
            ),
        )
        SignatureVerifier.verifyRegistry(withAdded)

        val afterRemove = RegistryBuilder.removeCertificateBySkidAndResign(
            RegistryParser.parse(withAdded),
            RemoveCertificateBySkidRequest(
                existingP12 = withAdded,
                subjectKeyId = skid,
                signerCertDer = buildCfg.signerCertDer,
                signerKey = buildCfg.signerKey,
            ),
        )
        assertEquals(before.safeBagInfos.size, RegistryParser.parse(afterRemove).safeBagInfos.size)
        SignatureVerifier.verifyRegistry(afterRemove)
    }
}
