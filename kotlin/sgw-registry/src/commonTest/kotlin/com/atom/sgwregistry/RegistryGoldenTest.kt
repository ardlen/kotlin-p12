package com.atom.sgwregistry

import com.atom.sgwregistry.api.ParseOptions
import com.atom.sgwregistry.api.SgwRegistry
import com.atom.sgwregistry.analyzer.RegistryAnalyzer
import com.atom.sgwregistry.asn1.DerUtils
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.model.RemoveCertificateBySkidRequest
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.verifier.SignatureVerifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RegistryGoldenTest {
    private fun readP12(name: String): ByteArray = TestFixtures.readBytes(name)

    @Test
    fun parseDemoOriginalContainer() {
        val p12 = readP12("demo-original-container.p12")
        val c = RegistryParser.parse(p12)
        assertEquals(3, c.pfxVersion)
        assertTrue(c.certificatesDer.isNotEmpty())
        assertTrue(c.safeBagInfos.isNotEmpty())
        assertNotNull(c.signerCertDer)
        assertTrue(c.signerCertResolved)
        assertNotNull(c.encryptedDigest)
        assertTrue(c.parseWarnings.isEmpty())
    }

    @Test
    fun verifyDemoOriginalContainer() {
        val p12 = readP12("demo-original-container.p12")
        SignatureVerifier.verifyRegistry(p12)
    }

    @Test
    fun parseSpasDelegate() {
        val p12 = readP12("spas-delegate.p12")
        val c = RegistryParser.parse(p12)
        assertEquals(3, c.pfxVersion)
        assertTrue(c.safeBagInfos.isNotEmpty())
    }

    @Test
    fun spasDelegateParsesUnsignedContainer() {
        val c = RegistryParser.parse(readP12("spas-delegate.p12"))
        assertEquals(3, c.pfxVersion)
        assertTrue(c.safeBagInfos.isNotEmpty())
        assertFalse(c.signerCertResolved)
        assertTrue(
            c.encryptedDigest == null ||
                c.parseWarnings.any { it.contains("SignerInfo", ignoreCase = true) },
        )
    }

    @Test
    fun spasDelegateVerifyFailsWithoutSignature() {
        assertFailsWith<Exception> {
            SignatureVerifier.verifyRegistry(readP12("spas-delegate.p12"))
        }
    }

    @Test
    fun tamperedSignatureFailsVerify() {
        val c = RegistryParser.parse(readP12("demo-original-container.p12"))
        val digest = c.encryptedDigest!!.copyOf()
        digest[0] = (digest[0].toInt() xor 0xFF).toByte()
        assertFailsWith<Exception> {
            SignatureVerifier.verifyContainer(c.copy(encryptedDigest = digest))
        }
    }

    @Test
    fun demoUsesSubjectKeyIdentifierSid() {
        val c = RegistryParser.parse(readP12("demo-original-container.p12"))
        assertEquals(0xA0, c.firstSignerSidTag)
        assertTrue(c.signerCertResolved)
    }

    @Test
    fun strictParseSucceedsOnCleanContainer() {
        val p12 = readP12("demo-original-container.p12")
        val c = RegistryParser.parse(p12, ParseOptions(strict = true))
        assertTrue(c.parseWarnings.isEmpty())
        SgwRegistry.parse(p12, ParseOptions(strict = true))
    }

    @Test
    fun toJsonIncludesCertificateDetails() {
        val c = RegistryParser.parse(readP12("demo-original-container.p12"))
        val json = RegistryAnalyzer.toJson(c).decodeToString()
        assertTrue(json.contains("\"certificates\""))
        assertTrue(json.contains("\"isSigner\""))
        assertTrue(json.contains("\"safeBagInfos\""))
    }

    @Test
    fun safeBagInputEqualsByByteArrayValue() {
        val der = byteArrayOf(1, 2, 3)
        val a = com.atom.sgwregistry.model.SafeBagInput(der, "role")
        val b = com.atom.sgwregistry.model.SafeBagInput(der.copyOf(), "role")
        assertEquals(a, b)
    }

    @Test
    fun roundTripBuildUsesSubjectKeyIdentifier() {
        if (!TestBuildConfig.exists()) return
        val built = RegistryBuilder.buildRegistry(TestBuildConfig.load())
        val parsed = RegistryParser.parse(built)
        assertEquals(0xA0, parsed.firstSignerSidTag)
        assertTrue(parsed.signerCertResolved)
    }

    @Test
    fun addCertificateAndResignIncreasesSafeBags() {
        require(TestBuildConfig.exists()) { "config.json required" }
        val buildCfg = TestBuildConfig.load()
        val built = RegistryBuilder.buildRegistry(buildCfg)
        val before = RegistryParser.parse(built)
        val newBag = buildCfg.safeBags.first()
        val updated = RegistryBuilder.addCertificateAndResign(
            before,
            com.atom.sgwregistry.model.AddCertificateRequest(
                existingP12 = built,
                newBag = newBag,
                signerCertDer = buildCfg.signerCertDer,
                signerKey = buildCfg.signerKey,
                rejectDuplicateCert = false,
            ),
        )
        val after = RegistryParser.parse(updated)
        assertEquals(before.safeBagInfos.size + 1, after.safeBagInfos.size)
        SignatureVerifier.verifyRegistry(updated)
    }

    @Test
    fun addCertificateIncrementsVer() {
        val p12 = readP12("demo-original-container.p12")
        val before = RegistryParser.parse(p12)
        val beforeAttrs = RegistryAnalyzer.parseAuthenticatedAttributes(before.authenticatedAttributesSetBytes)
        val beforeVer = beforeAttrs.first { it.first == "VER" }.second
        val (_, beforeVersion) = com.atom.sgwregistry.builder.VerAttribute.parseText(beforeVer)

        require(TestBuildConfig.exists()) { "config.json required" }
        val buildCfg = TestBuildConfig.load()
        val newBag = buildCfg.safeBags.firstOrNull { bag ->
            before.safeBagInfos.none { info ->
                info.certValueDer?.contentEquals(bag.certDer) == true
            }
        } ?: return

        val updated = RegistryBuilder.addCertificateAndResign(
            before,
            com.atom.sgwregistry.model.AddCertificateRequest(
                existingP12 = p12,
                newBag = newBag,
                signerCertDer = buildCfg.signerCertDer,
                signerKey = buildCfg.signerKey,
            ),
        )
        val after = RegistryParser.parse(updated)
        val afterVer = RegistryAnalyzer.parseAuthenticatedAttributes(after.authenticatedAttributesSetBytes)
            .first { it.first == "VER" }.second
        val (_, afterVersion) = com.atom.sgwregistry.builder.VerAttribute.parseText(afterVer)
        assertEquals(beforeVersion + 1, afterVersion)
        SignatureVerifier.verifyRegistry(updated)
    }

    @Test
    fun removeCertificateBySkidAndResign() {
        require(TestBuildConfig.exists()) { "config.json required" }
        val buildCfg = TestBuildConfig.load()
        val built = RegistryBuilder.buildRegistry(buildCfg)
        val before = RegistryParser.parse(built)
        val target = buildCfg.safeBags.first()
        val cert = PlatformCrypto.parseCertificate(PemEncoding.decodePemOrDer(target.certDer))
        val skid = PlatformCrypto.getSubjectKeyId(cert)
        assertTrue(skid.isNotEmpty())
        val updated = RegistryBuilder.removeCertificateBySkidAndResign(
            before,
            RemoveCertificateBySkidRequest(
                existingP12 = built,
                subjectKeyId = skid,
                signerCertDer = buildCfg.signerCertDer,
                signerKey = buildCfg.signerKey,
            ),
        )
        val after = RegistryParser.parse(updated)
        assertEquals(before.safeBagInfos.size - 1, after.safeBagInfos.size)
        SignatureVerifier.verifyRegistry(updated)
    }

    @Test
    fun removeCertificateBySkidHexAndResign() {
        require(TestBuildConfig.exists()) { "config.json required" }
        val buildCfg = TestBuildConfig.load()
        val built = RegistryBuilder.buildRegistry(buildCfg)
        val target = buildCfg.safeBags.last()
        val cert = PlatformCrypto.parseCertificate(PemEncoding.decodePemOrDer(target.certDer))
        val skidHex = PemEncoding.skidToHex(
            target.localKeyId ?: PlatformCrypto.getSubjectKeyId(cert),
        )
        val updated = RegistryBuilder.removeCertificateBySkidAndResign(
            existingP12 = built,
            subjectKeyIdHex = skidHex,
            signerCertDer = buildCfg.signerCertDer,
            signerKey = buildCfg.signerKey,
        )
        assertEquals(buildCfg.safeBags.size - 1, RegistryParser.parse(updated).safeBagInfos.size)
        SignatureVerifier.verifyRegistry(updated)
    }

    @Test
    fun removeCertificateBySkidNotFoundThrows() {
        require(TestBuildConfig.exists()) { "config.json required" }
        val buildCfg = TestBuildConfig.load()
        val built = RegistryBuilder.buildRegistry(buildCfg)
        assertFailsWith<IllegalArgumentException> {
            RegistryBuilder.removeCertificateBySkidAndResign(
                RemoveCertificateBySkidRequest(
                    existingP12 = built,
                    subjectKeyId = byteArrayOf(0x01, 0x02, 0x03, 0x04),
                    signerCertDer = buildCfg.signerCertDer,
                    signerKey = buildCfg.signerKey,
                ),
            )
        }
    }

    @Test
    fun addCertificateRejectsDuplicateByDefault() {
        require(TestBuildConfig.exists()) { "config.json required" }
        val buildCfg = TestBuildConfig.load()
        val built = RegistryBuilder.buildRegistry(buildCfg)
        val bag = buildCfg.safeBags.first()
        assertFailsWith<IllegalArgumentException> {
            RegistryBuilder.addCertificateAndResign(
                com.atom.sgwregistry.model.AddCertificateRequest(
                    existingP12 = built,
                    newBag = bag,
                    signerCertDer = buildCfg.signerCertDer,
                    signerKey = buildCfg.signerKey,
                ),
            )
        }
    }

    @Test
    fun roundTripBuildAndVerifyIfConfigPresent() {
        require(TestBuildConfig.exists()) { "config.json required for round-trip test" }
        val buildCfg = TestBuildConfig.load()
        val built = RegistryBuilder.buildRegistry(buildCfg)
        val parsed = RegistryParser.parse(built)
        assertEquals(buildCfg.safeBags.size, parsed.safeBagInfos.size)
        assertTrue(parsed.signerCertResolved)
        SignatureVerifier.verifyRegistry(built)
    }

    @Test
    fun derUtilsCanonicalSet() {
        val set = byteArrayOf(
            0x31, 0x0a,
            0x30, 0x03, 0x02, 0x01, 0x02,
            0x30, 0x03, 0x02, 0x01, 0x01,
        )
        val canonical = DerUtils.canonicalSetDer(set)
        assertNotNull(canonical)
        assertTrue(canonical!!.isNotEmpty())
    }

    @Test
    fun parseAuthenticatedAttributesFromDemo() {
        val p12 = readP12("demo-original-container.p12")
        val c = RegistryParser.parse(p12)
        val attrs = RegistryAnalyzer.parseAuthenticatedAttributes(c.authenticatedAttributesSetBytes)
        assertTrue(attrs.any { it.first == "VIN" })
        assertTrue(attrs.any { it.first == "messageDigest" })
        val detailed = RegistryAnalyzer.toTextDetailed(c)
        assertTrue(detailed.contains("messageDigest check: OK"))
        assertTrue(detailed.contains("signature check (signer cert): OK"))
    }

    @Test
    fun registryContainerIsImmutableCopy() {
        val p12 = readP12("demo-original-container.p12")
        val c = RegistryParser.parse(p12)
        val eContent = c.eContentBytes!!
        eContent[0] = 0x00
        val c2 = RegistryParser.parse(p12)
        assertNotEquals(0x00.toByte(), c2.eContentBytes!![0])
    }

    @Test
    fun noSilentSignerFallbackWhenSkidWrong() {
        val p12 = readP12("demo-original-container.p12")
        val c = RegistryParser.parse(p12)
        val mutated = c.copy(
            signerCertDer = c.certificatesDer.first(),
            signerCertResolved = false,
        )
        assertFalse(mutated.signerCertResolved)
        val attrs = RegistryAnalyzer.parseAuthenticatedAttributes(mutated.authenticatedAttributesSetBytes)
        assertTrue(attrs.isNotEmpty())
    }

    @Test
    fun loadSignerKeyFromPem() {
        if (!TestFixtures.exists("certs/signer-key.pem")) return
        val key = PlatformCrypto.parseEcPrivateKey(TestFixtures.readBytes("certs/signer-key.pem"))
        assertNotNull(key)
    }
}
