package com.atom.sgwregistry

import com.atom.sgwregistry.cloudconfig.CloudConfigCms
import com.atom.sgwregistry.model.CloudConfigResignOnlyRequest
import com.atom.sgwregistry.model.CloudConfigResignRequest
import com.atom.sgwregistry.model.MobDevCloudConfigJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CloudConfigCmsTest {
    private fun loadMobDev() = MobDevCloudConfigJson.parse(
        TestFixtures.readBytes("mob-dev-cloud_config.json"),
    )

    @Test
    fun parseMobDevCloudConfigJson() {
        if (!TestFixtures.exists("mob-dev-cloud_config.json")) return
        val response = MobDevCloudConfigJson.parse(TestFixtures.readBytes("mob-dev-cloud_config.json"))
        assertEquals("79079999999", response.cloudConfiguration.vin)
        assertTrue(response.cloudConfiguration.cloudConfigPem.contains("BEGIN CMS"))
        assertTrue(response.cloudConfiguration.cloudConfigJson.contains("cloudBroker"))
    }

    @Test
    fun parseAndVerifyMobDevCloudConfigPem() {
        if (!TestFixtures.exists("mob-dev-cloud_config.json")) return
        val dto = loadMobDev().cloudConfiguration
        val container = CloudConfigCms.parsePem(dto.cloudConfigPem)
        assertTrue(container.signerCertResolved)
        assertEquals(2096, container.eContentBytes?.size)
        CloudConfigCms.verifyJsonMatchesEContent(container, dto.cloudConfigJson)
        CloudConfigCms.verify(container)
    }

    @Test
    fun verifyCloudConfigurationEndToEnd() {
        if (!TestFixtures.exists("mob-dev-cloud_config.json")) return
        val dto = loadMobDev().cloudConfiguration
        CloudConfigCms.verifyCloudConfiguration(dto)
    }

    @Test
    fun toTextIncludesSignerAndDigestCheck() {
        if (!TestFixtures.exists("mob-dev-cloud_config.json")) return
        val text = CloudConfigCms.toText(loadMobDev().cloudConfiguration)
        assertTrue(text.contains("Signer subject:"))
        assertTrue(text.contains("messageDigest check: OK"))
        assertTrue(text.contains("signature check: OK"))
    }

    @Test
    fun resignRoundTripWithTestSigner() {
        if (!TestFixtures.exists("mob-dev-cloud_config.json")) return
        if (!TestBuildConfig.exists()) return
        val dto = loadMobDev().cloudConfiguration
        val buildCfg = TestBuildConfig.load()
        val newPem = CloudConfigCms.resignToPem(
            CloudConfigResignRequest(
                jsonPayload = dto.cloudConfigJson,
                signerCertDer = buildCfg.signerCertDer,
                signerKey = buildCfg.signerKey,
            ),
        )
        val resigned = CloudConfigCms.parsePem(newPem)
        CloudConfigCms.verifyJsonMatchesEContent(resigned, dto.cloudConfigJson)
        CloudConfigCms.verify(resigned)
        assertTrue((resigned.encryptedDigest?.size ?: 0) >= 70)
        assertEquals(0x30.toByte(), resigned.encryptedDigest!![0])
    }

    @Test
    fun requireIdentityAndOwnerIdInSigner() {
        if (!TestFixtures.exists("mob-dev-cloud_config.json")) return
        val dto = loadMobDev().cloudConfiguration
        CloudConfigCms.requireIdentity(dto, "79079999999", "d231b684-82b4-4fdc-83dd-fc9a1861c293")
        assertTrue(CloudConfigCms.matchesIdentity(dto, "79079999999", "d231b684-82b4-4fdc-83dd-fc9a1861c293"))
        CloudConfigCms.requireOwnerIdInSigner(dto)
    }

    @Test
    fun requireOwnerIdBindingMatchesFqdnAndSanUri() {
        if (!TestFixtures.exists("mob-dev-cloud_config.json")) return
        val dto = loadMobDev().cloudConfiguration
        CloudConfigCms.requireOwnerIdBinding(dto)
        val der = CloudConfigCms.parsePem(dto.cloudConfigPem).signerCertDer!!
        val uris = CloudConfigCms.extractSanUris(der)
        assertTrue(uris.any { it == "atombus:/user/d231b684-82b4-4fdc-83dd-fc9a1861c293" })
        assertEquals(
            "d231b684-82b4-4fdc-83dd-fc9a1861c293",
            CloudConfigCms.extractOwnerIdFromSanUris(uris),
        )
        assertTrue(CloudConfigCms.EKU_EMAIL_PROTECTION in CloudConfigCms.extractEkuOids(der))
    }

    @Test
    fun requireOwnerIdBindingRejectsMismatchedOwner() {
        if (!TestFixtures.exists("mob-dev-cloud_config.json")) return
        val dto = loadMobDev().cloudConfiguration
        val der = CloudConfigCms.parsePem(dto.cloudConfigPem).signerCertDer!!
        assertFailsWith<IllegalArgumentException> {
            CloudConfigCms.requireOwnerIdBinding(
                ownerId = "00000000-0000-0000-0000-000000000000",
                baseDomain = dto.baseDomain,
                signerCertDer = der,
            )
        }
    }

    @Test
    fun fixtureA1RejectsOwnerIdFqdnMismatch() {
        // Лог-анализ: UID signer / owner_id ≠ UID в baseDomain
        if (!TestFixtures.exists("a1-cloud-config-signed.json")) return
        val dto = MobDevCloudConfigJson.parse(
            TestFixtures.readBytes("a1-cloud-config-signed.json"),
        ).cloudConfiguration
        assertFailsWith<IllegalArgumentException> {
            CloudConfigCms.requireOwnerIdBinding(dto, requireEku = false)
        }
    }

    @Test
    fun fixtureARejectsClientAuthEku() {
        // Лог-анализ: EKU = TLS Client Auth вместо Email Protection
        if (!TestFixtures.exists("a-cloud-config-signed.json")) return
        val dto = MobDevCloudConfigJson.parse(
            TestFixtures.readBytes("a-cloud-config-signed.json"),
        ).cloudConfiguration
        val der = CloudConfigCms.parsePem(dto.cloudConfigPem).signerCertDer!!
        val ekus = CloudConfigCms.extractEkuOids(der)
        assertTrue(CloudConfigCms.EKU_CLIENT_AUTH in ekus)
        assertTrue(CloudConfigCms.EKU_EMAIL_PROTECTION !in ekus)
        assertFailsWith<IllegalArgumentException> {
            CloudConfigCms.requireSignerEkuForCms(der)
        }
    }

    @Test
    fun fixtureCloudConfigJsonPassesBindingAndEku() {
        if (!TestFixtures.exists("cloud-config.json")) return
        val dto = MobDevCloudConfigJson.parse(
            TestFixtures.readBytes("cloud-config.json"),
        ).cloudConfiguration
        CloudConfigCms.requireOwnerIdBinding(dto)
        CloudConfigCms.requireOwnerIdInSigner(dto)
    }

    @Test
    fun resignOnlyPreservesExistingEContent() {
        if (!TestFixtures.exists("mob-dev-cloud_config.json")) return
        if (!TestBuildConfig.exists()) return
        val dto = loadMobDev().cloudConfiguration
        val original = CloudConfigCms.parsePem(dto.cloudConfigPem)
        val buildCfg = TestBuildConfig.load()
        val request = CloudConfigResignOnlyRequest(
            signerCertDer = buildCfg.signerCertDer,
            signerKey = buildCfg.signerKey,
        )
        val resignedDer = CloudConfigCms.resignOnly(original, request)
        val resigned = CloudConfigCms.parsePem(
            com.atom.sgwregistry.crypto.PemEncoding.cmsToPem(resignedDer),
        )
        assertTrue(original.eContentBytes!!.contentEquals(resigned.eContentBytes))
        CloudConfigCms.verifyJsonMatchesEContent(resigned, dto.cloudConfigJson)
        CloudConfigCms.verify(resigned)
    }

    @Test
    fun resignConfigurationOnlyUpdatesPemOnly() {
        if (!TestFixtures.exists("mob-dev-cloud_config.json")) return
        if (!TestBuildConfig.exists()) return
        val dto = loadMobDev().cloudConfiguration
        val buildCfg = TestBuildConfig.load()
        val updated = CloudConfigCms.resignConfigurationOnly(
            dto = dto,
            signerCertDer = buildCfg.signerCertDer,
            signerKey = buildCfg.signerKey,
        )
        assertEquals(dto.cloudConfigJson, updated.cloudConfigJson)
        assertTrue(updated.cloudConfigPem.contains("BEGIN CMS"))
        CloudConfigCms.verifyCloudConfiguration(updated)
    }

    @Test
    fun resignProducesOpensslFriendlyCertificateEncoding() {
        // Cloud-config CMS: Certificate как SEQUENCE (не OCTET STRING), SID = IssuerAndSerial SEQUENCE.
        if (!TestFixtures.exists("mob-dev-cloud_config.json")) return
        if (!TestBuildConfig.exists()) return
        val dto = loadMobDev().cloudConfiguration
        val buildCfg = TestBuildConfig.load()
        val newPem = CloudConfigCms.resignToPem(
            CloudConfigResignRequest(
                jsonPayload = dto.cloudConfigJson,
                signerCertDer = buildCfg.signerCertDer,
                signerKey = buildCfg.signerKey,
            ),
        )
        val resigned = CloudConfigCms.parsePem(newPem)
        CloudConfigCms.verify(resigned)
        assertTrue(resigned.signerCertResolved)
        // IssuerAndSerialNumber — нетегированная SEQUENCE (0x30), не [1]/0xA1
        assertEquals(0x30, resigned.firstSignerSidTag)
        assertTrue(resigned.certificatesDer.isNotEmpty())
        assertEquals(0x30, resigned.certificatesDer[0][0].toInt() and 0xFF)
    }

    @Test
    fun registryParserParseCmsWorksOnMobDevPem() {
        if (!TestFixtures.exists("mob-dev-cloud_config.json")) return
        val dto = loadMobDev().cloudConfiguration
        val cms = com.atom.sgwregistry.crypto.PemEncoding.decodePemOrDer(dto.cloudConfigPem.encodeToByteArray())
        val c = com.atom.sgwregistry.parser.RegistryParser.parseCms(cms)
        assertTrue(c.signerCertResolved)
        com.atom.sgwregistry.verifier.SignatureVerifier.verifyContainer(c)
    }
}
