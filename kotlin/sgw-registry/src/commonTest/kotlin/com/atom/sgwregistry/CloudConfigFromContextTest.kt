package com.atom.sgwregistry

import com.atom.sgwregistry.cloudconfig.CloudConfigCms
import com.atom.sgwregistry.cloudconfig.CloudConfigFromContext
import com.atom.sgwregistry.cloudconfig.CloudConfigFqdnIdentitySource
import com.atom.sgwregistry.model.InvitationContextJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CloudConfigFromContextTest {
    @Test
    fun parseRespContextAndExtractOwnerUid() {
        if (!TestFixtures.exists("resp-context.json")) return
        val response = InvitationContextJson.parse(TestFixtures.readBytes("resp-context.json"))
        assertEquals("EAY1F1C56T2000014", response.vin)
        assertEquals("1281705f-8b16-4a49-989a-9abeeac2df20", response.id)
        val uid = CloudConfigFromContext.extractOwnerIdFromOwnershipCms(
            response.context.ownershipRegistry,
        )
        assertEquals("9c1dc2f4-a015-46b7-b88f-a9e30d0a9f86", uid)
    }

    @Test
    fun buildCloudConfigJsonCamelCase() {
        if (!TestFixtures.exists("resp-context.json")) return
        val response = InvitationContextJson.parse(TestFixtures.readBytes("resp-context.json"))
        val json = CloudConfigFromContext.buildCloudConfigJson(
            response.context.vehicleCloudConfiguration,
            payloadVersion = 5,
        )
        assertTrue(json.startsWith("""{"v":5,"cloudBroker":{"""))
        assertTrue(json.contains(""""rootCAs":["""))
        assertTrue(json.contains(""""fqdnConstrAlg":1"""))
        assertTrue(json.contains(""""baseDomain":"mqtt.atom.auto""""))
        assertTrue(!json.contains("fqdn_constr_alg"))
        assertTrue(!json.contains("root_cas"))
    }

    @Test
    fun rejectPlaceholderRootCas() {
        if (!TestFixtures.exists("resp-context.json")) return
        val response = InvitationContextJson.parse(TestFixtures.readBytes("resp-context.json"))
        val bad = response.context.vehicleCloudConfiguration.copy(
            cloudBroker = response.context.vehicleCloudConfiguration.cloudBroker.copy(
                rootCas = listOf("-----BEGIN CERTIFICATE-----\n<ATOM mTLS CA>\n-----END CERTIFICATE-----"),
            ),
        )
        assertFailsWith<IllegalArgumentException> {
            CloudConfigFromContext.buildCloudConfigJson(bad, payloadVersion = 5)
        }
    }

    @Test
    fun buildAndSignThenVerify() {
        if (!TestFixtures.exists("resp-context.json")) return
        if (!TestBuildConfig.exists()) return
        val response = InvitationContextJson.parse(TestFixtures.readBytes("resp-context.json"))
        val buildCfg = TestBuildConfig.load()
        // demo signer.pem: нет SAN URI atombus:/user/… — binding для Ownership leaf
        val signed = CloudConfigFromContext.buildAndSign(
            response = response,
            signerCertDer = buildCfg.signerCertDer,
            signerKey = buildCfg.signerKey,
            payloadVersion = 5,
            requireOwnerBinding = false,
        )
        assertEquals(response.vin, signed.vin)
        assertEquals("9c1dc2f4-a015-46b7-b88f-a9e30d0a9f86", signed.ownerId)
        assertTrue(signed.cloudConfigPem.contains("BEGIN CMS"))
        assertTrue(signed.cloudConfigJson.contains(""""v":5"""))
        // FQDN по умолчанию строится из owner_id (не tenant_id)
        assertTrue(
            signed.cloudConfigJson.contains("9c1dc2f4-a015-46b7-b88f-a9e30d0a9f86"),
            "FQDN must embed owner_id",
        )
        CloudConfigCms.verifyCloudConfiguration(signed)
        CloudConfigCms.requireIdentity(signed, response.vin, signed.ownerId)
    }

    @Test
    fun buildAndSignRejectsOwnerBindingWithoutSan() {
        if (!TestFixtures.exists("resp-context.json")) return
        if (!TestBuildConfig.exists()) return
        val response = InvitationContextJson.parse(TestFixtures.readBytes("resp-context.json"))
        val buildCfg = TestBuildConfig.load()
        assertFailsWith<IllegalArgumentException> {
            CloudConfigFromContext.buildAndSign(
                response = response,
                signerCertDer = buildCfg.signerCertDer,
                signerKey = buildCfg.signerKey,
                payloadVersion = 5,
                requireOwnerBinding = true,
            )
        }
    }

    @Test
    fun fqdnIdentitySourceOwnerVsTenant() {
        if (!TestFixtures.exists("resp-context.json")) return
        val response = InvitationContextJson.parse(TestFixtures.readBytes("resp-context.json"))
        val ownerUid = "9c1dc2f4-a015-46b7-b88f-a9e30d0a9f86"
        assertEquals(response.tenantId, "2281305f-4b16-4a49-989a-9abeeac2df20")

        val fromOwner = CloudConfigFromContext.buildUnsignedConfiguration(
            response = response,
            payloadVersion = 5,
            fqdnIdentitySource = CloudConfigFqdnIdentitySource.OwnerId,
        )
        assertTrue(fromOwner.baseDomain.contains(ownerUid))
        assertTrue(!fromOwner.baseDomain.contains(response.tenantId))

        val fromTenant = CloudConfigFromContext.buildUnsignedConfiguration(
            response = response,
            payloadVersion = 5,
            fqdnIdentitySource = CloudConfigFqdnIdentitySource.TenantId,
        )
        assertTrue(fromTenant.baseDomain.contains(response.tenantId))
        assertTrue(!fromTenant.baseDomain.contains(ownerUid))

        val tenantThenOwner = CloudConfigFromContext.resolveFqdnIdentityId(
            response = response,
            resolvedOwnerId = ownerUid,
            fqdnIdentitySource = CloudConfigFqdnIdentitySource.TenantIdThenOwnerId,
        )
        assertEquals(response.tenantId, tenantThenOwner)

        val explicit = CloudConfigFromContext.resolveFqdnIdentityId(
            response = response,
            resolvedOwnerId = ownerUid,
            fqdnIdentityId = "explicit-id",
            fqdnIdentitySource = CloudConfigFqdnIdentitySource.TenantId,
        )
        assertEquals("explicit-id", explicit)
    }
}
