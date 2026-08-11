package com.atom.sgwregistry

import com.atom.sgwregistry.api.SgwRegistry
import com.atom.sgwregistry.ownership.OwnershipLedgerJson
import com.atom.sgwregistry.ownership.OwnershipRegistryVerifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class OwnershipRegistryVerifierTest {
    private fun loadLedger() = OwnershipLedgerJson.parse(TestFixtures.readBytes("ownership-resp.json"))

    @Test
    fun verifyChainFromOwnershipRespJson() {
        if (!TestFixtures.exists("ownership-resp.json")) return
        val ledger = loadLedger()
        assertEquals("AAABBBCCC3", ledger.vin)
        assertEquals(2, ledger.context.ownershipRegistry.size)

        val lastOwnerId = "7f9fc821-a09e-4f96-badc-643daca070c6"
        val result = OwnershipRegistryVerifier.tryVerify(
            ownershipRegistryCms = ledger.context.ownershipRegistry,
            ownerId = lastOwnerId,
            vin = ledger.vin,
        )
        assertTrue(result.ok, result.reason ?: "expected OK")
        assertEquals(2, result.statementCount)
        assertEquals(ledger.vin, result.vin)
        assertEquals(lastOwnerId, result.ownerId)

        assertTrue(
            OwnershipRegistryVerifier.verify(
                ledger.context.ownershipRegistry,
                lastOwnerId,
                ledger.vin,
            ),
        )
        assertTrue(OwnershipRegistryVerifier.verifyLedger(ledger, lastOwnerId))
        assertTrue(SgwRegistry.verifyOwnershipLedger(ledger, lastOwnerId))
        assertTrue(SgwRegistry.verifyOwnershipRegistry(ledger.context.ownershipRegistry, lastOwnerId, ledger.vin))
        assertEquals(2, ledger.context.vehicleCloudConfiguration.currentVersion)
        assertEquals(2, ledger.context.vehicleCloudConfiguration.cloudBroker.rootCas.size)
    }

    @Test
    fun failsOnWrongOwnerId() {
        if (!TestFixtures.exists("ownership-resp.json")) return
        val ledger = loadLedger()
        val result = OwnershipRegistryVerifier.tryVerify(
            ledger.context.ownershipRegistry,
            ownerId = "aa9f5c8d-246a-429b-926a-22f1fc57d314",
            vin = ledger.vin,
        )
        assertFalse(result.ok)
        assertNotNull(result.reason)
        assertTrue(result.reason!!.contains("ownerId mismatch"))
    }

    @Test
    fun failsOnWrongVin() {
        if (!TestFixtures.exists("ownership-resp.json")) return
        val ledger = loadLedger()
        val result = OwnershipRegistryVerifier.tryVerify(
            ledger.context.ownershipRegistry,
            ownerId = "7f9fc821-a09e-4f96-badc-643daca070c6",
            vin = "1000VIN000VIN0001",
        )
        assertFalse(result.ok)
        assertNotNull(result.reason)
        assertTrue(result.reason!!.contains("VIN mismatch"))
    }

    @Test
    fun failsOnBrokenPHashChain() {
        if (!TestFixtures.exists("ownership-resp.json")) return
        val ledger = loadLedger()
        // reverse order breaks p_hash linkage
        val reversed = ledger.context.ownershipRegistry.asReversed()
        val result = OwnershipRegistryVerifier.tryVerify(
            reversed,
            ownerId = "7f9fc821-a09e-4f96-badc-643daca070c6",
            vin = ledger.vin,
        )
        assertFalse(result.ok)
        assertNotNull(result.reason)
    }

    @Test
    fun failsOnEmptyRegistry() {
        val result = OwnershipRegistryVerifier.tryVerify(emptyList(), "owner", "VIN")
        assertFalse(result.ok)
        assertEquals("ownership_registry is empty", result.reason)
    }

    @Test
    fun extractUidFromOwnerDn() {
        val uid = OwnershipRegistryVerifier.extractUidFromOwnerDn(
            "UID=7f9fc821-a09e-4f96-badc-643daca070c6,OU=EnhancedAuth+OU=Customers,O=ATOM",
        )
        assertEquals("7f9fc821-a09e-4f96-badc-643daca070c6", uid)
    }

    @Test
    fun genesisStatementHasEmptyPHash() {
        if (!TestFixtures.exists("ownership-resp.json")) return
        val ledger = loadLedger()
        val container = com.atom.sgwregistry.cloudconfig.CloudConfigCms.parsePem(
            ledger.context.ownershipRegistry[0],
        )
        val st0 = OwnershipRegistryVerifier.parseStatement(container)
        assertEquals(1, st0.v)
        assertEquals("", st0.previousHash)
        assertEquals("AAABBBCCC3", st0.vin)
        assertEquals(
            "00000000-0000-7000-8000-000057751751",
            OwnershipRegistryVerifier.extractUidFromOwnerDn(st0.ownerDn),
        )

        val st1 = OwnershipRegistryVerifier.parseStatement(
            com.atom.sgwregistry.cloudconfig.CloudConfigCms.parsePem(ledger.context.ownershipRegistry[1]),
        )
        assertEquals(2, st1.v)
        assertTrue(st1.previousHash.isNotEmpty())
        assertEquals(
            "7f9fc821-a09e-4f96-badc-643daca070c6",
            OwnershipRegistryVerifier.extractUidFromOwnerDn(st1.ownerDn),
        )
    }
}
