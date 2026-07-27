package com.atom.sgwregistry

import com.atom.sgwregistry.cloudconfig.CloudBrokerFqdn
import kotlin.test.Test
import kotlin.test.assertEquals

class CloudBrokerFqdnTest {
    @Test
    fun hashBMatchesCesExample() {
        // CES 2.1.2 §5.4: VIN 1GNDT13S532183584 → c602
        assertEquals("c602", CloudBrokerFqdn.hashB("1GNDT13S532183584"))
    }

    @Test
    fun buildFqdnMatchesCesExample() {
        val fqdn = CloudBrokerFqdn.buildFqdn(
            vin = "1GNDT13S532183584",
            identityId = "bdb79393-a9e3-4024-86a8-5f372df9121f",
            domainSuffix = "mqtt.atom.auto",
        )
        assertEquals(
            "c602-bdb79393-a9e3-4024-86a8-5f372df9121f.mqtt.atom.auto",
            fqdn,
        )
    }

    @Test
    fun resolveFromRespContextVinAndTenantId() {
        // resp-context.json: vin + tenant_id + draft base_domain mqtt.atom.auto
        val fqdn = CloudBrokerFqdn.buildFqdn(
            vin = "EAY1F1C56T2000014",
            identityId = "2281305f-4b16-4a49-989a-9abeeac2df20",
            domainSuffix = "mqtt.atom.auto",
        )
        assertEquals(
            "d06e-2281305f-4b16-4a49-989a-9abeeac2df20.mqtt.atom.auto",
            fqdn,
        )
    }
}
