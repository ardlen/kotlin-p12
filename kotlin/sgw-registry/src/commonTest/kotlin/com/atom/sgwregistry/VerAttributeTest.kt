package com.atom.sgwregistry

import com.atom.sgwregistry.builder.VerAttribute
import kotlinx.datetime.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class VerAttributeTest {
    @Test
    fun parseAndFormatVerText() {
        val ts = Instant.parse("2026-01-19T12:00:00Z")
        val text = VerAttribute.formatText(ts, 102)
        assertEquals("2026-01-19 12:00:00:V102", text)
        val (parsedTs, ver) = VerAttribute.parseText(text)
        assertEquals(ts, parsedTs)
        assertEquals(102, ver)
    }

    @Test
    fun parseRejectsInvalidFormat() {
        assertFailsWith<IllegalArgumentException> {
            VerAttribute.parseText("2026-01-19T12:00:00Z")
        }
        assertFailsWith<IllegalArgumentException> {
            VerAttribute.parseText("2026-01-19 12:00:00:V0")
        }
    }

    @Test
    fun bumpIncrementsVersion() {
        val attrs = com.atom.sgwregistry.model.SignerAttrs(
            vin = "VIN",
            verTimestamp = Instant.parse("2026-01-19T12:00:00Z"),
            verVersion = 102,
            uid = "UID",
        )
        val bumped = VerAttribute.bumpForRegistryUpdate(attrs)
        assertEquals(103, bumped.verVersion)
        assertTrue(bumped.verTimestamp >= attrs.verTimestamp)
    }
}
