package com.atom.sgwregistry.asn1

import com.atom.sgwregistry.internal.bytesToHex
import com.atom.sgwregistry.model.SafeBagInfo
import com.atom.sgwregistry.util.formatVerTimestamp
import kotlinx.datetime.Instant

/** Общий разбор CMS/PKCS#12 Attribute. */
object AttributeDecoder {
    data class BagAttributes(
        val roleName: String? = null,
        val localKeyId: ByteArray? = null,
        val roleNotBefore: Instant? = null,
        val roleNotAfter: Instant? = null,
    )

    fun parseAuthenticatedAttributes(setBytes: ByteArray?): List<Pair<String, String>> {
        val list = ArrayList<Pair<String, String>>()
        if (setBytes == null || setBytes.size < 2) return list
        try {
            val set = AsnReader(setBytes).readSet()
            while (set.hasData()) {
                val attr = set.readSequence()
                val oid = attr.readObjectIdentifier()
                val values = attr.readSet()
                decodeAuthValue(oid, values)?.let { (name, value) -> list.add(name to value) }
            }
        } catch (_: Exception) { }
        return list
    }

    fun parseBagAttributes(setTlv: ByteArray): BagAttributes {
        var roleName: String? = null
        var localKeyId: ByteArray? = null
        var roleNotBefore: Instant? = null
        var roleNotAfter: Instant? = null
        try {
            val set = AsnReader(setTlv).readSet()
            while (set.hasData()) {
                val attr = set.readSequence()
                val oid = attr.readObjectIdentifierString()
                val values = attr.readSet()
                when {
                    Oids.oidEquals(oid, Oids.pkcs9FriendlyName) || Oids.oidEquals(oid, Oids.atomRoleName) ->
                        roleName = values.readUtf8String()
                    Oids.oidEquals(oid, Oids.pkcs9LocalKeyId) ->
                        localKeyId = values.readOctetString()
                    Oids.oidEquals(oid, Oids.atomRoleValidityPeriod) -> {
                        val period = values.readSequence()
                        roleNotBefore = period.readGeneralizedTime()
                        roleNotAfter = period.readGeneralizedTime()
                    }
                }
            }
        } catch (_: Exception) { }
        return BagAttributes(roleName, localKeyId, roleNotBefore, roleNotAfter)
    }

    fun applyBagAttributes(info: SafeBagInfo, attrs: BagAttributes): SafeBagInfo = info.copy(
        roleName = attrs.roleName ?: info.roleName,
        localKeyId = attrs.localKeyId ?: info.localKeyId,
        roleNotBefore = attrs.roleNotBefore ?: info.roleNotBefore,
        roleNotAfter = attrs.roleNotAfter ?: info.roleNotAfter,
    )

    private fun decodeAuthValue(oid: IntArray, values: AsnReader): Pair<String, String>? {
        val valueStr = when {
            Oids.oidEquals(oid, Oids.pkcs9ContentType) -> {
                val s = values.readObjectIdentifierString()
                if (Oids.oidEquals(s, Oids.pkcs7Data)) "pkcs7-data" else s
            }
            Oids.oidEquals(oid, Oids.pkcs9MessageDigest) ->
                values.readOctetString().let(::bytesToHex)
            Oids.oidEquals(oid, Oids.pkcs9SigningTime) ->
                values.readUtcTime().toString()
            Oids.oidEquals(oid, Oids.atomVin) || Oids.oidEquals(oid, Oids.atomUid) ->
                values.readUtf8String()
            Oids.oidEquals(oid, Oids.atomVer) -> {
                val ver = values.readSequence()
                val ts = ver.readGeneralizedTime()
                val v = ver.readInteger()
                "${formatVerTimestamp(ts)}:V$v"
            }
            else -> return null
        }
        val name = when {
            Oids.oidEquals(oid, Oids.pkcs9ContentType) -> "contentType"
            Oids.oidEquals(oid, Oids.pkcs9MessageDigest) -> "messageDigest"
            Oids.oidEquals(oid, Oids.pkcs9SigningTime) -> "signingTime"
            Oids.oidEquals(oid, Oids.pkcs9SigningCertificateV2) -> "signingCertificateV2"
            Oids.oidEquals(oid, Oids.atomVin) -> "VIN"
            Oids.oidEquals(oid, Oids.atomUid) -> "UID"
            Oids.oidEquals(oid, Oids.atomVer) -> "VER"
            else -> Oids.oidString(oid)
        }
        return name to valueStr
    }
}
