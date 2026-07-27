/**
 * CES Vehicle cloud configuration (2.1.2) §5 — построение FQDN CloudBroker.
 *
 * fqdnConstrAlg = 1:
 * ```
 * FQDN = hashB(VIN) + "-" + ownerID + "." + baseDomain
 * // пример: c602-bdb79393-a9e3-4024-86a8-5f372df9121f.mqtt.atom.auto
 * ```
 *
 * hashB (§5.2.1): SHA-1(ASCII VIN) → последние 4 hex-символа (lowercase).
 *
 * В signed / TBOX JSON поле `endpoint.baseDomain` хранит **полный FQDN**
 * (как в CES §examples / mob-dev fixtures), а invitation draft часто отдаёт
 * только суффикс (`mqtt.atom.auto`).
 */
package com.atom.sgwregistry.cloudconfig

import com.atom.sgwregistry.crypto.Sha1

object CloudBrokerFqdn {
    const val ALG_HASH_B_VIN_OWNER = 1

    /**
     * hashB(VIN): last 4 hex chars of SHA-1 over ASCII VIN.
     * CES example: VIN `1GNDT13S532183584` → `c602`.
     */
    fun hashB(vin: String): String {
        require(vin.isNotBlank()) { "VIN required for hashB" }
        val digest = Sha1.digest(vin.encodeToByteArray())
        val hex = buildString(digest.size * 2) {
            for (b in digest) {
                val v = b.toInt() and 0xFF
                append("0123456789abcdef"[v ushr 4])
                append("0123456789abcdef"[v and 0x0F])
            }
        }
        return hex.takeLast(4)
    }

    /**
     * Полный FQDN для `endpoint.baseDomain` в signed / TBOX payload.
     *
     * @param domainSuffix суффикс из invitation (`mqtt.atom.auto`)
     * @param identityId   CES: ownerID (UID leaf); в invitation-примере — `tenant_id`
     */
    fun buildFqdn(
        vin: String,
        identityId: String,
        domainSuffix: String,
        fqdnConstrAlg: Int = ALG_HASH_B_VIN_OWNER,
    ): String {
        require(identityId.isNotBlank()) { "identityId (ownerID / tenant_id) required" }
        require(domainSuffix.isNotBlank()) { "domainSuffix required" }
        val suffix = domainSuffix.trim().trimStart('.')
        return when (fqdnConstrAlg) {
            ALG_HASH_B_VIN_OWNER -> "${hashB(vin)}-$identityId.$suffix"
            else -> throw IllegalArgumentException("Unsupported fqdnConstrAlg=$fqdnConstrAlg")
        }
    }

    /**
     * Если [domainOrFqdn] уже содержит [identityId] как сегмент префикса — вернуть как есть,
     * иначе построить FQDN из суффикса.
     */
    fun resolveBaseDomain(
        vin: String,
        identityId: String,
        domainOrFqdn: String,
        fqdnConstrAlg: Int = ALG_HASH_B_VIN_OWNER,
    ): String {
        val d = domainOrFqdn.trim()
        if (looksLikeConstructedFqdn(d, identityId)) return d
        return buildFqdn(vin, identityId, d, fqdnConstrAlg)
    }

    private fun looksLikeConstructedFqdn(value: String, identityId: String): Boolean {
        val host = value.substringBefore(':') // strip optional :port
        val prefix = host.substringBefore('.', missingDelimiterValue = "")
        return prefix.contains('-') &&
            prefix.contains(identityId, ignoreCase = true) &&
            host.count { it == '.' } >= 2
    }
}
