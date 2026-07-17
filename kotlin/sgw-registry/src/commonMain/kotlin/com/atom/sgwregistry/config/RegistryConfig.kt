package com.atom.sgwregistry.config

import kotlinx.serialization.Serializable

/** Схема config.json (совместима с форматом SgwRegistry). */
@Serializable
data class RegistryConfig(
    val signerCert: String = "",
    val signerKey: String = "",
    val signerCertPem: String? = null,
    val signerKeyPem: String? = null,
    val vin: String = "",
    val verTimestamp: String = "",
    val verVersion: Int = 0,
    val uid: String = "",
    val safeBags: List<SafeBagConfigEntry> = emptyList(),
)

/** Один SafeBag в config.json. */
@Serializable
data class SafeBagConfigEntry(
    val cert: String = "",
    val certPem: String? = null,
    val roleName: String = "",
    val roleNotBefore: String = "",
    val roleNotAfter: String = "",
    val localKeyID: String? = null,
)
