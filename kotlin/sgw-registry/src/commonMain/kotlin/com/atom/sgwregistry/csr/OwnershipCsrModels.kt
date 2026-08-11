package com.atom.sgwregistry.csr

/**
 * Запрос на PKCS#10 CSR для Ownership leaf (без BouncyCastle).
 *
 * В `extensionRequest` по умолчанию:
 * - KeyUsage: digitalSignature
 * - EKU: emailProtection (`1.3.6.1.5.5.7.3.4`) — для CMS cloud_config
 * - SAN: `URI:atombus:/user/{ownerId}`
 */
data class OwnershipCsrRequest(
    val ownerId: String,
    val organization: String = "ATOM",
    val organizationalUnits: List<String> = listOf("Customers", "EnhancedAuth"),
    val includeEmailProtectionEku: Boolean = true,
    val includeClientAuthEku: Boolean = false,
    val includeKeyUsageDigitalSignature: Boolean = true,
)

data class OwnershipCsrResult(
    val csrDer: ByteArray,
    val csrPem: String,
    val publicKeySpki: ByteArray,
    val ownerId: String,
    val sanUri: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is OwnershipCsrResult) return false
        return ownerId == other.ownerId &&
            sanUri == other.sanUri &&
            csrDer.contentEquals(other.csrDer) &&
            csrPem == other.csrPem &&
            publicKeySpki.contentEquals(other.publicKeySpki)
    }

    override fun hashCode(): Int {
        var result = ownerId.hashCode()
        result = 31 * result + sanUri.hashCode()
        result = 31 * result + csrDer.contentHashCode()
        result = 31 * result + csrPem.hashCode()
        result = 31 * result + publicKeySpki.contentHashCode()
        return result
    }
}
