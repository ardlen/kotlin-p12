/**
 * Проверка CMS-подписи ATOM-PKCS12-REGISTRY.
 */
package com.atom.sgwregistry.verifier

import com.atom.sgwregistry.api.SignatureVerifierService
import com.atom.sgwregistry.asn1.DerUtils
import com.atom.sgwregistry.asn1.Oids
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.model.RegistryContainer
import com.atom.sgwregistry.parser.RegistryParser

object SignatureVerifier : SignatureVerifierService {
    override fun verifyRegistry(p12Der: ByteArray) {
        verifyContainer(RegistryParser.parse(p12Der))
    }

    override fun verifyContainer(c: RegistryContainer) {
        val authAttrs = c.authenticatedAttributesSetBytes
            ?: throw IllegalStateException("AuthenticatedAttributes absent or empty")
        val encDigest = c.encryptedDigest
            ?: throw IllegalStateException("EncryptedDigest absent or empty")
        val signerDer = c.signerCertDer
            ?: throw IllegalStateException("Signer certificate not found in container")

        if (!Oids.oidEquals(c.digestAlgorithmOid, Oids.sha256)) {
            throw IllegalStateException("Unsupported digest algorithm (supported: SHA-256)")
        }
        if (!Oids.oidEquals(c.signatureAlgorithmOid, Oids.ecdsaWithSha256)) {
            throw IllegalStateException("Unsupported signature algorithm (supported: ecdsaWithSHA256)")
        }

        val canonicalSet = DerUtils.canonicalSetDer(authAttrs)
            ?: throw IllegalStateException("Cannot build canonical SET from authenticatedAttributes")
        val digest = PlatformCrypto.sha256(canonicalSet)
        val cert = PlatformCrypto.parseCertificate(signerDer)
        val valid = PlatformCrypto.verifyHashEcdsaDer(cert, digest, encDigest)
        if (!valid) throw IllegalStateException("Signature verification failed")
    }

    override fun tryVerifyRegistry(p12Der: ByteArray): Pair<Boolean, String?> = try {
        verifyRegistry(p12Der)
        true to null
    } catch (e: Exception) {
        false to (e.message ?: e::class.simpleName)
    }
}
