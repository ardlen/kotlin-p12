/**
 * Диагностика: проверка гипотезы SHA256withECDSA vs NONEwithECDSA (одноразовый CLI).
 */
package com.atom.sgwregistry.samples

import com.atom.sgwregistry.asn1.DerUtils
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.parser.RegistryParser
import java.io.File
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

fun main(args: Array<String>) {
    val path = args.getOrNull(0) ?: error("Usage: VerifySignatureHypothesisMain <file.p12>")
    val p12 = File(path).readBytes()
    val c = RegistryParser.parse(p12)

    val authAttrs = c.authenticatedAttributesSetBytes
        ?: error("no authenticatedAttributes")
    val encDigest = c.encryptedDigest ?: error("no encryptedDigest")
    val signerDer = c.signerCertDer ?: error("no signerCertDer")
    val eContent = c.eContentBytes ?: error("no eContent")

    val canonicalSet = DerUtils.canonicalSetDer(authAttrs)
        ?: error("cannot canonicalize auth attrs")
    val digestAuthCanonical = PlatformCrypto.sha256(canonicalSet)
    val digestAuthRaw = PlatformCrypto.sha256(authAttrs)
    val digestEContent = PlatformCrypto.sha256(eContent)

    val x509 = CertificateFactory.getInstance("X.509")
        .generateCertificate(signerDer.inputStream()) as X509Certificate

    println("=== myA2-modified.p12 signature hypothesis test ===")
    println("signerCertResolved: ${c.signerCertResolved}")
    println("SignatureAlgorithm OID: ${c.signatureAlgorithmOid?.joinToString(".")}")
    println("encryptedDigest: ${encDigest.size} bytes")
    println("canonicalSet: ${canonicalSet.size} bytes, authAttrs raw: ${authAttrs.size} bytes")
    println("digest(canonicalSet): ${digestAuthCanonical.toHex()}")
    println("messageDigest attr matches eContent: ${digestEContent.toHex()}")
    println()

    data class Case(val name: String, val jcaAlg: String, val data: ByteArray)

    val cases = listOf(
        Case("library: NONEwithECDSA(SHA256(canonicalSet))", "NONEwithECDSA", digestAuthCanonical),
        Case("SHA256withECDSA(canonicalSet bytes)", "SHA256withECDSA", canonicalSet),
        Case("SHA256withECDSA(raw authAttrs SET)", "SHA256withECDSA", authAttrs),
        Case("SHA256withECDSA(SHA256(canonicalSet)) double-hash?", "SHA256withECDSA", digestAuthCanonical),
        Case("NONEwithECDSA(SHA256(raw authAttrs))", "NONEwithECDSA", digestAuthRaw),
        Case("SHA256withECDSA(eContent)", "SHA256withECDSA", eContent),
        Case("NONEwithECDSA(SHA256(eContent))", "NONEwithECDSA", digestEContent),
    )

    for (tc in cases) {
        val ok = tryVerify(x509, tc.jcaAlg, tc.data, encDigest)
        println("${if (ok) "OK " else "FAIL"}  ${tc.name}")
    }
}

private fun tryVerify(cert: X509Certificate, algorithm: String, data: ByteArray, signature: ByteArray): Boolean =
    try {
        val sig = Signature.getInstance(algorithm)
        sig.initVerify(cert.publicKey)
        sig.update(data)
        sig.verify(signature)
    } catch (e: Exception) {
        println("      (error: ${e.message})")
        false
    }

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
