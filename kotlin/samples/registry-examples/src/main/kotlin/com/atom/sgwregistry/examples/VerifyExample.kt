package com.atom.sgwregistry.examples

import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.verifier.SignatureVerifier
import java.nio.file.Path

/**
 * Пример: [SignatureVerifier] — проверка ECDSA-подписи над authenticatedAttributes.
 */
object VerifyExample {
    fun run(p12Path: Path) {
        SampleSupport.section("SignatureVerifier")
        val p12 = SampleSupport.readBytes(p12Path)
        val container = RegistryParser.parse(p12)

        SampleSupport.printVer("VER before verify", container)

        println("signerCertResolved: ${container.signerCertResolved}")
        if (!container.signerCertResolved) {
            println("  (подписант не сопоставлен с сертификатом — verify, скорее всего, не пройдёт)")
        }

        println("verifyContainer(container):")
        try {
            SignatureVerifier.verifyContainer(container)
            println("  OK")
        } catch (e: Exception) {
            println("  FAIL: ${e.message}")
        }

        println("verifyRegistry(p12Der):")
        try {
            SignatureVerifier.verifyRegistry(p12)
            println("  OK")
        } catch (e: Exception) {
            println("  FAIL: ${e.message}")
        }

        val (ok, err) = SignatureVerifier.tryVerifyRegistry(p12)
        println("tryVerifyRegistry: ok=$ok${err?.let { ", error=$it" } ?: ""}")
    }
}
