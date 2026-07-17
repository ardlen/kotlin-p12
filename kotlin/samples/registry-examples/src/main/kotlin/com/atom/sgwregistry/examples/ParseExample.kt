package com.atom.sgwregistry.examples

import com.atom.sgwregistry.analyzer.RegistryAnalyzer
import com.atom.sgwregistry.parser.RegistryParser
import java.nio.file.Path

/**
 * Пример: [RegistryParser.parse] — разбор DER .p12 в [com.atom.sgwregistry.model.RegistryContainer].
 *
 * Контейнер возвращается с иммутабельными копиями байтов ([RegistryContainer.immutable]).
 */
object ParseExample {
    fun run(p12Path: Path) {
        SampleSupport.section("RegistryParser.parse")
        val p12 = SampleSupport.readBytes(p12Path)
        val container = RegistryParser.parse(p12)

        println("PFX version: ${container.pfxVersion}")
        println("contentType: ${container.contentType}")
        println("certificates: ${container.certificatesDer.size}")
        println("safeBags: ${container.safeBagInfos.size}")
        println("signerCert present: ${container.signerCertDer != null}")
        println("signerCertResolved (SKID/issuerAndSerial): ${container.signerCertResolved}")
        println("eContent bytes: ${container.eContentBytes?.size ?: 0}")
        println("authAttrs bytes: ${container.authenticatedAttributesSetBytes?.size ?: 0}")
        println("encryptedDigest bytes: ${container.encryptedDigest?.size ?: 0}")

        if (container.parseWarnings.isNotEmpty()) {
            println("parseWarnings:")
            container.parseWarnings.forEach { println("  - $it") }
        }

        val authAttrs = RegistryAnalyzer.parseAuthenticatedAttributes(container.authenticatedAttributesSetBytes)
        if (authAttrs.isNotEmpty()) {
            println("authenticatedAttributes:")
            authAttrs.forEach { (name, value) ->
                if (name == "VER") {
                    com.atom.sgwregistry.builder.VerAttribute.parseText(value)
                    println("  $name: $value  (format yyyy-MM-dd HH:mm:ss:Vn)")
                } else {
                    println("  $name: $value")
                }
            }
        }

        container.safeBagInfos.forEachIndexed { i, bag ->
            println("  safeBag[$i] role=${bag.roleName} subject=${bag.certSummary?.subject ?: "-"}")
        }
    }
}
