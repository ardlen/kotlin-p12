/**
 * Минимальный CLI: анализ .p12 и проверка подписи.
 *
 * Использование: analyze-registry-example <file.p12>
 */
package com.atom.sgwregistry.samples

import com.atom.sgwregistry.analyzer.RegistryAnalyzer
import com.atom.sgwregistry.builder.VerAttribute
import com.atom.sgwregistry.parser.RegistryParser
import java.io.File

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        System.err.println("Usage: analyze-registry-example <file.p12>")
        kotlin.system.exitProcess(1)
    }
    val path = args[0]
    val p12 = File(path).readBytes()
    val c = RegistryParser.parse(p12)
    RegistryAnalyzer.parseAuthenticatedAttributes(c.authenticatedAttributesSetBytes)
        .firstOrNull { it.first == "VER" }?.second
        ?.let { ver ->
            VerAttribute.parseText(ver)
            System.err.println("VER: $ver  (yyyy-MM-dd HH:mm:ss:Vn)")
        }
    if (c.parseWarnings.isNotEmpty()) {
        System.err.println("Parse warnings:")
        c.parseWarnings.forEach { System.err.println("  - $it") }
    }
    println(RegistryAnalyzer.toTextDetailed(c))
    try {
        RegistryAnalyzer.verifyRegistry(p12)
        System.err.println("Signature verification: OK (signerCertResolved=${c.signerCertResolved})")
    } catch (e: Exception) {
        System.err.println("Signature verification: ${e.message}")
        kotlin.system.exitProcess(1)
    }
}
