package com.atom.sgwregistry.examples

import com.atom.sgwregistry.analyzer.RegistryAnalyzer
import com.atom.sgwregistry.analyzer.RegistryAnalyzerJvm
import com.atom.sgwregistry.builder.VerAttribute
import com.atom.sgwregistry.parser.RegistryParser
import java.nio.file.Files
import java.nio.file.Path

/**
 * Пример: [RegistryAnalyzer] — отчёты (в т.ч. ATOM authAttrs), PEM/JSON, экспорт, verify.
 */
object AnalyzeExample {
    fun run(p12Path: Path, exportDir: Path) {
        SampleSupport.section("RegistryAnalyzer")
        val p12 = SampleSupport.readBytes(p12Path)
        val container = RegistryParser.parse(p12)

        SampleSupport.printVer("VER", container)
        SampleSupport.verText(container)?.let { VerAttribute.parseText(it) }

        println("toText():")
        println(RegistryAnalyzer.toText(container))

        println("toTextDetailed() (VIN, messageDigest check, signature check):")
        println(RegistryAnalyzer.toTextDetailed(container))

        val json = RegistryAnalyzer.toJson(container)
        println("toJson: ${json.size} bytes")
        println(String(json, Charsets.UTF_8))

        val attrs = RegistryAnalyzer.parseAuthenticatedAttributes(container.authenticatedAttributesSetBytes)
        println("parseAuthenticatedAttributes: ${attrs.size} attr(s)")
        attrs.forEach { (n, v) ->
            val display = if (n == "VER") {
                VerAttribute.parseText(v)
                v
            } else {
                v.take(64) + if (v.length > 64) "…" else ""
            }
            println("  $n = $display")
        }

        val certsPem = RegistryAnalyzer.toPem(container)
        val bagsPem = RegistryAnalyzer.toSafeBagsPem(container)
        val signerPem = RegistryAnalyzer.signerCertPem(container)
        println("toPem (all certs): ${certsPem.size} bytes")
        println("toSafeBagsPem: ${bagsPem.size} bytes")
        println("signerCertPem: ${signerPem.size} bytes")

        if (Files.exists(exportDir)) {
            Files.walk(exportDir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
        val nCerts = RegistryAnalyzerJvm.exportCertificatesToDir(container, exportDir.resolve("certs").toString())
        val nBags = RegistryAnalyzerJvm.exportSafeBagCertsToDir(container, exportDir.resolve("safebags").toString())
        println("exportCertsToDir: $nCerts file(s) → ${exportDir.resolve("certs")}")
        println("exportSafeBagsToDir: $nBags file(s) → ${exportDir.resolve("safebags")}")

        println("verifyRegistryFile:")
        try {
            RegistryAnalyzerJvm.verifyRegistryFile(p12Path.toString())
            println("  OK")
        } catch (e: Exception) {
            println("  FAIL: ${e.message}")
        }
    }
}
