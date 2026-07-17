/**
 * CLI: переподпись существующего .p12 без изменения SafeBags (VER bump +1).
 *
 * Usage:
 *   resign-registry-example -input file.p12 -signer-cert certs/signer.pem -signer-key certs/signer-key.pem [-output file.p12]
 */
package com.atom.sgwregistry.samples

import com.atom.sgwregistry.analyzer.RegistryAnalyzer
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.builder.RegistryConverters
import com.atom.sgwregistry.builder.VerAttribute
import com.atom.sgwregistry.crypto.PemUtils
import com.atom.sgwregistry.model.resignWithSafeBags
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.verifier.SignatureVerifier
import java.io.File

fun main(args: Array<String>) {
    var input = ""
    var output: String? = null
    var signerCertPath = "certs/signer.pem"
    var signerKeyPath = "certs/signer-key.pem"

    var i = 0
    while (i < args.size) {
        when (val a = args[i]) {
            "-h", "--help" -> {
                printResignUsage()
                return
            }
            "-input", "--input" -> input = args[++i]
            "-output", "--output" -> output = args[++i]
            "-signer-cert" -> signerCertPath = args[++i]
            "-signer-key" -> signerKeyPath = args[++i]
            else -> if (!a.startsWith("-") && input.isEmpty()) input = a
        }
        i++
    }

    require(input.isNotEmpty()) { "-input <file.p12> required" }
    require(File(input).exists()) { "Input not found: $input" }
    require(File(signerCertPath).exists()) { "Signer cert not found: $signerCertPath" }
    require(File(signerKeyPath).exists()) { "Signer key not found: $signerKeyPath" }

    val outPath = output ?: input
    val p12 = File(input).readBytes()
    val container = RegistryParser.parse(p12)
    val beforeVer = RegistryAnalyzer.parseAuthenticatedAttributes(container.authenticatedAttributesSetBytes)
        .firstOrNull { it.first == "VER" }?.second
    System.err.println("VER before resign: $beforeVer")

    val attrs = VerAttribute.bumpForRegistryUpdate(RegistryConverters.extractSignerAttrs(container))
    val safeBags = RegistryConverters.safeBagInfosToInputs(container.safeBagInfos)
    val signerCert = PemUtils.loadCertificateFromFile(signerCertPath)
    val signerKey = PemUtils.loadPrivateKey(signerKeyPath)

    val resigned = RegistryBuilder.resignWithSafeBags(
        safeBags = safeBags,
        signerCert = signerCert,
        signerKey = signerKey,
        attrs = attrs,
    )

    File(outPath).writeBytes(resigned)
    val afterVer = RegistryAnalyzer.parseAuthenticatedAttributes(RegistryParser.parse(resigned).authenticatedAttributesSetBytes)
        .firstOrNull { it.first == "VER" }?.second
    System.err.println("VER after resign: $afterVer")
    System.err.println("Written: $outPath")

    SignatureVerifier.verifyRegistry(resigned)
    System.err.println("Signature verification: OK")
}

private fun printResignUsage() {
    println(
        """
        |Usage:
        |  resign-registry-example -input <in.p12> [-output <out.p12>] [-signer-cert certs/signer.pem] [-signer-key certs/signer-key.pem]
        """.trimMargin(),
    )
}
