/**
 * CLI: добавление / удаление сертификата в существующем .p12 с переподписью.
 *
 * VER обязателен: при каждом изменении версия увеличивается на 1 (V102→V103),
 * timestamp обновляется до текущего UTC (`yyyy-MM-dd HH:mm:ss`).
 *
 * Использование:
 *   update-registry-example add  -input registry.p12 -config config.json -output out.p12 [-bag-index N]
 *   update-registry-example remove -input registry.p12 -config config.json -output out.p12 -skid HEX
 */
package com.atom.sgwregistry.samples

import com.atom.sgwregistry.analyzer.RegistryAnalyzer
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.builder.VerAttribute
import com.atom.sgwregistry.config.ConfigLoader
import com.atom.sgwregistry.crypto.PemUtils
import com.atom.sgwregistry.model.AddCertificateRequest
import com.atom.sgwregistry.model.RemoveCertificateBySkidRequest
import com.atom.sgwregistry.parser.RegistryParser
import com.atom.sgwregistry.verifier.SignatureVerifier
import java.io.File

fun main(args: Array<String>) {
    if (args.isEmpty() || args[0] in setOf("-h", "--help")) {
        printUpdateUsage()
        return
    }

    when (args[0].lowercase()) {
        "add" -> runAdd(args.drop(1).toTypedArray())
        "remove" -> runRemove(args.drop(1).toTypedArray())
        else -> {
            System.err.println("Unknown command: ${args[0]}")
            printUpdateUsage()
            kotlin.system.exitProcess(1)
        }
    }
}

private fun runAdd(args: Array<String>) {
    val opts = parseOpts(args, defaultOutput = "registry-added.p12")
    val p12 = File(opts.input).readBytes()
    val before = RegistryParser.parse(p12)
    val buildCfg = loadBuildConfig(opts.config)

    val newBag = selectBagToAdd(before, buildCfg, opts.bagIndex)
    System.err.println("Adding role=${newBag.roleName}, cert ${newBag.certDer.size} bytes")
    printVerLine("VER before add", before)

    val updated = RegistryBuilder.addCertificateAndResign(
        before,
        AddCertificateRequest(
            existingP12 = p12,
            newBag = newBag,
            signerCertDer = buildCfg.signerCertDer,
            signerKey = buildCfg.signerKey,
        ),
    )
    File(opts.output).writeBytes(updated)
    val after = RegistryParser.parse(updated)
    printVer(before, after)
    System.err.println("safeBags: ${before.safeBagInfos.size} → ${after.safeBagInfos.size}")
    System.err.println("Created: ${opts.output}")
    verifyOrExit(updated)
}

private fun runRemove(args: Array<String>) {
    val opts = parseOpts(args, defaultOutput = "registry-removed.p12")
    require(!opts.skidHex.isNullOrBlank()) { "-skid HEX required for remove" }

    val p12 = File(opts.input).readBytes()
    val before = RegistryParser.parse(p12)
    val buildCfg = loadBuildConfig(opts.config)
    val skidHex = opts.skidHex

    System.err.println("Removing SKID: $skidHex")
    printVerLine("VER before remove", before)

    val updated = RegistryBuilder.removeCertificateBySkidAndResign(
        before,
        RemoveCertificateBySkidRequest(
            existingP12 = p12,
            subjectKeyId = PemUtils.decodeSkidHex(skidHex),
            signerCertDer = buildCfg.signerCertDer,
            signerKey = buildCfg.signerKey,
        ),
    )
    File(opts.output).writeBytes(updated)
    val after = RegistryParser.parse(updated)
    printVer(before, after)
    System.err.println("safeBags: ${before.safeBagInfos.size} → ${after.safeBagInfos.size}")
    System.err.println("Created: ${opts.output}")
    verifyOrExit(updated)
}

private data class UpdateOpts(
    val input: String,
    val config: String,
    val output: String,
    val bagIndex: Int = -1,
    val skidHex: String? = null,
)

private fun parseOpts(args: Array<String>, defaultOutput: String): UpdateOpts {
    var input = ""
    var config = "config.json"
    var output = defaultOutput
    var bagIndex = -1
    var skidHex: String? = null

    var i = 0
    while (i < args.size) {
        when (val a = args[i]) {
            "-input", "--input" -> input = args[++i]
            "-config", "--config" -> config = args[++i]
            "-output", "--output" -> output = args[++i]
            "-bag-index" -> bagIndex = args[++i].toInt()
            "-skid" -> skidHex = args[++i]
            else -> if (!a.startsWith("-") && input.isEmpty()) input = a
        }
        i++
    }
    require(input.isNotEmpty()) { "-input <file.p12> required" }
    require(File(config).exists()) { "Config not found: $config" }
    require(File(input).exists()) { "Input not found: $input" }
    return UpdateOpts(input, config, output, bagIndex, skidHex)
}

private fun loadBuildConfig(configPath: String) =
    ConfigLoader.toBuildConfig(
        ConfigLoader.readConfig(configPath),
        File(configPath).parentFile?.canonicalPath ?: ".",
    )

private fun selectBagToAdd(
    before: com.atom.sgwregistry.model.RegistryContainer,
    buildCfg: com.atom.sgwregistry.model.BuildConfig,
    bagIndex: Int,
): com.atom.sgwregistry.model.SafeBagInput {
    val existing = before.safeBagInfos.mapNotNull { it.certValueDer }
    if (bagIndex >= 0) {
        require(bagIndex < buildCfg.safeBags.size) { "bag-index out of range" }
        return buildCfg.safeBags[bagIndex]
    }
    return buildCfg.safeBags.firstOrNull { bag ->
        existing.none { it.contentEquals(bag.certDer) }
    } ?: throw IllegalStateException("No cert in config missing from registry; specify -bag-index")
}

private fun printVerLine(label: String, container: com.atom.sgwregistry.model.RegistryContainer) {
    RegistryAnalyzer.parseAuthenticatedAttributes(container.authenticatedAttributesSetBytes)
        .firstOrNull { it.first == "VER" }?.second
        ?.let { ver ->
            VerAttribute.parseText(ver)
            System.err.println("$label: $ver")
        }
}

private fun printVer(
    before: com.atom.sgwregistry.model.RegistryContainer,
    after: com.atom.sgwregistry.model.RegistryContainer,
) {
    fun verLine(c: com.atom.sgwregistry.model.RegistryContainer) =
        RegistryAnalyzer.parseAuthenticatedAttributes(c.authenticatedAttributesSetBytes)
            .firstOrNull { it.first == "VER" }?.second
    val beforeVer = verLine(before)
    val afterVer = verLine(after)
    if (beforeVer != null && afterVer != null) {
        val (_, v0) = VerAttribute.parseText(beforeVer)
        val (_, v1) = VerAttribute.parseText(afterVer)
        System.err.println("VER: $beforeVer → $afterVer (V$v0 → V$v1)")
    }
}

private fun verifyOrExit(p12: ByteArray) {
    try {
        SignatureVerifier.verifyRegistry(p12)
        System.err.println("Signature verification: OK")
    } catch (e: Exception) {
        System.err.println("Signature verification: ${e.message}")
        kotlin.system.exitProcess(1)
    }
}

private fun printUpdateUsage() {
    println(
        """
        |Usage:
        |  update-registry-example add -input <in.p12> -config <config.json> -output <out.p12> [-bag-index N]
        |  update-registry-example remove -input <in.p12> -config <config.json> -output <out.p12> -skid <hex>
        |
        |VER is mandatory: each change bumps version (Vn→V{n+1}) and sets UTC timestamp.
        |
        |Examples:
        |  update-registry-example add -input demo-original-container.p12 -config config.json -output kotlin-out/added.p12
        |  update-registry-example remove -input kotlin-out/added.p12 -config config.json -output kotlin-out/removed.p12 -skid 019c9eff384f76abaf6163d38b3f384b
        """.trimMargin(),
    )
}
