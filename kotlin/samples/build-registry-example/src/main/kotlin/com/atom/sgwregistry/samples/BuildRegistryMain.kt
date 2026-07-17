/**
 * Минимальный CLI: сборка .p12 из config.json.
 *
 * Использование:
 *   build-registry-example [-config config.json] [-output file.p12] [-quiet]
 */
package com.atom.sgwregistry.samples

import com.atom.sgwregistry.analyzer.RegistryAnalyzer
import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.builder.VerAttribute
import com.atom.sgwregistry.config.ConfigLoader
import com.atom.sgwregistry.parser.RegistryParser
import java.io.File

fun main(args: Array<String>) {
    var configPath = "config.json"
    var outputPath = "owner.p12"
    var quiet = false
    var showHelp = false

    var i = 0
    while (i < args.size) {
        when (val a = args[i]) {
            "-h", "--help" -> showHelp = true
            "-quiet" -> quiet = true
            "-config", "--config" -> { configPath = args[++i] }
            "-output", "--output" -> { outputPath = args[++i] }
            else -> if (!a.startsWith("-")) configPath = a
        }
        i++
    }

    if (showHelp) {
        println("Usage: build-registry-example [-config config.json] [-output file.p12] [-quiet]")
        return
    }

    val configFile = File(configPath)
    if (!configFile.exists()) {
        System.err.println("Config not found: $configPath")
        kotlin.system.exitProcess(1)
    }

    val configDir = configFile.parentFile?.canonicalPath ?: "."
    val fileConfig = ConfigLoader.readConfig(configPath)
    val buildConfig = ConfigLoader.toBuildConfig(fileConfig, configDir)
    val p12 = RegistryBuilder.buildRegistry(buildConfig)
    File(outputPath).writeBytes(p12)
    System.err.println("Created: $outputPath")

    val container = RegistryParser.parse(p12)
    RegistryAnalyzer.parseAuthenticatedAttributes(container.authenticatedAttributesSetBytes)
        .firstOrNull { it.first == "VER" }?.second
        ?.let { ver ->
            VerAttribute.parseText(ver)
            System.err.println("VER: $ver")
        }

    if (!quiet) {
        val c = container
        if (c.parseWarnings.isNotEmpty()) {
            System.err.println("Parse warnings:")
            c.parseWarnings.forEach { System.err.println("  - $it") }
        }
        println(RegistryAnalyzer.toTextDetailed(c))
        try {
            RegistryAnalyzer.verifyRegistry(p12)
            System.err.println("Signature verification: OK")
        } catch (e: Exception) {
            System.err.println("Signature verification: ${e.message}")
            kotlin.system.exitProcess(1)
        }
    }
}
