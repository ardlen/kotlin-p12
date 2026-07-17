package com.atom.sgwregistry.analyzer

import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.model.RegistryContainer
import com.atom.sgwregistry.model.SafeBagInfo
import java.io.File
import java.nio.file.Files
import java.nio.file.Path

/** JVM file I/O helpers for [RegistryAnalyzer]. */
object RegistryAnalyzerJvm {
    fun verifyRegistryFile(path: String) {
        RegistryAnalyzer.verifyRegistry(File(path).readBytes())
    }

    fun exportCertificatesToDir(c: RegistryContainer, dir: String): Int {
        val path = Path.of(dir)
        Files.createDirectories(path)
        var n = 0
        c.certificatesDer.forEachIndexed { i, der ->
            Files.writeString(path.resolve("cert-${i + 1}.pem"), PemEncoding.certToPem(der))
            n++
        }
        return n
    }

    fun exportSafeBagCertsToDir(c: RegistryContainer, dir: String): Int {
        val path = Path.of(dir)
        Files.createDirectories(path)
        var n = 0
        val used = HashMap<String, Int>()
        c.safeBagInfos.forEachIndexed { i, bag ->
            bag.certValueDer?.let { der ->
                var baseName = safeBagExportBasename(bag, i)
                val key = baseName.lowercase()
                val cnt = used[key]
                if (cnt != null) {
                    val next = cnt + 1
                    used[key] = next
                    baseName = "$baseName-$next"
                } else {
                    used[key] = 1
                }
                Files.writeString(path.resolve("$baseName.pem"), PemEncoding.certToPem(der))
                n++
            }
        }
        return n
    }

    private fun safeBagExportBasename(info: SafeBagInfo, index: Int): String {
        val role = sanitizeExportBasename(info.roleName)
        val serial = info.certSummary?.serial?.let { sanitizeExportBasename(it) } ?: ""
        return when {
            role.isNotEmpty() && serial.isNotEmpty() -> "${role}_$serial"
            role.isNotEmpty() -> role
            serial.isNotEmpty() -> "cert_$serial"
            else -> "cert-${index + 1}"
        }
    }

    private fun sanitizeExportBasename(s: String): String {
        if (s.isBlank()) return ""
        val cleaned = Regex("[^a-zA-Z0-9._-]+").replace(s.trim(), "_").trim('_')
        return if (cleaned.length > 64) cleaned.substring(0, 64) else cleaned
    }
}
