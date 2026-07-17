package com.atom.sgwregistry

import java.nio.file.Files
import java.nio.file.Path

actual object TestFixtures {
    private fun repoRoot(): Path {
        System.getProperty("sgw.registry.repoRoot")?.let { return Path.of(it) }
        var p = Path.of(System.getProperty("user.dir"))
        repeat(6) {
            if (Files.exists(p.resolve("demo-original-container.p12"))) return p
            p = p.parent ?: return p
        }
        return Path.of(System.getProperty("user.dir"))
    }

    actual fun rootDir(): String = repoRoot().toString()

    actual fun exists(relativePath: String): Boolean =
        Files.exists(repoRoot().resolve(relativePath))

    actual fun readBytes(relativePath: String): ByteArray {
        val candidates = listOf(
            repoRoot().resolve(relativePath),
            repoRoot().parent.resolve(relativePath),
            repoRoot().resolve("..").resolve(relativePath).normalize(),
        )
        for (p in candidates) {
            if (Files.exists(p)) return Files.readAllBytes(p)
        }
        error("Test file not found: $relativePath (root=${repoRoot()})")
    }
}
