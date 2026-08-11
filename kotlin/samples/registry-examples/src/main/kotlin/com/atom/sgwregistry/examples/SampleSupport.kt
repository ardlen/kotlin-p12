/**
 * Общие утилиты для примеров: поиск корня репозитория, пути по умолчанию, вывод секций.
 */
package com.atom.sgwregistry.examples

import com.atom.sgwregistry.analyzer.RegistryAnalyzer
import com.atom.sgwregistry.builder.VerAttribute
import com.atom.sgwregistry.model.RegistryContainer
import java.nio.file.Files
import java.nio.file.Path

object SampleSupport {
    /** Корень монорепозитория (родитель каталога kotlin/). */
    val repoRoot: Path by lazy { findRepoRoot() }

    fun defaultP12(): Path = locateFile("demo-original-container.p12")

    fun defaultConfig(): Path = locateFile("config.json")

    fun readBytes(path: Path): ByteArray = Files.readAllBytes(path)

    fun requireExists(path: Path, label: String): Path {
        check(Files.isRegularFile(path)) { "$label not found: $path (repoRoot=$repoRoot, user.dir=${System.getProperty("user.dir")})" }
        return path
    }

    /** Относительный путь разрешается от [repoRoot]; абсолютный — без изменений. */
    fun resolveInputPath(path: String): Path {
        val p = Path.of(path)
        return if (p.isAbsolute) p.normalize() else repoRoot.resolve(p).normalize()
    }

    fun section(title: String) {
        println()
        println("=== $title ===")
    }

    /** ANSI: зелёный для `true`/`OK`, красный для `false`. Отключается при `NO_COLOR` / не-TTY. */
    fun colorBool(value: Boolean): String {
        val text = value.toString()
        if (!useAnsiColor()) return text
        val code = if (value) Ansi.GREEN else Ansi.RED
        return "${code}$text${Ansi.RESET}"
    }

    fun colorOkLabel(): String =
        if (useAnsiColor()) "${Ansi.GREEN}OK${Ansi.RESET}" else "OK"

    fun colorFailLabel(): String =
        if (useAnsiColor()) "${Ansi.RED}FAIL${Ansi.RESET}" else "FAIL"

    private fun useAnsiColor(): Boolean {
        if (System.getenv("NO_COLOR") != null) return false
        if (System.getenv("TERM") == "dumb") return false
        // Gradle JavaExec часто не помечает stdout как TTY — всё равно красим в local CLI.
        return System.console() != null || System.getenv("FORCE_COLOR") != null ||
            System.getProperty("sgw.registry.ansi") == "true" ||
            System.getenv("TERM")?.isNotBlank() == true
    }

    private object Ansi {
        const val RESET = "\u001B[0m"
        const val GREEN = "\u001B[32m"
        const val RED = "\u001B[31m"
    }

    fun verText(container: RegistryContainer): String? =
        RegistryAnalyzer.parseAuthenticatedAttributes(container.authenticatedAttributesSetBytes)
            .firstOrNull { it.first == "VER" }?.second

    fun printVer(label: String, container: RegistryContainer) {
        val ver = verText(container)
        if (ver == null) {
            println("$label: (отсутствует)")
            return
        }
        VerAttribute.parseText(ver)
        println("$label: $ver")
    }

    fun printVerBump(before: RegistryContainer, after: RegistryContainer) {
        val beforeVer = verText(before)
        val afterVer = verText(after)
        if (beforeVer == null || afterVer == null) {
            println("VER: (missing in before=$beforeVer or after=$afterVer)")
            return
        }
        val (_, v0) = VerAttribute.parseText(beforeVer)
        val (_, v1) = VerAttribute.parseText(afterVer)
        println("VER: $beforeVer → $afterVer")
        println("VER version: V$v0 → V$v1 (auto +1 on registry change)")
    }

    private fun locateFile(name: String): Path {
        for (base in searchBases()) {
            val candidate = base.resolve(name)
            if (Files.isRegularFile(candidate)) return candidate
        }
        return repoRoot.resolve(name)
    }

    private fun searchBases(): List<Path> = listOf(repoRoot, repoRoot.resolve("kotlin"))

    private fun findRepoRoot(): Path {
        System.getProperty("sgw.registry.repoRoot")?.let { prop ->
            val root = Path.of(prop)
            if (Files.isDirectory(root)) return root
        }

        var p = Path.of(System.getProperty("user.dir"))
        for (i in 0 until 8) {
            if (isRepoRoot(p)) return p
            p = p.parent ?: return Path.of(System.getProperty("user.dir"))
        }
        return Path.of(System.getProperty("user.dir"))
    }

    private fun isRepoRoot(dir: Path): Boolean {
        if (!Files.isDirectory(dir)) return false
        if (Files.isRegularFile(dir.resolve("kotlin/gradlew"))) return true
        if (Files.isRegularFile(dir.resolve("demo-original-container.p12"))) return true
        if (Files.isRegularFile(dir.resolve("kotlin/demo-original-container.p12"))) return true
        if (Files.isRegularFile(dir.resolve("config.json")) && Files.isDirectory(dir.resolve("kotlin"))) return true
        return false
    }
}
