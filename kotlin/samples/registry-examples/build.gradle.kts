/**
 * JVM-примеры публичного API sgw-registry.
 *
 *  Зависимость — **project(":sgw-registry")** (локальная разработка без publish).
 *  Для проверки Maven-артефакта см. README / API.md.
 *
 * Запуск (из каталога kotlin/):
 * ```bash
 * # Кастомные пути и SKID:
 * ./gradlew :samples:registry-examples:run --args="remove-cert in.p12 config.json out.p12 019c9eff..."
 * ./gradlew :samples:registry-examples:runRemove-cert --args="kotlin-out/in.p12 config.json kotlin-out/out.p12 019c9eff..."
 *
 * # Сокращённые задачи без --args — только пути по умолчанию из RegistryExamplesMain.kt:
 * ./gradlew :samples:registry-examples:runParse
 * ./gradlew :samples:registry-examples:runRemove-cert
 * ./gradlew :samples:registry-examples:runCloud-config
 * ./gradlew :samples:registry-examples:runCloud-config-trust
 * ./gradlew :samples:registry-examples:runCloud-config-from-context
 * ./gradlew :samples:registry-examples:runAll
 * ```
 *
 * workingDir = корень монорепозитория (родитель kotlin/), чтобы относительные пути
 * demo-original-container.p12, config.json, kotlin-out/… резолвились как в README.
 */
plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    application
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation(project(":sgw-registry"))
    implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.6.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
}

application {
    mainClass.set("com.atom.sgwregistry.examples.RegistryExamplesMainKt")
}

// kotlin/ → родитель = корень репозитория (demo-original-container.p12, config.json, kotlin-out/)
val repoRoot = rootProject.projectDir.parentFile

tasks.withType<JavaExec>().configureEach {
    // Относительные пути в CLI разрешаются от корня репо, не от kotlin/
    workingDir = repoRoot
    // SampleSupport.repoRoot читает это свойство при старте JVM
    systemProperty("sgw.registry.repoRoot", repoRoot.absolutePath)
}

tasks.named<JavaExec>("run") {
    // classpath, workingDir, mainClass — из application + configureEach выше
    // Пример: ./gradlew :samples:registry-examples:run --args="parse demo-original-container.p12"
}

// Удобные алиасы: runParse, runVerify, runAnalyze, runBuild, runConfig,
// runAdd-cert, runRemove-cert, runUpdate-registry, runCloud-config, runAll
listOf(
    "parse", "build", "verify", "analyze", "config",
    "add-cert", "remove-cert", "update-registry",
    "cloud-config", "cloud-config-trust", "cloud-config-from-context",
    "empty-owner", "empty-owner-unsigned", "all",
).forEach { cmd ->
    tasks.register<JavaExec>("run${cmd.replaceFirstChar { it.uppercase() }}") {
        group = "application"
        description = "Run registry-examples $cmd (optional --args for paths; command name added automatically)"
        classpath = sourceSets.main.get().runtimeClasspath
        mainClass.set("com.atom.sgwregistry.examples.RegistryExamplesMainKt")
        args(cmd)
        // Gradle --args replaces task args; prepend command if user passed only paths/SKID
        doFirst {
            val current = args.orEmpty().map { it.toString() }
            if (current.isEmpty()) {
                args = listOf(cmd)
            } else if (current[0].lowercase() != cmd) {
                args = listOf(cmd) + current
            }
        }
    }
}
