plugins {
    kotlin("jvm")
    application
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation("com.atom:sgw-registry:2.6.0")
    implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.6.1")
}

application {
    mainClass.set("com.atom.sgwregistry.samples.BuildRegistryMainKt")
}

val repoRoot = rootProject.projectDir.parentFile

tasks.withType<JavaExec>().configureEach {
    workingDir = repoRoot
    systemProperty("sgw.registry.repoRoot", repoRoot.absolutePath)
}

tasks.named<JavaExec>("run") {
    // configured above
}

tasks.register<JavaExec>("runAnalyze") {
    group = "application"
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("com.atom.sgwregistry.samples.AnalyzeRegistryMainKt")
}

tasks.register<JavaExec>("runUpdateAdd") {
    group = "application"
    description = "Add certificate to registry and re-sign"
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("com.atom.sgwregistry.samples.UpdateRegistryMainKt")
    args(
        "add",
        "-input", "demo-original-container.p12",
        "-config", "config.json",
        "-output", "kotlin-out/cli-added.p12",
    )
}

tasks.register<JavaExec>("runResign") {
    group = "application"
    description = "Re-sign registry without changing SafeBags"
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("com.atom.sgwregistry.samples.ResignRegistryMainKt")
    args(
        "-input", "myA-modified.p12",
        "-signer-cert", "certs/signer.pem",
        "-signer-key", "certs/signer-key.pem",
    )
}

tasks.register<JavaExec>("runVerifyHypothesis") {
    group = "application"
    description = "Test signature algorithm hypotheses on a .p12 file"
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("com.atom.sgwregistry.samples.VerifySignatureHypothesisMainKt")
    args("/Users/vitaliiardelyan/Development/kotlin-p12/myA2-modified.p12")
}

tasks.register<JavaExec>("runUpdateRemove") {
    group = "application"
    description = "Remove certificate by SKID and re-sign"
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("com.atom.sgwregistry.samples.UpdateRegistryMainKt")
    args(
        "remove",
        "-input", "kotlin-out/cli-added.p12",
        "-config", "config.json",
        "-output", "kotlin-out/cli-removed.p12",
        "-skid", "019c9eff384f76abaf6163d38b3f384b",
    )
}
