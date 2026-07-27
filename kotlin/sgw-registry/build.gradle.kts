plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("com.android.library")
    `maven-publish`
}

kotlin {
    jvm {
        compilations.all {
            compileTaskProvider.configure {
                compilerOptions {
                    jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
                }
            }
        }
        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
            val repoRoot = rootProject.projectDir.parentFile
            workingDir = repoRoot
            systemProperty("sgw.registry.repoRoot", repoRoot.absolutePath)
        }
    }

    androidTarget {
        publishLibraryVariants("release")
        compilations.all {
            compileTaskProvider.configure {
                compilerOptions {
                    jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
                }
            }
        }
    }

    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.6.1")
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }

        val jvmMain by getting
        val jvmTest by getting {
            dependsOn(commonTest)
            dependencies {
                implementation(kotlin("test"))
                implementation(kotlin("test-junit5"))
            }
        }

        val androidMain by getting

        val androidUnitTest by getting {
            dependsOn(commonTest)
            dependencies {
                implementation(kotlin("test"))
                implementation(kotlin("test-junit"))
            }
        }

        val iosMain by creating {
            dependsOn(commonMain)
        }
        val iosArm64Main by getting { dependsOn(iosMain) }
        val iosSimulatorArm64Main by getting { dependsOn(iosMain) }

        val iosSimulatorArm64Test by getting {
            dependsOn(commonTest)
            dependencies {
                implementation(kotlin("test"))
            }
        }
    }
}

// K/N test.kexe — не .app bundle; все ресурсы кладём рядом с исполняемым файлом
val repoTestFixtures = rootProject.projectDir.parentFile
val syncIosTestFixtures = tasks.register<Sync>("syncIosTestFixtures") {
    from(repoTestFixtures) {
        include(
            "demo-original-container.p12",
            "spas-delegate.p12",
            "mob-dev-cloud_config.json",
            "resp-context.json",
            "config.json",
            "infotainment_client.pem",
            "certs/**",
        )
    }
    into(layout.buildDirectory.dir("iosTestFixtures"))
}

val copyIosSimulatorArm64TestResources = tasks.register<Copy>("copyIosSimulatorArm64TestResources") {
    dependsOn("iosSimulatorArm64TestProcessResources", "linkDebugTestIosSimulatorArm64", syncIosTestFixtures)
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    from(layout.buildDirectory.dir("processedResources/iosSimulatorArm64/test"))
    from(syncIosTestFixtures.map { it.destinationDir })
    into(layout.buildDirectory.dir("bin/iosSimulatorArm64/debugTest"))
    include("**/*")
}

tasks.named("iosSimulatorArm64Test") {
    dependsOn(copyIosSimulatorArm64TestResources)
}

android {
    namespace = "com.atom.sgwregistry"
    compileSdk = 35
    defaultConfig {
        minSdk = 24
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    testOptions {
        unitTests.all {
            val repoRoot = rootProject.projectDir.parentFile
            it.workingDir = repoRoot
            it.systemProperty("sgw.registry.repoRoot", repoRoot.absolutePath)
        }
    }
}

val distDir = rootProject.layout.projectDirectory.dir("dist")

tasks.register<Copy>("dist") {
    group = "distribution"
    description = "Copies JVM library JAR and sources JAR to kotlin/dist/"
    dependsOn("jvmJar", "jvmSourcesJar")
    from(
        tasks.named("jvmJar", org.gradle.jvm.tasks.Jar::class).flatMap { it.archiveFile },
        tasks.named("jvmSourcesJar", org.gradle.jvm.tasks.Jar::class).flatMap { it.archiveFile },
    )
    into(distDir)
    doLast {
        logger.lifecycle("Artifacts: ${distDir.asFile.absolutePath}")
    }
}

publishing {
    publications.withType<MavenPublication>().configureEach {
        pom {
            name.set("SgwRegistry")
            description.set("ATOM-PKCS12-REGISTRY (.p12) parse, build, and verify — Kotlin Multiplatform")
            url.set("https://github.com/atom/sgw-registry")
        }
    }
    repositories {
        maven {
            name = "localDist"
            url = distDir.dir("maven").asFile.toURI()
        }
    }
}

tasks.register("publishLibrary") {
    group = "distribution"
    description = "Builds JARs, copies to kotlin/dist/, publishes to kotlin/dist/maven and ~/.m2"
    dependsOn("dist", "publishToMavenLocal")
    dependsOn(tasks.matching { it.name.startsWith("publish") && it.name.endsWith("ToLocalDistRepository") })
}
