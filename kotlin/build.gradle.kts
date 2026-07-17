plugins {
    kotlin("multiplatform") version "2.0.21" apply false
    kotlin("plugin.serialization") version "2.0.21" apply false
    id("com.android.library") version "8.5.2" apply false
}

allprojects {
    group = "com.atom"
    version = "2.5.0"
}

subprojects {
    // repositories configured in settings.gradle.kts
}

tasks.register("publishLibrary") {
    group = "distribution"
    description = "Build and publish sgw-registry for use in other projects"
    dependsOn(":sgw-registry:publishLibrary")
}
