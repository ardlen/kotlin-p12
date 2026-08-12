pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
 // Только kotlin/dist/maven — примеры и потребители тестируют опубликованный dist,
 // multiplatform публикация Maven в dist/maven/com.atom:sgw-registry:2.6.0.
        maven { url = uri("${rootDir}/dist/maven") }
        google()
        mavenCentral()
    }
}

rootProject.name = "sgw-registry-kotlin"

include("sgw-registry")
include("samples:build-registry-example")
include("samples:registry-examples")

// Android SDK: IDE and Gradle need kotlin/local.properties (see local.properties.example)
val localPropertiesFile = File(rootDir, "local.properties")
if (!localPropertiesFile.exists()) {
    val sdkDir = sequenceOf(
        System.getenv("ANDROID_HOME"),
        System.getenv("ANDROID_SDK_ROOT"),
        "${System.getProperty("user.home")}/Library/Android/sdk",
        "${System.getProperty("user.home")}/Android/Sdk",
    ).firstOrNull { path -> path != null && File(path).isDirectory }
    if (sdkDir != null) {
        localPropertiesFile.writeText("sdk.dir=$sdkDir\n")
    }
}
