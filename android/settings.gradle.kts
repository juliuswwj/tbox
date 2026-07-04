pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // The gomobile-built tbox.aar is picked up from app/libs via a flatDir
        // fallback declared in app/build.gradle.kts.
    }
}

rootProject.name = "tbox"
include(":app")
