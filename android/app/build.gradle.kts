import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.juliuswwj.tbox.android"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.juliuswwj.tbox.android"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }

    signingConfigs {
        create("release") {
            // Keystore path (non-secret; overridable via -P or env).
            val ksPath = (project.findProperty("TBOX_KEYSTORE") as String?)
                ?: System.getenv("TBOX_KEYSTORE")
                ?: "/opt/tools/licenses/tbox-release.jks"
            // Credentials (never committed): gradle property -> env var -> a
            // .properties file sitting next to the keystore.
            val credFile = file(ksPath.removeSuffix(".jks") + ".properties")
            val creds = Properties().apply {
                if (credFile.exists()) credFile.inputStream().use { load(it) }
            }
            fun cred(key: String): String? =
                (project.findProperty(key) as String?) ?: System.getenv(key) ?: creds.getProperty(key)

            storeFile = file(ksPath)
            storePassword = cred("TBOX_STORE_PASSWORD")
            keyAlias = cred("TBOX_KEY_ALIAS") ?: "tbox"
            keyPassword = cred("TBOX_KEY_PASSWORD")
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        viewBinding = true
    }
}

dependencies {
    // The gomobile artifact (produced by `make android` into app/libs). Using a
    // file dependency avoids declaring a project-level repository, which the
    // settings.gradle.kts dependency-resolution mode forbids.
    implementation(files("libs/tbox.aar"))

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
}
