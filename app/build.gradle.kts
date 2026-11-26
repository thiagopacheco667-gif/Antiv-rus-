plugins {
    id("aegis.android.application")
    id("aegis.android.compose")
    id("aegis.android.hilt")
    alias(libs.plugins.kotlin.serialization)
}

/** Assinatura de release via variáveis de ambiente (CI). Nada de segredos no repositório. */
val releaseKeystore: String? = System.getenv("AEGIS_KEYSTORE_PATH")

android {
    namespace = "com.aegis.security"

    defaultConfig {
        applicationId = "com.aegis.security"
        versionCode = 2
        versionName = "1.0.0"
    }

    signingConfigs {
        if (releaseKeystore != null && file(releaseKeystore).exists()) {
            create("release") {
                storeFile = file(releaseKeystore)
                storePassword = System.getenv("AEGIS_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("AEGIS_KEY_ALIAS")
                keyPassword = System.getenv("AEGIS_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            // Sem keystore de release (segredos do CI), assina com a chave de depuração para que o APK
            // seja instalável. Para publicar, configure AEGIS_KEYSTORE_* (ver README).
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = true
        disable += setOf("ObsoleteSdkInt", "GradleDependency", "NewerVersionAvailable", "AndroidGradlePluginVersion", "OldTargetApi")
    }
}

dependencies {
    implementation(projects.core.common)
    implementation(projects.core.database)
    implementation(projects.core.designsystem)
    implementation(projects.core.network)
    implementation(projects.core.security)
    implementation(projects.core.ui)
    implementation(projects.domain)
    implementation(projects.data)

    implementation(projects.feature.dashboard)
    implementation(projects.feature.scanner)
    implementation(projects.feature.reports)
    implementation(projects.feature.filedetails)
    implementation(projects.feature.history)
    implementation(projects.feature.settings)

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.core.splashscreen)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.kotlinx.serialization.json)
}
