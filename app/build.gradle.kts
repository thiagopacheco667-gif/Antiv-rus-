plugins {
    id("aegis.android.application")
    id("aegis.android.compose")
    id("aegis.android.hilt")
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.aegis.security"

    defaultConfig {
        applicationId = "com.aegis.security"
        versionCode = 1
        versionName = "0.1.0-etapa1"
    }

    buildTypes {
        release {
            // R8 e assinatura de release são configurados e validados na Etapa 10.
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    implementation(projects.core.common)
    implementation(projects.core.database)
    implementation(projects.core.designsystem)
    implementation(projects.core.security)
    implementation(projects.core.ui)
    implementation(projects.domain)
    implementation(projects.data)

    implementation(projects.feature.dashboard)
    implementation(projects.feature.scanner)
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
