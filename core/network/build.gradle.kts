plugins {
    id("aegis.android.library")
    id("aegis.android.hilt")
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.aegis.security.core.network"
}

dependencies {
    api(libs.okhttp)
    api(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.android)
}
