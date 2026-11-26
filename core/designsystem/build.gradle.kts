plugins {
    id("aegis.android.library")
    id("aegis.android.compose")
}

android {
    namespace = "com.aegis.security.core.designsystem"
}

dependencies {
    api(libs.androidx.compose.foundation)
    api(libs.androidx.compose.material3)
    api(libs.androidx.compose.material.icons.extended)
    api(libs.androidx.compose.ui)
}
