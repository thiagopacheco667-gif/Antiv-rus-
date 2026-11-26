plugins {
    id("aegis.android.library")
    id("aegis.android.hilt")
}

android {
    namespace = "com.aegis.security.core.common"
}

dependencies {
    api(libs.kotlinx.coroutines.android)
}
