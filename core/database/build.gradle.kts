plugins {
    id("aegis.android.library")
    id("aegis.android.hilt")
    id("aegis.android.room")
}

android {
    namespace = "com.aegis.security.core.database"
}

dependencies {
    implementation(libs.kotlinx.coroutines.android)

    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.kotlinx.coroutines.test)
}
