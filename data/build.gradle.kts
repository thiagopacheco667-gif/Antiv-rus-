plugins {
    id("aegis.android.library")
    id("aegis.android.hilt")
}

android {
    namespace = "com.aegis.security.data"
}

dependencies {
    api(projects.domain)
    implementation(projects.core.common)
    implementation(projects.core.database)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.kotlinx.coroutines.android)
}
