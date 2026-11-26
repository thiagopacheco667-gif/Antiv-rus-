plugins {
    id("aegis.android.library")
    id("aegis.android.hilt")
}

android {
    namespace = "com.aegis.security.core.security"
}

dependencies {
    api(projects.domain)
    implementation(projects.core.common)
}
