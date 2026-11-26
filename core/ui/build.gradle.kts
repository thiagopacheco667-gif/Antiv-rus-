plugins {
    id("aegis.android.library")
    id("aegis.android.compose")
}

android {
    namespace = "com.aegis.security.core.ui"
}

dependencies {
    api(projects.domain)
    api(projects.core.designsystem)
}
