plugins {
    id("aegis.jvm.library")
    alias(libs.plugins.kotlin.serialization)
}

dependencies {
    api(libs.kotlinx.coroutines.core)
    api(libs.kotlinx.serialization.core)
    implementation(libs.javax.inject)
}
