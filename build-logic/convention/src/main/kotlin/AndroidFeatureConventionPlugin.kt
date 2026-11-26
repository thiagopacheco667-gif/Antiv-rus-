import com.aegis.security.buildlogic.libs
import com.aegis.security.buildlogic.library
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.dependencies

/**
 * Módulo de feature: UI em Compose, ViewModel com Hilt e rota de navegação tipada.
 * Features dependem apenas de :domain e da camada de UI; nunca umas das outras.
 */
class AndroidFeatureConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply("aegis.android.library")
            pluginManager.apply("aegis.android.compose")
            pluginManager.apply("aegis.android.hilt")
            pluginManager.apply("org.jetbrains.kotlin.plugin.serialization")

            dependencies {
                add("implementation", project(":domain"))
                add("implementation", project(":core:designsystem"))
                add("implementation", project(":core:ui"))

                add("implementation", libs.library("androidx.compose.material3"))
                add("implementation", libs.library("androidx.compose.material.icons.extended"))
                add("implementation", libs.library("androidx.lifecycle.runtime.compose"))
                add("implementation", libs.library("androidx.lifecycle.viewmodel.compose"))
                add("implementation", libs.library("androidx.navigation.compose"))
                add("implementation", libs.library("androidx.hilt.navigation.compose"))
                add("implementation", libs.library("kotlinx.serialization.json"))
            }
        }
    }
}
