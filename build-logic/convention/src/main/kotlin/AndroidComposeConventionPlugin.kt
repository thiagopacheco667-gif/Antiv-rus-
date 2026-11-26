import com.aegis.security.buildlogic.libs
import com.aegis.security.buildlogic.library
import com.android.build.api.dsl.CommonExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.dependencies

/**
 * Habilita Jetpack Compose. Deve ser aplicado depois de `aegis.android.application`
 * ou `aegis.android.library`, pois depende da extensão `android`.
 */
class AndroidComposeConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply("org.jetbrains.kotlin.plugin.compose")

            val android = extensions.getByName("android") as CommonExtension<*, *, *, *, *, *>
            android.buildFeatures {
                compose = true
            }

            dependencies {
                val bom = libs.library("androidx.compose.bom")
                add("implementation", platform(bom))
                add("androidTestImplementation", platform(bom))
                add("implementation", libs.library("androidx.compose.ui.tooling.preview"))
                add("debugImplementation", libs.library("androidx.compose.ui.tooling"))
            }
        }
    }
}
