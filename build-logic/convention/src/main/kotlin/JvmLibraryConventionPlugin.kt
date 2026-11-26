import com.aegis.security.buildlogic.configureKotlinJvm
import com.aegis.security.buildlogic.libs
import com.aegis.security.buildlogic.library
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.dependencies

/** Módulo Kotlin puro (sem Android), usado pela camada de domínio. */
class JvmLibraryConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply("org.jetbrains.kotlin.jvm")
            configureKotlinJvm()

            dependencies {
                add("testImplementation", libs.library("junit4"))
                add("testImplementation", libs.library("kotlinx.coroutines.test"))
            }
        }
    }
}
