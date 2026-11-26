import androidx.room.gradle.RoomExtension
import com.aegis.security.buildlogic.libs
import com.aegis.security.buildlogic.library
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.dependencies

class AndroidRoomConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply("com.google.devtools.ksp")
            pluginManager.apply("androidx.room")

            extensions.configure<RoomExtension> {
                // Esquemas versionados no repositório para validar migrações futuras.
                schemaDirectory("$projectDir/schemas")
            }

            dependencies {
                add("implementation", libs.library("androidx.room.runtime"))
                add("implementation", libs.library("androidx.room.ktx"))
                add("ksp", libs.library("androidx.room.compiler"))
            }
        }
    }
}
