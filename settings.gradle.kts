pluginManagement {
    includeBuild("build-logic")
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

rootProject.name = "AegisSecurity"

include(":app")

include(":core:common")
include(":core:database")
include(":core:designsystem")
include(":core:security")
include(":core:ui")

include(":domain")
include(":data")

include(":feature:dashboard")
include(":feature:scanner")
include(":feature:history")
include(":feature:settings")
