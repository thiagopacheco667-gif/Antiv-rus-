package com.aegis.security.feature.settings

import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.compose.composable
import kotlinx.serialization.Serializable

@Serializable
data object SettingsDestination

fun NavController.navigateToSettings() = navigate(SettingsDestination) { launchSingleTop = true }

fun NavGraphBuilder.settingsScreen(onNavigateBack: () -> Unit) {
    composable<SettingsDestination> {
        SettingsRoute(onNavigateBack = onNavigateBack)
    }
}
