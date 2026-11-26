package com.aegis.security.feature.dashboard

import androidx.navigation.NavGraphBuilder
import androidx.navigation.compose.composable
import kotlinx.serialization.Serializable

@Serializable
data object DashboardDestination

fun NavGraphBuilder.dashboardScreen(
    onAnalyzeFile: () -> Unit,
    onOpenHistory: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    composable<DashboardDestination> {
        DashboardRoute(
            onAnalyzeFile = onAnalyzeFile,
            onOpenHistory = onOpenHistory,
            onOpenSettings = onOpenSettings,
        )
    }
}
