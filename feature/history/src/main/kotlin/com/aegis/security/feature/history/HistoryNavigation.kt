package com.aegis.security.feature.history

import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.compose.composable
import kotlinx.serialization.Serializable

@Serializable
data object HistoryDestination

fun NavController.navigateToHistory() = navigate(HistoryDestination) { launchSingleTop = true }

fun NavGraphBuilder.historyScreen(onNavigateBack: () -> Unit, onOpenRecord: (Long) -> Unit) {
    composable<HistoryDestination> {
        HistoryRoute(onNavigateBack = onNavigateBack, onOpenRecord = onOpenRecord)
    }
}
