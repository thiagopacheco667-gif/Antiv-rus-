package com.aegis.security.feature.scanner

import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.compose.composable
import kotlinx.serialization.Serializable

@Serializable
data object ScannerDestination

fun NavController.navigateToScanner() = navigate(ScannerDestination) { launchSingleTop = true }

fun NavGraphBuilder.scannerScreen(onNavigateBack: () -> Unit) {
    composable<ScannerDestination> {
        ScannerRoute(onNavigateBack = onNavigateBack)
    }
}
