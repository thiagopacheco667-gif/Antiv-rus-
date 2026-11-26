package com.aegis.security.feature.scanner

import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.compose.composable
import kotlinx.serialization.Serializable

@Serializable
data object ScannerDestination

/** O URI vem do Storage Access Framework; apenas a permissão temporária de leitura é usada. */
@Serializable
data class AnalyzingDestination(val uri: String)

fun NavController.navigateToScanner() = navigate(ScannerDestination) { launchSingleTop = true }

fun NavController.navigateToAnalyzing(uri: String) = navigate(AnalyzingDestination(uri)) {
    popUpTo<ScannerDestination> { inclusive = true }
}

fun NavGraphBuilder.scannerScreen(
    onNavigateBack: () -> Unit,
    onFileSelected: (String) -> Unit,
) {
    composable<ScannerDestination> {
        ScannerRoute(onNavigateBack = onNavigateBack, onFileSelected = onFileSelected)
    }
}

fun NavGraphBuilder.analyzingScreen(
    onCompleted: (recordId: Long, sourceUri: String) -> Unit,
    onCancelled: () -> Unit,
) {
    composable<AnalyzingDestination> {
        AnalyzingRoute(onCompleted = onCompleted, onCancelled = onCancelled)
    }
}
