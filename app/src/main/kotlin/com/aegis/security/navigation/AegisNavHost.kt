package com.aegis.security.navigation

import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.rememberNavController
import com.aegis.security.feature.dashboard.DashboardDestination
import com.aegis.security.feature.dashboard.dashboardScreen
import com.aegis.security.feature.filedetails.detailsScreen
import com.aegis.security.feature.filedetails.navigateToDetails
import com.aegis.security.feature.history.historyScreen
import com.aegis.security.feature.history.navigateToHistory
import com.aegis.security.feature.reports.navigateToResult
import com.aegis.security.feature.reports.resultScreen
import com.aegis.security.feature.scanner.AnalyzingDestination
import com.aegis.security.feature.scanner.analyzingScreen
import com.aegis.security.feature.scanner.navigateToAnalyzing
import com.aegis.security.feature.scanner.navigateToScanner
import com.aegis.security.feature.scanner.scannerScreen
import com.aegis.security.feature.settings.navigateToSettings
import com.aegis.security.feature.settings.settingsScreen

private const val ENTER_MS = 280
private const val EXIT_MS = 200

/**
 * Grafo de navegação com rotas tipadas. Fluxo principal:
 * Dashboard → Scanner (SAF) → Analisando → Resultado → Detalhes técnicos.
 */
@Composable
fun AegisNavHost(
    modifier: Modifier = Modifier,
    navController: NavHostController = rememberNavController(),
) {
    // navigateUp() não faz nada no destino inicial, evitando pilha vazia em toques duplos.
    val navigateBack: () -> Unit = { navController.navigateUp() }
    val openRecord: (Long) -> Unit = { id -> navController.navigateToResult(id) }

    NavHost(
        navController = navController,
        startDestination = DashboardDestination,
        modifier = modifier,
        enterTransition = { fadeIn(tween(ENTER_MS)) + slideInHorizontally(tween(ENTER_MS)) { it / 10 } },
        exitTransition = { fadeOut(tween(EXIT_MS)) },
        popEnterTransition = { fadeIn(tween(ENTER_MS)) },
        popExitTransition = { fadeOut(tween(EXIT_MS)) + slideOutHorizontally(tween(ENTER_MS)) { it / 10 } },
    ) {
        dashboardScreen(
            onAnalyzeFile = { navController.navigateToScanner() },
            onOpenRecord = openRecord,
            onOpenHistory = { navController.navigateToHistory() },
            onOpenSettings = { navController.navigateToSettings() },
        )
        scannerScreen(
            onNavigateBack = navigateBack,
            onFileSelected = { uri -> navController.navigateToAnalyzing(uri) },
        )
        analyzingScreen(
            onCompleted = { id, uri ->
                navController.navigateToResult(id, uri) {
                    popUpTo<AnalyzingDestination> { inclusive = true }
                }
            },
            onCancelled = navigateBack,
        )
        resultScreen(
            onNavigateBack = navigateBack,
            onOpenDetails = { id -> navController.navigateToDetails(id) },
        )
        detailsScreen(onNavigateBack = navigateBack)
        historyScreen(onNavigateBack = navigateBack, onOpenRecord = openRecord)
        settingsScreen(onNavigateBack = navigateBack)
    }
}
