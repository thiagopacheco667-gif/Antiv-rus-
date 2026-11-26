package com.aegis.security.feature.reports

import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavOptionsBuilder
import androidx.navigation.compose.composable
import kotlinx.serialization.Serializable

/** [sourceUri] só existe logo após a análise (permissão temporária do SAF); nunca é persistido. */
@Serializable
data class ResultDestination(val recordId: Long, val sourceUri: String? = null)

fun NavController.navigateToResult(recordId: Long, sourceUri: String? = null, builder: NavOptionsBuilder.() -> Unit = {}) =
    navigate(ResultDestination(recordId, sourceUri)) {
        launchSingleTop = true
        builder()
    }

fun NavGraphBuilder.resultScreen(onNavigateBack: () -> Unit, onOpenDetails: (Long) -> Unit) {
    composable<ResultDestination> {
        ResultRoute(onNavigateBack = onNavigateBack, onOpenDetails = onOpenDetails)
    }
}
