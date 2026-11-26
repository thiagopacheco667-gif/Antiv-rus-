package com.aegis.security.feature.dashboard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aegis.security.domain.analysis.ScannerStatus
import com.aegis.security.domain.model.DashboardSummary
import com.aegis.security.domain.usecase.GetScannerStatusUseCase
import com.aegis.security.domain.usecase.ObserveDashboardSummaryUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

@HiltViewModel
class DashboardViewModel @Inject constructor(
    observeDashboardSummary: ObserveDashboardSummaryUseCase,
    getScannerStatus: GetScannerStatusUseCase,
) : ViewModel() {

    private val scannerStatus: ScannerStatus = getScannerStatus()

    val uiState: StateFlow<DashboardUiState> = observeDashboardSummary()
        .map<DashboardSummary, DashboardUiState> { summary -> DashboardUiState.Ready(scannerStatus, summary) }
        // Falha ao ler o histórico é mostrada como erro — nunca como "zero ameaças".
        .catch { emit(DashboardUiState.Error) }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = DashboardUiState.Loading,
        )
}

sealed interface DashboardUiState {
    data object Loading : DashboardUiState
    data object Error : DashboardUiState
    data class Ready(val scanner: ScannerStatus, val summary: DashboardSummary) : DashboardUiState
}
