package com.aegis.security.feature.scanner

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aegis.security.domain.analysis.ScannerStatus
import com.aegis.security.domain.model.AnalysisLimits
import com.aegis.security.domain.model.OnlineServiceConfig
import com.aegis.security.domain.usecase.GetScannerStatusUseCase
import com.aegis.security.domain.usecase.ObserveAnalysisLimitsUseCase
import com.aegis.security.domain.usecase.ObserveOnlineServiceConfigUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

@HiltViewModel
class ScannerViewModel @Inject constructor(
    getScannerStatus: GetScannerStatusUseCase,
    observeLimits: ObserveAnalysisLimitsUseCase,
    observeOnlineConfig: ObserveOnlineServiceConfigUseCase,
) : ViewModel() {
    private val status = getScannerStatus()

    val uiState: StateFlow<ScannerUiState> = combine(observeLimits(), observeOnlineConfig()) { limits, online ->
        ScannerUiState(status, limits, online)
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ScannerUiState(status, AnalysisLimits(), OnlineServiceConfig.Empty))
}

data class ScannerUiState(
    val status: ScannerStatus,
    val limits: AnalysisLimits,
    val online: OnlineServiceConfig,
)
