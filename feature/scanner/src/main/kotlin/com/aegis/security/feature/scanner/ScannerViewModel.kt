package com.aegis.security.feature.scanner

import androidx.lifecycle.ViewModel
import com.aegis.security.domain.analysis.ScannerStatus
import com.aegis.security.domain.usecase.GetScannerStatusUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject

/**
 * Etapa 1: expõe apenas o estado real dos mecanismos.
 * A seleção via Storage Access Framework entra na Etapa 2, junto com o primeiro mecanismo.
 */
@HiltViewModel
class ScannerViewModel @Inject constructor(
    getScannerStatus: GetScannerStatusUseCase,
) : ViewModel() {
    val uiState: ScannerUiState = ScannerUiState(status = getScannerStatus())
}

data class ScannerUiState(val status: ScannerStatus)
