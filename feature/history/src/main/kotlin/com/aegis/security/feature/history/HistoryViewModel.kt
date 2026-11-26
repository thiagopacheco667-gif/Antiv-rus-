package com.aegis.security.feature.history

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aegis.security.domain.model.ScanRecord
import com.aegis.security.domain.usecase.ClearHistoryUseCase
import com.aegis.security.domain.usecase.DeleteScanRecordUseCase
import com.aegis.security.domain.usecase.ObserveHistoryUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject
import kotlin.coroutines.cancellation.CancellationException

@HiltViewModel
class HistoryViewModel @Inject constructor(
    observeHistory: ObserveHistoryUseCase,
    private val deleteScanRecord: DeleteScanRecordUseCase,
    private val clearHistory: ClearHistoryUseCase,
) : ViewModel() {

    val uiState: StateFlow<HistoryUiState> = observeHistory()
        .map<List<ScanRecord>, HistoryUiState> { HistoryUiState.Ready(it) }
        .catch { emit(HistoryUiState.Error) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), HistoryUiState.Loading)

    private val _pendingConfirmation = MutableStateFlow<HistoryConfirmation?>(null)
    val pendingConfirmation: StateFlow<HistoryConfirmation?> = _pendingConfirmation.asStateFlow()

    private val _operationFailed = MutableStateFlow(false)
    val operationFailed: StateFlow<Boolean> = _operationFailed.asStateFlow()

    fun requestDelete(record: ScanRecord) {
        _pendingConfirmation.value = HistoryConfirmation.DeleteOne(record.id, record.fileName)
    }

    fun requestClearAll() {
        _pendingConfirmation.value = HistoryConfirmation.ClearAll
    }

    fun dismissConfirmation() {
        _pendingConfirmation.value = null
    }

    fun confirm() {
        val confirmation = _pendingConfirmation.value ?: return
        _pendingConfirmation.value = null
        viewModelScope.launch {
            try {
                when (confirmation) {
                    is HistoryConfirmation.DeleteOne -> deleteScanRecord(confirmation.id)
                    HistoryConfirmation.ClearAll -> clearHistory()
                }
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (error: Exception) {
                _operationFailed.value = true
            }
        }
    }

    fun onOperationErrorShown() {
        _operationFailed.value = false
    }
}

sealed interface HistoryUiState {
    data object Loading : HistoryUiState
    data object Error : HistoryUiState
    data class Ready(val records: List<ScanRecord>) : HistoryUiState
}

sealed interface HistoryConfirmation {
    data class DeleteOne(val id: Long, val fileName: String) : HistoryConfirmation
    data object ClearAll : HistoryConfirmation
}
