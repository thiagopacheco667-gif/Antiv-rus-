package com.aegis.security.feature.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aegis.security.domain.model.ThemePreference
import com.aegis.security.domain.usecase.ClearHistoryUseCase
import com.aegis.security.domain.usecase.ObserveScanCountUseCase
import com.aegis.security.domain.usecase.ObserveThemePreferenceUseCase
import com.aegis.security.domain.usecase.SetThemePreferenceUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject
import kotlin.coroutines.cancellation.CancellationException

@HiltViewModel
class SettingsViewModel @Inject constructor(
    observeThemePreference: ObserveThemePreferenceUseCase,
    observeScanCount: ObserveScanCountUseCase,
    private val setThemePreference: SetThemePreferenceUseCase,
    private val clearHistory: ClearHistoryUseCase,
) : ViewModel() {

    val uiState: StateFlow<SettingsUiState> = combine(
        observeThemePreference(),
        observeScanCount(),
    ) { theme, count -> SettingsUiState.Ready(theme, count) as SettingsUiState }
        .catch { emit(SettingsUiState.Error) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), SettingsUiState.Loading)

    private val _clearDialogVisible = MutableStateFlow(false)
    val clearDialogVisible: StateFlow<Boolean> = _clearDialogVisible.asStateFlow()

    private val _message = MutableStateFlow<SettingsMessage?>(null)
    val message: StateFlow<SettingsMessage?> = _message.asStateFlow()

    fun onThemeSelected(preference: ThemePreference) {
        viewModelScope.launch {
            runOperation { setThemePreference(preference) }
        }
    }

    fun requestClearHistory() {
        _clearDialogVisible.value = true
    }

    fun dismissClearHistory() {
        _clearDialogVisible.value = false
    }

    fun confirmClearHistory() {
        _clearDialogVisible.value = false
        viewModelScope.launch {
            if (runOperation { clearHistory() }) _message.value = SettingsMessage.HistoryCleared
        }
    }

    fun onMessageShown() {
        _message.value = null
    }

    private suspend fun runOperation(block: suspend () -> Unit): Boolean = try {
        block()
        true
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (error: Exception) {
        _message.value = SettingsMessage.OperationFailed
        false
    }
}

sealed interface SettingsUiState {
    data object Loading : SettingsUiState
    data object Error : SettingsUiState
    data class Ready(val theme: ThemePreference, val storedRecords: Int) : SettingsUiState
}

enum class SettingsMessage { HistoryCleared, OperationFailed }
