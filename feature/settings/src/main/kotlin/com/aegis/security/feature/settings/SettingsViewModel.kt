package com.aegis.security.feature.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aegis.security.domain.analysis.PatternScanner
import com.aegis.security.domain.analysis.RuleEngine
import com.aegis.security.domain.model.AnalysisLimits
import com.aegis.security.domain.model.BackendStatus
import com.aegis.security.domain.model.OnlineServiceConfig
import com.aegis.security.domain.model.ThemePreference
import com.aegis.security.domain.usecase.CheckBackendStatusUseCase
import com.aegis.security.domain.usecase.ClearHistoryUseCase
import com.aegis.security.domain.usecase.GetScannerStatusUseCase
import com.aegis.security.domain.usecase.ObserveAnalysisLimitsUseCase
import com.aegis.security.domain.usecase.ObserveOnlineServiceConfigUseCase
import com.aegis.security.domain.usecase.ObserveScanCountUseCase
import com.aegis.security.domain.usecase.ObserveThemePreferenceUseCase
import com.aegis.security.domain.usecase.SetAnalysisLimitsUseCase
import com.aegis.security.domain.usecase.SetOnlineServiceConfigUseCase
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

sealed interface ConnectionTest {
    data object Idle : ConnectionTest
    data object Running : ConnectionTest
    data class Success(val status: BackendStatus) : ConnectionTest
    data class Failure(val message: String) : ConnectionTest
}

@HiltViewModel
class SettingsViewModel @Inject constructor(
    observeThemePreference: ObserveThemePreferenceUseCase,
    observeScanCount: ObserveScanCountUseCase,
    observeLimits: ObserveAnalysisLimitsUseCase,
    observeOnlineConfig: ObserveOnlineServiceConfigUseCase,
    getScannerStatus: GetScannerStatusUseCase,
    ruleEngine: RuleEngine,
    patternScanners: Set<@JvmSuppressWildcards PatternScanner>,
    private val setThemePreference: SetThemePreferenceUseCase,
    private val setAnalysisLimits: SetAnalysisLimitsUseCase,
    private val setOnlineConfig: SetOnlineServiceConfigUseCase,
    private val checkBackend: CheckBackendStatusUseCase,
    private val clearHistory: ClearHistoryUseCase,
) : ViewModel() {

    val engineNames: List<String> = getScannerStatus().engines.map { it.displayName }
    val ruleCount: Int = ruleEngine.ruleCount
    val yaraIntegrated: Boolean = patternScanners.isNotEmpty()

    val uiState: StateFlow<SettingsUiState> = combine(
        observeThemePreference(),
        observeScanCount(),
        observeLimits(),
        observeOnlineConfig(),
    ) { theme, count, limits, online -> SettingsUiState.Ready(theme, count, limits, online) as SettingsUiState }
        .catch { emit(SettingsUiState.Error) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), SettingsUiState.Loading)

    private val _clearDialogVisible = MutableStateFlow(false)
    val clearDialogVisible: StateFlow<Boolean> = _clearDialogVisible.asStateFlow()

    private val _message = MutableStateFlow<SettingsMessage?>(null)
    val message: StateFlow<SettingsMessage?> = _message.asStateFlow()

    private val _connection = MutableStateFlow<ConnectionTest>(ConnectionTest.Idle)
    val connection: StateFlow<ConnectionTest> = _connection.asStateFlow()

    fun onThemeSelected(preference: ThemePreference) {
        viewModelScope.launch { runOperation { setThemePreference(preference) } }
    }

    fun onLimitsChanged(limits: AnalysisLimits) {
        viewModelScope.launch { runOperation { setAnalysisLimits(limits) } }
    }

    /** [token] vazio mantém o token atual; use [removeOnlineConfig] para apagá-lo. */
    fun saveOnlineConfig(url: String, token: String) {
        if (url.isNotBlank() && !OnlineServiceConfig.isValidBaseUrl(url)) {
            _message.value = SettingsMessage.InvalidUrl
            return
        }
        viewModelScope.launch {
            if (runOperation { setOnlineConfig(url, token.ifBlank { null }) }) {
                _message.value = SettingsMessage.OnlineSaved
                _connection.value = ConnectionTest.Idle
            }
        }
    }

    fun removeOnlineConfig() {
        viewModelScope.launch {
            if (runOperation { setOnlineConfig("", "") }) {
                _message.value = SettingsMessage.OnlineRemoved
                _connection.value = ConnectionTest.Idle
            }
        }
    }

    fun testConnection() {
        _connection.value = ConnectionTest.Running
        viewModelScope.launch {
            _connection.value = checkBackend().fold(
                onSuccess = { ConnectionTest.Success(it) },
                onFailure = { ConnectionTest.Failure(it.message ?: "falha") },
            )
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
    data class Ready(
        val theme: ThemePreference,
        val storedRecords: Int,
        val limits: AnalysisLimits,
        val online: OnlineServiceConfig,
    ) : SettingsUiState
}

enum class SettingsMessage { HistoryCleared, OperationFailed, OnlineSaved, OnlineRemoved, InvalidUrl }
