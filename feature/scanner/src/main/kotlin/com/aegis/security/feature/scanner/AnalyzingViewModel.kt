package com.aegis.security.feature.scanner

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.navigation.toRoute
import com.aegis.security.domain.analysis.ScanEvent
import com.aegis.security.domain.analysis.ScanStep
import com.aegis.security.domain.usecase.AnalyzeFileUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

enum class StepState { PENDING, RUNNING, DONE, SKIPPED }

data class AnalyzingUiState(
    val steps: Map<ScanStep, StepState> = ScanStep.entries.associateWith { StepState.PENDING },
    val currentFraction: Float? = null,
    val completedRecordId: Long? = null,
    val cancelled: Boolean = false,
    val unexpectedError: String? = null,
) {
    /** Progresso real: etapas concluídas + fração medida da etapa atual (ex.: bytes lidos no hash). */
    val progress: Float
        get() {
            val total = steps.size
            val done = steps.count { it.value == StepState.DONE || it.value == StepState.SKIPPED }
            val running = if (steps.any { it.value == StepState.RUNNING }) (currentFraction ?: 0f) else 0f
            return ((done + running) / total).coerceIn(0f, 1f)
        }
}

@HiltViewModel
class AnalyzingViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val analyzeFile: AnalyzeFileUseCase,
) : ViewModel() {
    val sourceUri: String = savedStateHandle.toRoute<AnalyzingDestination>().uri

    private val _uiState = MutableStateFlow(AnalyzingUiState())
    val uiState: StateFlow<AnalyzingUiState> = _uiState.asStateFlow()

    private var job: Job? = null

    init {
        start()
    }

    private fun start() {
        job = viewModelScope.launch {
            analyzeFile(sourceUri)
                .catch { error -> _uiState.update { it.copy(unexpectedError = error.message ?: error.javaClass.simpleName) } }
                .collect { event -> _uiState.update { reduce(it, event) } }
        }
    }

    /** Cancelamento cooperativo: a cópia temporária é apagada e nada é salvo no histórico. */
    fun cancel() {
        job?.cancel()
        _uiState.update { it.copy(cancelled = true) }
    }

    private fun reduce(state: AnalyzingUiState, event: ScanEvent): AnalyzingUiState = when (event) {
        is ScanEvent.Progress -> {
            val steps = state.steps.toMutableMap()
            ScanStep.entries.filter { it.ordinal < event.step.ordinal && steps[it] != StepState.SKIPPED }.forEach { steps[it] = StepState.DONE }
            steps[event.step] = StepState.RUNNING
            state.copy(steps = steps, currentFraction = event.fraction)
        }
        is ScanEvent.StepSkipped -> state.copy(steps = state.steps + (event.step to StepState.SKIPPED))
        is ScanEvent.Completed -> state.copy(
            steps = state.steps.mapValues { if (it.value == StepState.SKIPPED) it.value else StepState.DONE },
            currentFraction = null,
            completedRecordId = event.recordId,
        )
    }
}
