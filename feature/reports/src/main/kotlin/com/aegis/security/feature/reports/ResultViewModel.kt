package com.aegis.security.feature.reports

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.navigation.toRoute
import com.aegis.security.domain.model.OnlineReputation
import com.aegis.security.domain.model.ScanRecord
import com.aegis.security.domain.usecase.DiscardPartsUseCase
import com.aegis.security.domain.usecase.FileMismatchException
import com.aegis.security.domain.usecase.InspectExecutablePartsUseCase
import com.aegis.security.domain.usecase.LookupReputationUseCase
import com.aegis.security.domain.usecase.PartsSession
import com.aegis.security.domain.usecase.UploadUnknownPartsUseCase
import com.aegis.security.domain.usecase.ObserveOnlineServiceConfigUseCase
import com.aegis.security.domain.usecase.ObserveScanRecordUseCase
import com.aegis.security.domain.usecase.UploadForAnalysisUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject
import kotlin.coroutines.cancellation.CancellationException

sealed interface ResultUiState {
    data object Loading : ResultUiState
    data object NotFound : ResultUiState
    data class Ready(val record: ScanRecord, val onlineConfigured: Boolean) : ResultUiState
}

/** Estado das ações online. Cada passo externo exige confirmação explícita. */
sealed interface OnlineAction {
    data object Idle : OnlineAction
    data object ConfirmLookup : OnlineAction
    data object LookingUp : OnlineAction
    data object NeedsFileSelection : OnlineAction
    data object ConfirmUpload : OnlineAction
    data class Uploading(val progress: Float) : OnlineAction
    data class WaitingAnalysis(val status: String) : OnlineAction
    data class Error(val message: String) : OnlineAction
    data object ConfirmParts : OnlineAction
    data class PartsWorking(val message: PartsMessage) : OnlineAction
    data object ConfirmPartsUpload : OnlineAction
    data class PartsUploading(val index: Int, val total: Int, val part: String, val progress: Float) : OnlineAction
}

sealed interface PartsMessage {
    data class Extracting(val part: String) : PartsMessage
    data class Checking(val index: Int, val total: Int, val part: String) : PartsMessage
}

private enum class AfterSelection { UPLOAD, PARTS }

@HiltViewModel
class ResultViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    observeRecord: ObserveScanRecordUseCase,
    observeOnlineConfig: ObserveOnlineServiceConfigUseCase,
    private val lookupReputation: LookupReputationUseCase,
    private val uploadForAnalysis: UploadForAnalysisUseCase,
    private val inspectParts: InspectExecutablePartsUseCase,
    private val uploadUnknownParts: UploadUnknownPartsUseCase,
    private val discardParts: DiscardPartsUseCase,
) : ViewModel() {
    private val route = savedStateHandle.toRoute<ResultDestination>()
    val recordId: Long = route.recordId
    private var sourceUri: String? = route.sourceUri

    val uiState: StateFlow<ResultUiState> = combine(observeRecord(recordId), observeOnlineConfig().map { it.isConfigured }) { record, configured ->
        if (record == null) ResultUiState.NotFound else ResultUiState.Ready(record, configured)
    }
        .catch { emit(ResultUiState.NotFound) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ResultUiState.Loading)

    private val _action = MutableStateFlow<OnlineAction>(OnlineAction.Idle)
    val action: StateFlow<OnlineAction> = _action.asStateFlow()

    private var job: Job? = null
    private var afterSelection = AfterSelection.UPLOAD
    private var partsSession: PartsSession? = null

    private val _hasPartsSession = MutableStateFlow(false)
    val hasPartsSession: StateFlow<Boolean> = _hasPartsSession.asStateFlow()

    fun requestLookup() {
        _action.value = OnlineAction.ConfirmLookup
    }

    fun confirmLookup() {
        _action.value = OnlineAction.LookingUp
        job = viewModelScope.launch {
            guarded {
                val result = lookupReputation(recordId)
                _action.value = (result as? OnlineReputation.Failed)?.let { OnlineAction.Error(it.message) } ?: OnlineAction.Idle
            }
        }
    }

    fun requestUpload() {
        afterSelection = AfterSelection.UPLOAD
        _action.value = if (sourceUri == null) OnlineAction.NeedsFileSelection else OnlineAction.ConfirmUpload
    }

    fun requestParts() {
        afterSelection = AfterSelection.PARTS
        _action.value = if (sourceUri == null) OnlineAction.NeedsFileSelection else OnlineAction.ConfirmParts
    }

    /** Extrai o código do APK e consulta o hash de cada parte (consentimento já dado). */
    fun confirmParts() {
        val uri = sourceUri ?: return
        _action.value = OnlineAction.PartsWorking(PartsMessage.Extracting(""))
        job = viewModelScope.launch {
            guarded {
                releaseSession()
                val session = inspectParts(recordId, uri) { progress ->
                    _action.value = OnlineAction.PartsWorking(
                        when (progress) {
                            is InspectExecutablePartsUseCase.Progress.Extracting -> PartsMessage.Extracting(progress.part)
                            is InspectExecutablePartsUseCase.Progress.Checking -> PartsMessage.Checking(progress.index, progress.total, progress.part)
                        },
                    )
                }
                partsSession = session
                _hasPartsSession.value = true
                _action.value = OnlineAction.Idle
            }
        }
    }

    fun requestPartsUpload() {
        if (partsSession != null) _action.value = OnlineAction.ConfirmPartsUpload
    }

    fun confirmPartsUpload() {
        val session = partsSession ?: return
        _action.value = OnlineAction.PartsUploading(0, 0, "", 0f)
        job = viewModelScope.launch {
            guarded {
                partsSession = null
                _hasPartsSession.value = false
                uploadUnknownParts(recordId, session, { index, total, part, fraction ->
                    _action.value = OnlineAction.PartsUploading(index, total, part, fraction)
                })
                _action.value = OnlineAction.Idle
            }
        }
    }

    private fun releaseSession() {
        partsSession?.let(discardParts::invoke)
        partsSession = null
        _hasPartsSession.value = false
    }

    override fun onCleared() {
        releaseSession()
    }

    /** Arquivo selecionado novamente (ex.: ao abrir pelo histórico). O SHA-256 é conferido antes do envio. */
    fun onFileReselected(uri: String?) {
        if (uri == null) {
            _action.value = OnlineAction.Idle
            return
        }
        sourceUri = uri
        _action.value = if (afterSelection == AfterSelection.PARTS) OnlineAction.ConfirmParts else OnlineAction.ConfirmUpload
    }

    fun confirmUpload() {
        val uri = sourceUri ?: return
        _action.value = OnlineAction.Uploading(0f)
        job = viewModelScope.launch {
            guarded {
                val result = uploadForAnalysis(
                    recordId = recordId,
                    uri = uri,
                    onUploadProgress = { progress -> _action.value = OnlineAction.Uploading(progress) },
                    onStatus = { status -> _action.value = OnlineAction.WaitingAnalysis(status) },
                )
                _action.value = (result as? OnlineReputation.Failed)?.let { OnlineAction.Error(it.message) } ?: OnlineAction.Idle
            }
        }
    }

    /** Cancela a operação online em andamento; nada é salvo para operações canceladas. */
    fun cancelOnline() {
        job?.cancel()
        _action.value = OnlineAction.Idle
    }

    fun dismiss() {
        val busy = _action.value.let {
            it is OnlineAction.Uploading || it is OnlineAction.WaitingAnalysis || it == OnlineAction.LookingUp ||
                it is OnlineAction.PartsWorking || it is OnlineAction.PartsUploading
        }
        if (!busy) {
            _action.value = OnlineAction.Idle
        }
    }

    private suspend fun guarded(block: suspend () -> Unit) {
        try {
            block()
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (error: Exception) {
            _action.value = OnlineAction.Error(
                when (error) {
                    is FileMismatchException -> error.message!!
                    is java.io.IOException -> "não foi possível ler o arquivo: ${error.message}"
                    else -> error.message ?: "falha inesperada"
                },
            )
        }
    }
}
