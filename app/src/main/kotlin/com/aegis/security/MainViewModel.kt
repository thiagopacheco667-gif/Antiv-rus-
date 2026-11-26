package com.aegis.security

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aegis.security.domain.model.ThemePreference
import com.aegis.security.domain.usecase.ObserveThemePreferenceUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    observeThemePreference: ObserveThemePreferenceUseCase,
) : ViewModel() {

    val uiState: StateFlow<MainUiState> = observeThemePreference()
        .map<ThemePreference, MainUiState> { MainUiState.Ready(it) }
        .catch { emit(MainUiState.Ready(ThemePreference.Default)) }
        // Eagerly: a splash screen aguarda a preferência de tema para evitar troca visual.
        .stateIn(viewModelScope, SharingStarted.Eagerly, MainUiState.Loading)
}

sealed interface MainUiState {
    data object Loading : MainUiState
    data class Ready(val theme: ThemePreference) : MainUiState
}
