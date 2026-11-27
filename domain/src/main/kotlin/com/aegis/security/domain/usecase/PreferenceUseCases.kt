package com.aegis.security.domain.usecase

import com.aegis.security.domain.model.AnalysisLimits
import com.aegis.security.domain.model.BackendStatus
import com.aegis.security.domain.model.OnlineMode
import com.aegis.security.domain.model.OnlineServiceConfig
import com.aegis.security.domain.model.ThemePreference
import com.aegis.security.domain.repository.ReputationRepository
import com.aegis.security.domain.repository.UserPreferencesRepository
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class ObserveThemePreferenceUseCase @Inject constructor(
    private val repository: UserPreferencesRepository,
) {
    operator fun invoke(): Flow<ThemePreference> = repository.themePreference
}

class SetThemePreferenceUseCase @Inject constructor(
    private val repository: UserPreferencesRepository,
) {
    suspend operator fun invoke(preference: ThemePreference) = repository.setThemePreference(preference)
}

class ObserveAnalysisLimitsUseCase @Inject constructor(
    private val repository: UserPreferencesRepository,
) {
    operator fun invoke(): Flow<AnalysisLimits> = repository.analysisLimits
}

class SetAnalysisLimitsUseCase @Inject constructor(
    private val repository: UserPreferencesRepository,
) {
    suspend operator fun invoke(limits: AnalysisLimits) = repository.setAnalysisLimits(limits)
}

class ObserveOnlineServiceConfigUseCase @Inject constructor(
    private val repository: UserPreferencesRepository,
) {
    operator fun invoke(): Flow<OnlineServiceConfig> = repository.onlineServiceConfig
}

class SetOnlineServiceConfigUseCase @Inject constructor(
    private val repository: UserPreferencesRepository,
) {
    suspend operator fun invoke(mode: OnlineMode, baseUrl: String, credential: String?) {
        val trimmed = baseUrl.trim().trimEnd('/')
        require(trimmed.isEmpty() || OnlineServiceConfig.isValidBaseUrl(trimmed)) { "A URL deve usar HTTPS" }
        val key = credential?.trim()
        if (mode == OnlineMode.DIRECT && !key.isNullOrEmpty()) {
            require(OnlineServiceConfig.isValidApiKey(key)) { "Chave do VirusTotal inválida (64 caracteres hexadecimais)" }
        }
        repository.setOnlineServiceConfig(mode, trimmed, key)
    }
}

class CheckBackendStatusUseCase @Inject constructor(
    private val reputation: ReputationRepository,
) {
    suspend operator fun invoke(): Result<BackendStatus> = reputation.status()
}
