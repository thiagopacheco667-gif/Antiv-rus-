package com.aegis.security.domain.repository

import com.aegis.security.domain.model.AnalysisLimits
import com.aegis.security.domain.model.OnlineServiceConfig
import com.aegis.security.domain.model.ThemePreference
import kotlinx.coroutines.flow.Flow

interface UserPreferencesRepository {
    val themePreference: Flow<ThemePreference>
    val analysisLimits: Flow<AnalysisLimits>
    val onlineServiceConfig: Flow<OnlineServiceConfig>

    suspend fun setThemePreference(preference: ThemePreference)

    suspend fun setAnalysisLimits(limits: AnalysisLimits)

    /** [accessToken] nulo mantém o token atual; vazio remove. Armazenado criptografado. */
    suspend fun setOnlineServiceConfig(baseUrl: String, accessToken: String?)

    suspend fun accessToken(): String?
}
