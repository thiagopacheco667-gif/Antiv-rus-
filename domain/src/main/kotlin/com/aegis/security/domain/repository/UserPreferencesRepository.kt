package com.aegis.security.domain.repository

import com.aegis.security.domain.model.AnalysisLimits
import com.aegis.security.domain.model.OnlineMode
import com.aegis.security.domain.model.OnlineServiceConfig
import com.aegis.security.domain.model.ThemePreference
import kotlinx.coroutines.flow.Flow

interface UserPreferencesRepository {
    val themePreference: Flow<ThemePreference>
    val analysisLimits: Flow<AnalysisLimits>
    val onlineServiceConfig: Flow<OnlineServiceConfig>

    suspend fun setThemePreference(preference: ThemePreference)

    suspend fun setAnalysisLimits(limits: AnalysisLimits)

    /**
     * Salva o modo e, conforme o modo, a credencial (token do servidor ou chave do VirusTotal),
     * sempre cifrada. [credential] nulo mantém a atual; vazio remove.
     */
    suspend fun setOnlineServiceConfig(mode: OnlineMode, baseUrl: String, credential: String?)

    /** Credencial decifrada do modo informado. */
    suspend fun credential(mode: OnlineMode): String?
}
