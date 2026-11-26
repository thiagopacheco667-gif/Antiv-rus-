package com.aegis.security.domain.repository

import com.aegis.security.domain.model.ThemePreference
import kotlinx.coroutines.flow.Flow

interface UserPreferencesRepository {
    val themePreference: Flow<ThemePreference>

    suspend fun setThemePreference(preference: ThemePreference)
}
