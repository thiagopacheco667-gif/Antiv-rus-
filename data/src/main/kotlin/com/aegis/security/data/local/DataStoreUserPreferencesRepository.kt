package com.aegis.security.data.local

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import com.aegis.security.data.mapper.toEnumOrNull
import com.aegis.security.domain.model.ThemePreference
import com.aegis.security.domain.repository.UserPreferencesRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import java.io.IOException
import javax.inject.Inject

/**
 * Preferências não sensíveis (tema). Configurações sensíveis do serviço online
 * (Etapa 7) usarão armazenamento criptografado separado.
 */
internal class DataStoreUserPreferencesRepository @Inject constructor(
    private val dataStore: DataStore<Preferences>,
) : UserPreferencesRepository {

    override val themePreference: Flow<ThemePreference> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { preferences ->
            preferences[THEME_KEY]?.toEnumOrNull<ThemePreference>() ?: ThemePreference.Default
        }
        .distinctUntilChanged()

    override suspend fun setThemePreference(preference: ThemePreference) {
        dataStore.edit { it[THEME_KEY] = preference.name }
    }

    private companion object {
        val THEME_KEY = stringPreferencesKey("theme_preference")
    }
}
