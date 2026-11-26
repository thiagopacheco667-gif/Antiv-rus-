package com.aegis.security.data.local

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import com.aegis.security.data.mapper.toEnumOrNull
import com.aegis.security.domain.model.AnalysisLimits
import com.aegis.security.domain.model.OnlineServiceConfig
import com.aegis.security.domain.model.ThemePreference
import com.aegis.security.domain.repository.UserPreferencesRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.io.IOException
import javax.inject.Inject

internal class DataStoreUserPreferencesRepository @Inject constructor(
    private val dataStore: DataStore<Preferences>,
    private val tokenCipher: TokenCipher,
) : UserPreferencesRepository {

    private val data: Flow<Preferences> = dataStore.data.catch { error ->
        if (error is IOException) emit(emptyPreferences()) else throw error
    }

    override val themePreference: Flow<ThemePreference> = data
        .map { it[THEME]?.toEnumOrNull<ThemePreference>() ?: ThemePreference.Default }
        .distinctUntilChanged()

    override val analysisLimits: Flow<AnalysisLimits> = data
        .map { prefs ->
            val defaults = AnalysisLimits()
            try {
                AnalysisLimits(
                    maxFileSizeMb = prefs[MAX_FILE_MB] ?: defaults.maxFileSizeMb,
                    maxArchiveEntries = prefs[MAX_ENTRIES] ?: defaults.maxArchiveEntries,
                    maxTotalUncompressedMb = prefs[MAX_UNCOMPRESSED_MB] ?: defaults.maxTotalUncompressedMb,
                    maxCompressionRatio = prefs[MAX_RATIO] ?: defaults.maxCompressionRatio,
                    maxNestingDepth = prefs[MAX_DEPTH] ?: defaults.maxNestingDepth,
                    maxContentScanMb = prefs[MAX_SCAN_MB] ?: defaults.maxContentScanMb,
                )
            } catch (error: IllegalArgumentException) {
                defaults
            }
        }
        .distinctUntilChanged()

    override val onlineServiceConfig: Flow<OnlineServiceConfig> = data
        .map { OnlineServiceConfig(baseUrl = it[BACKEND_URL].orEmpty(), hasAccessToken = !it[BACKEND_TOKEN].isNullOrEmpty()) }
        .distinctUntilChanged()

    override suspend fun setThemePreference(preference: ThemePreference) {
        dataStore.edit { it[THEME] = preference.name }
    }

    override suspend fun setAnalysisLimits(limits: AnalysisLimits) {
        dataStore.edit {
            it[MAX_FILE_MB] = limits.maxFileSizeMb
            it[MAX_ENTRIES] = limits.maxArchiveEntries
            it[MAX_UNCOMPRESSED_MB] = limits.maxTotalUncompressedMb
            it[MAX_RATIO] = limits.maxCompressionRatio
            it[MAX_DEPTH] = limits.maxNestingDepth
            it[MAX_SCAN_MB] = limits.maxContentScanMb
        }
    }

    override suspend fun setOnlineServiceConfig(baseUrl: String, accessToken: String?) {
        val encrypted = accessToken?.takeIf { it.isNotEmpty() }?.let(tokenCipher::encrypt)
        dataStore.edit {
            if (baseUrl.isEmpty()) it.remove(BACKEND_URL) else it[BACKEND_URL] = baseUrl
            when {
                accessToken == null -> Unit
                encrypted == null -> it.remove(BACKEND_TOKEN)
                else -> it[BACKEND_TOKEN] = encrypted
            }
        }
    }

    override suspend fun accessToken(): String? = data.first()[BACKEND_TOKEN]?.let(tokenCipher::decrypt)

    private companion object {
        val THEME = stringPreferencesKey("theme_preference")
        val MAX_FILE_MB = intPreferencesKey("limit_max_file_mb")
        val MAX_ENTRIES = intPreferencesKey("limit_max_entries")
        val MAX_UNCOMPRESSED_MB = intPreferencesKey("limit_max_uncompressed_mb")
        val MAX_RATIO = intPreferencesKey("limit_max_ratio")
        val MAX_DEPTH = intPreferencesKey("limit_max_depth")
        val MAX_SCAN_MB = intPreferencesKey("limit_max_scan_mb")
        val BACKEND_URL = stringPreferencesKey("backend_url")
        val BACKEND_TOKEN = stringPreferencesKey("backend_token_encrypted")
    }
}
