package com.aegis.security.domain.usecase

import com.aegis.security.domain.model.ThemePreference
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
