package com.aegis.security.data.di

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.preferencesDataStoreFile
import com.aegis.security.core.common.dispatchers.AegisDispatchers
import com.aegis.security.core.common.dispatchers.ApplicationScope
import com.aegis.security.core.common.dispatchers.Dispatcher
import com.aegis.security.data.local.DataStoreUserPreferencesRepository
import com.aegis.security.data.repository.RoomScanHistoryRepository
import com.aegis.security.domain.repository.ScanHistoryRepository
import com.aegis.security.domain.repository.UserPreferencesRepository
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
internal abstract class RepositoryModule {
    @Binds
    abstract fun bindsScanHistoryRepository(impl: RoomScanHistoryRepository): ScanHistoryRepository

    @Binds
    abstract fun bindsUserPreferencesRepository(
        impl: DataStoreUserPreferencesRepository,
    ): UserPreferencesRepository
}

@Module
@InstallIn(SingletonComponent::class)
internal object DataStoreModule {
    private const val PREFERENCES_FILE = "aegis_user_preferences"

    @Provides
    @Singleton
    fun providesPreferencesDataStore(
        @ApplicationContext context: Context,
        @Dispatcher(AegisDispatchers.IO) ioDispatcher: CoroutineDispatcher,
        @ApplicationScope scope: CoroutineScope,
    ): DataStore<Preferences> = PreferenceDataStoreFactory.create(
        corruptionHandler = ReplaceFileCorruptionHandler { emptyPreferences() },
        scope = CoroutineScope(scope.coroutineContext + ioDispatcher),
        produceFile = { context.preferencesDataStoreFile(PREFERENCES_FILE) },
    )
}
