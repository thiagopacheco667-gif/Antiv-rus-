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
import com.aegis.security.data.local.KeystoreTokenCipher
import com.aegis.security.data.local.SafFileStager
import com.aegis.security.data.local.TokenCipher
import com.aegis.security.data.remote.BackendReputationRepository
import com.aegis.security.data.remote.Clock
import com.aegis.security.data.remote.CoroutineSleeper
import com.aegis.security.data.remote.Sleeper
import com.aegis.security.data.remote.SystemClock
import com.aegis.security.data.repository.RoomScanHistoryRepository
import com.aegis.security.domain.repository.FileStager
import com.aegis.security.domain.repository.ReputationRepository
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
    abstract fun bindsUserPreferencesRepository(impl: DataStoreUserPreferencesRepository): UserPreferencesRepository

    @Binds
    abstract fun bindsFileStager(impl: SafFileStager): FileStager

    @Binds
    @Singleton
    abstract fun bindsReputationRepository(impl: BackendReputationRepository): ReputationRepository

    @Binds
    abstract fun bindsTokenCipher(impl: KeystoreTokenCipher): TokenCipher

    @Binds
    abstract fun bindsClock(impl: SystemClock): Clock

    @Binds
    abstract fun bindsSleeper(impl: CoroutineSleeper): Sleeper
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
