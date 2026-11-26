package com.aegis.security.core.database.di

import android.content.Context
import androidx.room.Room
import com.aegis.security.core.database.AegisDatabase
import com.aegis.security.core.database.dao.ScanRecordDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
internal object DatabaseModule {
    @Provides
    @Singleton
    fun providesAegisDatabase(@ApplicationContext context: Context): AegisDatabase =
        Room.databaseBuilder(context, AegisDatabase::class.java, AegisDatabase.NAME).build()

    @Provides
    fun providesScanRecordDao(database: AegisDatabase): ScanRecordDao = database.scanRecordDao()
}
