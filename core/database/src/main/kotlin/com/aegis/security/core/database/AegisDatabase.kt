package com.aegis.security.core.database

import androidx.room.Database
import androidx.room.RoomDatabase
import com.aegis.security.core.database.dao.ScanRecordDao
import com.aegis.security.core.database.model.ScanRecordEntity

@Database(
    entities = [ScanRecordEntity::class],
    version = 1,
    exportSchema = true,
)
abstract class AegisDatabase : RoomDatabase() {
    abstract fun scanRecordDao(): ScanRecordDao

    companion object {
        const val NAME = "aegis.db"
    }
}
