package com.aegis.security.core.database

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.aegis.security.core.database.dao.ScanRecordDao
import com.aegis.security.core.database.model.ScanRecordEntity

@Database(
    entities = [ScanRecordEntity::class],
    version = 2,
    exportSchema = true,
)
abstract class AegisDatabase : RoomDatabase() {
    abstract fun scanRecordDao(): ScanRecordDao

    companion object {
        const val NAME = "aegis.db"

        /** v2: relatório detalhado (JSON) para resultado e detalhes técnicos. */
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE scan_records ADD COLUMN report_json TEXT")
            }
        }

        val ALL_MIGRATIONS = arrayOf(MIGRATION_1_2)
    }
}
