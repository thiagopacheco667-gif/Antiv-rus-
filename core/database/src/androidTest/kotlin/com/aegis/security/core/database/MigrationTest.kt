package com.aegis.security.core.database

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Cria um banco no esquema v1 (como gerado pelo Room 2.6) e verifica a migração para v2. */
@RunWith(AndroidJUnit4::class)
class MigrationTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val name = "migration-test.db"

    @Before
    fun createV1() {
        context.deleteDatabase(name)
        val db = SQLiteDatabase.openOrCreateDatabase(context.getDatabasePath(name), null)
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS `scan_records` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                "`file_name` TEXT NOT NULL, `sha256` TEXT NOT NULL, `format` TEXT NOT NULL, `size_bytes` INTEGER, " +
                "`scanned_at` INTEGER NOT NULL, `verdict` TEXT NOT NULL, `origin` TEXT NOT NULL, `evidence_summary` TEXT NOT NULL)",
        )
        db.execSQL("CREATE INDEX IF NOT EXISTS `index_scan_records_scanned_at` ON `scan_records` (`scanned_at`)")
        db.execSQL("CREATE INDEX IF NOT EXISTS `index_scan_records_sha256` ON `scan_records` (`sha256`)")
        db.execSQL(
            "INSERT INTO scan_records (file_name, sha256, format, size_bytes, scanned_at, verdict, origin, evidence_summary) " +
                "VALUES ('antigo.zip', '${"a".repeat(64)}', 'ZIP', 10, 1, 'SUSPICIOUS', 'LOCAL', 'x')",
        )
        db.version = 1
        db.close()
    }

    @After
    fun tearDown() {
        context.deleteDatabase(name)
    }

    @Test
    fun migration1to2_keepsRecords_andAddsReportColumn() = runTest {
        val database = Room.databaseBuilder(context, AegisDatabase::class.java, name)
            .addMigrations(*AegisDatabase.ALL_MIGRATIONS)
            .build()
        val rows = database.scanRecordDao().observeAll().first()
        assertEquals(1, rows.size)
        assertEquals("antigo.zip", rows.single().fileName)
        assertEquals("SUSPICIOUS", rows.single().verdict)
        assertNull(rows.single().reportJson)
        database.close()
    }
}
