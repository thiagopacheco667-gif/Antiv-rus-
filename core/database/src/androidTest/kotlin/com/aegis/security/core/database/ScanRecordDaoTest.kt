package com.aegis.security.core.database

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.aegis.security.core.database.dao.ScanRecordDao
import com.aegis.security.core.database.model.ScanRecordEntity
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ScanRecordDaoTest {
    private lateinit var database: AegisDatabase
    private lateinit var dao: ScanRecordDao

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        database = Room.inMemoryDatabaseBuilder(context, AegisDatabase::class.java).build()
        dao = database.scanRecordDao()
    }

    @After
    fun tearDown() {
        database.close()
    }

    @Test
    fun emptyDatabase_reportsZeroAndEmptyLists() = runTest {
        assertEquals(0, dao.observeCount().first())
        assertTrue(dao.observeAll().first().isEmpty())
    }

    @Test
    fun recent_isOrderedByMostRecentAndLimited() = runTest {
        dao.insert(entity(name = "a.zip", scannedAt = 100))
        dao.insert(entity(name = "b.apk", scannedAt = 300))
        dao.insert(entity(name = "c.pdf", scannedAt = 200))

        val recent = dao.observeRecent(limit = 2).first()

        assertEquals(listOf("b.apk", "c.pdf"), recent.map { it.fileName })
    }

    @Test
    fun countByVerdict_countsOnlyMatchingRows() = runTest {
        dao.insert(entity(name = "a", verdict = "THREAT_DETECTED"))
        dao.insert(entity(name = "b", verdict = "SUSPICIOUS"))
        dao.insert(entity(name = "c", verdict = "THREAT_DETECTED"))

        assertEquals(2, dao.observeCountByVerdict("THREAT_DETECTED").first())
    }

    @Test
    fun deleteById_removesOnlyThatRow_andDeleteAllClears() = runTest {
        val keep = dao.insert(entity(name = "keep"))
        val remove = dao.insert(entity(name = "remove"))

        assertEquals(1, dao.deleteById(remove))
        assertEquals(listOf(keep), dao.observeAll().first().map { it.id })

        dao.deleteAll()
        assertEquals(0, dao.observeCount().first())
    }

    private fun entity(
        name: String,
        scannedAt: Long = 0,
        verdict: String = "INCONCLUSIVE",
    ) = ScanRecordEntity(
        fileName = name,
        sha256 = "0".repeat(64),
        format = "UNKNOWN",
        sizeBytes = 0,
        scannedAtEpochMillis = scannedAt,
        verdict = verdict,
        origin = "LOCAL",
        evidenceSummary = "",
    )
}
