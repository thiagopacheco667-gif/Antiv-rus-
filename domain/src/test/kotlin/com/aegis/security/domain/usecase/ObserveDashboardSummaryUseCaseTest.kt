package com.aegis.security.domain.usecase

import com.aegis.security.domain.model.AnalysisOrigin
import com.aegis.security.domain.model.FileFormat
import com.aegis.security.domain.model.ScanRecord
import com.aegis.security.domain.model.Verdict
import com.aegis.security.domain.testing.FakeScanHistoryRepository
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ObserveDashboardSummaryUseCaseTest {
    private val repository = FakeScanHistoryRepository()
    private val useCase = ObserveDashboardSummaryUseCase(repository)

    @Test
    fun emptyHistory_producesEmptySummary_withoutInventedData() = runTest {
        val summary = useCase().first()

        assertEquals(0, summary.totalScans)
        assertEquals(0, summary.threatsDetected)
        assertNull(summary.lastScan)
        assertTrue(summary.recentScans.isEmpty())
        assertFalse(summary.hasHistory)
    }

    @Test
    fun summary_countsOnlyConfirmedThreats_andOrdersByMostRecent() = runTest {
        repository.save(record(Verdict.SAFE_BY_CHECKS, scannedAt = 100))
        repository.save(record(Verdict.THREAT_DETECTED, scannedAt = 300))
        repository.save(record(Verdict.SUSPICIOUS, scannedAt = 200))

        val summary = useCase().first()

        assertEquals(3, summary.totalScans)
        assertEquals(1, summary.threatsDetected)
        assertEquals(Verdict.THREAT_DETECTED, summary.lastScan?.verdict)
        assertEquals(listOf(300L, 200L, 100L), summary.recentScans.map { it.scannedAtEpochMillis })
    }

    @Test
    fun recentLimit_isRespected_butTotalCountsEverything() = runTest {
        repeat(8) { repository.save(record(Verdict.INCONCLUSIVE, scannedAt = it.toLong())) }

        val summary = useCase(recentLimit = 3).first()

        assertEquals(8, summary.totalScans)
        assertEquals(3, summary.recentScans.size)
    }

    @Test(expected = IllegalArgumentException::class)
    fun nonPositiveLimit_isRejected() {
        useCase(recentLimit = 0)
    }

    private fun record(verdict: Verdict, scannedAt: Long) = ScanRecord(
        fileName = "arquivo-$scannedAt",
        sha256 = "f".repeat(64),
        format = FileFormat.ZIP,
        sizeBytes = 10,
        scannedAtEpochMillis = scannedAt,
        verdict = verdict,
        origin = AnalysisOrigin.LOCAL,
        evidenceSummary = "",
    )
}
