package com.aegis.security.domain.usecase

import com.aegis.security.domain.analysis.EngineResult
import com.aegis.security.domain.analysis.ScanEvent
import com.aegis.security.domain.analysis.ScanStep
import com.aegis.security.domain.analysis.Severity
import com.aegis.security.domain.model.AnalysisLimits
import com.aegis.security.domain.model.EngineStatus
import com.aegis.security.domain.model.FileFormat
import com.aegis.security.domain.model.Verdict
import com.aegis.security.domain.testing.FakeEngine
import com.aegis.security.domain.testing.FakeFileStager
import com.aegis.security.domain.testing.FakeIdentifier
import com.aegis.security.domain.testing.FakePreferences
import com.aegis.security.domain.testing.FakeRuleEngine
import com.aegis.security.domain.testing.FakeScanHistoryRepository
import com.aegis.security.domain.testing.MarkerFact
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class AnalyzeFileUseCaseTest {
    @get:Rule
    val temp = TemporaryFolder()

    private val history = FakeScanHistoryRepository()

    private fun useCase(
        format: FileFormat,
        vararg engines: FakeEngine,
        stager: FakeFileStager = FakeFileStager(temp.newFolder()),
        limits: AnalysisLimits = AnalysisLimits(),
    ) = AnalyzeFileUseCase(stager, FakeIdentifier(format), engines.toSet(), FakeRuleEngine(), history, FakePreferences(limits))

    private fun file(name: String, bytes: ByteArray = ByteArray(16) { it.toByte() }): String =
        File(temp.root, name).apply { writeBytes(bytes) }.absolutePath

    private suspend fun runAndGetVerdict(uc: AnalyzeFileUseCase, uri: String): Verdict {
        val events = uc(uri).toList()
        val id = (events.last() as ScanEvent.Completed).recordId
        return history.getRecord(id)!!.verdict
    }

    @Test
    fun inaccessibleFile_isAnalysisError_neverSafe() = runTest {
        val stager = FakeFileStager(temp.newFolder()).apply { inaccessible = true }
        val verdict = runAndGetVerdict(useCase(FileFormat.ZIP, stager = stager), file("x.zip"))
        assertEquals(Verdict.ANALYSIS_ERROR, verdict)
    }

    @Test
    fun missingFile_isAnalysisError() = runTest {
        val verdict = runAndGetVerdict(useCase(FileFormat.ZIP), File(temp.root, "nao-existe.zip").absolutePath)
        assertEquals(Verdict.ANALYSIS_ERROR, verdict)
    }

    @Test
    fun fileAboveLimit_isInconclusive_andNotHashed() = runTest {
        val big = file("grande.bin", ByteArray(2 * 1024 * 1024))
        val uc = useCase(FileFormat.UNKNOWN, limits = AnalysisLimits(maxFileSizeMb = 1))
        val record = history.getRecord((uc(big).toList().last() as ScanEvent.Completed).recordId)!!
        assertEquals(Verdict.INCONCLUSIVE, record.verdict)
        assertTrue(record.sha256.isEmpty())
    }

    @Test
    fun emptyFile_isInconclusive() = runTest {
        val engine = FakeEngine("zip", setOf(FileFormat.UNKNOWN)) { EngineResult.Completed() }
        assertEquals(Verdict.INCONCLUSIVE, runAndGetVerdict(useCase(FileFormat.UNKNOWN, engine), file("vazio", ByteArray(0))))
    }

    @Test
    fun unsupportedFormat_isInconclusive_evenWithoutFindings() = runTest {
        val generic = FakeEngine("eicar", FileFormat.entries.toSet(), structural = false) { EngineResult.Completed() }
        assertEquals(Verdict.INCONCLUSIVE, runAndGetVerdict(useCase(FileFormat.UNKNOWN, generic), file("sem-extensao")))
    }

    @Test
    fun crashingEngine_isRecordedAsFailure_andNeverSafe() = runTest {
        val crash = FakeEngine("zip", setOf(FileFormat.ZIP)) { error("estrutura inesperada") }
        val events = useCase(FileFormat.ZIP, crash)(file("quebrado.zip")).toList()
        val record = history.getRecord((events.last() as ScanEvent.Completed).recordId)!!
        assertNotEquals(Verdict.SAFE_BY_CHECKS, record.verdict)
        assertEquals(EngineStatus.FAILED, record.report!!.engines.single().status)
    }

    @Test
    fun completedStructuralAnalysis_withoutFindings_isSafeByChecks_withDisclaimer() = runTest {
        val engine = FakeEngine("zip", setOf(FileFormat.ZIP)) { EngineResult.Completed() }
        val events = useCase(FileFormat.ZIP, engine)(file("ok.zip")).toList()
        val record = history.getRecord((events.last() as ScanEvent.Completed).recordId)!!
        assertEquals(Verdict.SAFE_BY_CHECKS, record.verdict)
        assertTrue(record.report!!.explanation.any { it.contains("Nenhuma verificação garante") })
    }

    @Test
    fun highSeverityFinding_isSuspicious_andConfirmedSignature_isThreat() = runTest {
        val high = FakeEngine("zip", setOf(FileFormat.ZIP)) { EngineResult.Completed(facts = listOf(MarkerFact(Severity.HIGH))) }
        assertEquals(Verdict.SUSPICIOUS, runAndGetVerdict(useCase(FileFormat.ZIP, high), file("a.zip")))
        val eicar = FakeEngine("sig", setOf(FileFormat.ZIP)) { EngineResult.Completed(facts = listOf(MarkerFact(Severity.CRITICAL, confirms = true))) }
        assertEquals(Verdict.THREAT_DETECTED, runAndGetVerdict(useCase(FileFormat.ZIP, eicar), file("b.zip")))
    }

    @Test
    fun steps_areReportedInRealOrder_andOnlineStepIsSkipped() = runTest {
        val engine = FakeEngine("zip", setOf(FileFormat.ZIP)) { EngineResult.Completed() }
        val events = useCase(FileFormat.ZIP, engine)(file("ordem.zip")).toList()
        val steps = events.filterIsInstance<ScanEvent.Progress>().map { it.step }.distinct()
        assertEquals(listOf(ScanStep.IDENTIFYING, ScanStep.HASHING, ScanStep.INSPECTING, ScanStep.CHECKING_INDICATORS, ScanStep.FINALIZING), steps)
        assertTrue(events.contains(ScanEvent.StepSkipped(ScanStep.ONLINE_REPUTATION)))
    }

    @Test
    fun cancellationDuringAnalysis_savesNothing_andReleasesCopy() = runTest {
        val started = CompletableDeferred<Unit>()
        val stager = FakeFileStager(temp.newFolder())
        val slow = FakeEngine("zip", setOf(FileFormat.ZIP)) {
            started.complete(Unit)
            awaitCancellation()
        }
        val job = launch { useCase(FileFormat.ZIP, slow, stager = stager)(file("lento.zip")).toList() }
        started.await()
        job.cancel()
        job.join()
        assertTrue(history.records.value.isEmpty())
        assertEquals(1, stager.released.size)
        assertTrue(stager.released.none { it.exists() })
    }
}
