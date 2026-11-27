package com.aegis.security.core.security

import com.aegis.security.core.security.rules.ArchiveRules
import com.aegis.security.core.security.rules.DefaultRuleEngine
import com.aegis.security.core.security.testing.TestFiles
import com.aegis.security.core.security.testing.TestFiles.ZipSpec
import com.aegis.security.core.security.zip.ZipEngine
import com.aegis.security.core.security.zip.ZipFacts
import com.aegis.security.domain.analysis.EngineResult
import com.aegis.security.domain.model.AnalysisLimits
import com.aegis.security.domain.model.FileFormat
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ZipEngineTest {
    @get:Rule
    val temp = TemporaryFolder()
    private val engine = ZipEngine()
    private val rules = DefaultRuleEngine(setOf(ArchiveRules()))

    private suspend fun facts(bytes: ByteArray, limits: AnalysisLimits = AnalysisLimits()): ZipFacts {
        val file = temp.newFile().apply { writeBytes(bytes) }
        val result = engine.analyze(TestFiles.input(file, FileFormat.ZIP, limits))
        return (result as EngineResult.Completed).facts.single() as ZipFacts
    }

    @Test
    fun validZip_hasNoIndicators() = runTest {
        val facts = facts(TestFiles.zip(listOf(ZipSpec("docs/leia-me.txt", "olá".toByteArray()), ZipSpec("foto.jpg", ByteArray(64)))))
        assertEquals(2, facts.entryCount)
        assertTrue(rules.evaluate(listOf(facts)).isEmpty())
    }

    @Test
    fun suspiciousStructure_isDetected() = runTest {
        val facts = facts(
            TestFiles.zip(
                listOf(
                    ZipSpec("../../etc/evil.txt", "x".toByteArray()),
                    ZipSpec("/abs/path.txt", "x".toByteArray()),
                    ZipSpec("fatura.pdf.exe", ByteArray(4)),
                    ZipSpec("duplicado.txt", "1".toByteArray()),
                    ZipSpec("duplicado.txt", "2".toByteArray()),
                    ZipSpec("foto‮gpj.scr", ByteArray(4)),
                ),
            ),
        )
        assertEquals(listOf("../../etc/evil.txt"), facts.traversalEntries)
        assertEquals(listOf("/abs/path.txt"), facts.absolutePathEntries)
        assertEquals(listOf("fatura.pdf.exe"), facts.doubleExtensionEntries)
        assertEquals(listOf("duplicado.txt"), facts.duplicateEntries)
        assertEquals(1, facts.misleadingNameEntries.size)
        val ids = rules.evaluate(listOf(facts)).map { it.ruleId }.toSet()
        assertTrue(ids.containsAll(setOf("AEGIS-ZIP-001", "AEGIS-ZIP-003", "AEGIS-ZIP-004", "AEGIS-ZIP-005", "AEGIS-ZIP-006")))
    }

    @Test
    fun highCompressionRatio_isFlaggedAsZipBomb_withoutExtracting() = runTest {
        val zeros = ByteArray(8 * 1024 * 1024)
        val facts = facts(TestFiles.zip(listOf(ZipSpec("zeros.bin", zeros, deflate = true))))
        assertTrue(facts.bombIndicators.isNotEmpty())
        assertTrue(rules.evaluate(listOf(facts)).any { it.ruleId == "AEGIS-ZIP-002" })
    }

    @Test
    fun declaredSizeAboveLimit_isFlagged() = runTest {
        val bytes = TestFiles.zip(listOf(ZipSpec("mentira.bin", "pequeno".toByteArray(), declaredSize = 3L * 1024 * 1024 * 1024)))
        val facts = facts(bytes, AnalysisLimits(maxTotalUncompressedMb = 256))
        assertTrue(facts.bombIndicators.any { it.contains("acima do limite") })
    }

    @Test
    fun nestedArchive_isInspected_andDepthLimitIsRespected() = runTest {
        val inner = TestFiles.zip(listOf(ZipSpec("../escape.txt", "x".toByteArray())))
        val outer = TestFiles.zip(listOf(ZipSpec("interno.zip", inner, deflate = true)))
        val deep = facts(outer)
        assertEquals(listOf("interno.zip!/../escape.txt"), deep.traversalEntries)
        val shallow = facts(outer, AnalysisLimits(maxNestingDepth = 0))
        assertTrue(shallow.nestingLimitReached)
        assertTrue(shallow.traversalEntries.isEmpty())
    }

    @Test
    fun zipBombInsideNestedArchive_isDetected() = runTest {
        val inner = TestFiles.zip(listOf(ZipSpec("zeros.bin", ByteArray(4 * 1024 * 1024), deflate = true)))
        val outer = TestFiles.zip(listOf(ZipSpec("bomba.zip", inner, deflate = true)))
        val facts = facts(outer, AnalysisLimits(maxCompressionRatio = 20))
        assertTrue(facts.bombIndicators.isNotEmpty())
    }

    @Test
    fun malformedZip_failsInsteadOfReportingClean() = runTest {
        val file = temp.newFile().apply { writeBytes(byteArrayOf(0x50, 0x4B, 0x03, 0x04) + ByteArray(40) { 7 }) }
        val result = engine.analyze(TestFiles.input(file, FileFormat.ZIP))
        assertTrue(result is EngineResult.Failed)
    }

    @Test
    fun entryLimit_isEnforced() = runTest {
        val many = (1..30).map { ZipSpec("f$it.txt", "x".toByteArray()) }
        val facts = facts(TestFiles.zip(many), AnalysisLimits(maxArchiveEntries = 10))
        assertTrue(facts.entryLimitExceeded)
        assertEquals(10, facts.entryCount)
    }

    @Test
    fun limitsReached_markInspectionIncomplete() = runTest {
        val file = temp.newFile().apply { writeBytes(TestFiles.zip((1..30).map { ZipSpec("f$it.txt", "x".toByteArray()) })) }
        val result = engine.analyze(TestFiles.input(file, FileFormat.ZIP, AnalysisLimits(maxArchiveEntries = 10))) as EngineResult.Completed
        assertTrue(result.incomplete.isNotEmpty())
    }

    @Test
    fun standardApkCode_isNotFlaggedAsEmbeddedExecutable() = runTest {
        val facts = facts(TestFiles.zip(listOf(ZipSpec("classes.dex", ByteArray(8)), ZipSpec("lib/arm64-v8a/libmain.so", ByteArray(8)), ZipSpec("assets/extra.exe", ByteArray(8)))))
        val common = com.aegis.security.domain.analysis.CommonFacts("jogo.apk", "apk", FileFormat.APK, 100)
        val finding = rules.evaluate(listOf(facts, common)).single { it.ruleId == "AEGIS-ZIP-003" }
        assertEquals("assets/extra.exe", finding.evidence)
    }
}
