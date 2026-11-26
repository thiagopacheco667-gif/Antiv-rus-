package com.aegis.security.core.security

import com.aegis.security.core.security.elf.ElfEngine
import com.aegis.security.core.security.elf.ElfFacts
import com.aegis.security.core.security.pe.PeEngine
import com.aegis.security.core.security.pe.PeFacts
import com.aegis.security.core.security.rules.BinaryRules
import com.aegis.security.core.security.rules.DefaultRuleEngine
import com.aegis.security.core.security.testing.TestFiles
import com.aegis.security.domain.analysis.EngineResult
import com.aegis.security.domain.model.FileFormat
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class BinaryEnginesTest {
    @get:Rule
    val temp = TemporaryFolder()
    private val rules = DefaultRuleEngine(setOf(BinaryRules()))

    private suspend fun pe(bytes: ByteArray): PeFacts {
        val file = temp.newFile("a.exe").also { it.writeBytes(bytes) }
        return (PeEngine().analyze(TestFiles.input(file, FileFormat.PE_EXECUTABLE)) as EngineResult.Completed).facts.single() as PeFacts
    }

    @Test
    fun validPe_isParsed_withoutIndicators() = runTest {
        val facts = pe(TestFiles.pe())
        assertEquals("x86 (i386)", facts.machine)
        assertEquals(".text", facts.entrySection)
        assertEquals(1, facts.sections.size)
        assertTrue(facts.inconsistencies.isEmpty())
        assertTrue(rules.evaluate(listOf(facts)).isEmpty())
    }

    @Test
    fun writableExecutableSection_andPackerName_areFlagged() = runTest {
        val facts = pe(TestFiles.pe(sectionCharacteristics = 0xE0000020, sectionName = "UPX1"))
        val ids = rules.evaluate(listOf(facts)).map { it.ruleId }
        assertTrue("AEGIS-PE-001" in ids)
        assertTrue("AEGIS-PE-003" in ids)
    }

    @Test
    fun entryPointOutsideSections_isInconsistent() = runTest {
        val facts = pe(TestFiles.pe(entryRva = 0x9000))
        assertTrue(facts.inconsistencies.isNotEmpty())
        assertTrue(rules.evaluate(listOf(facts)).any { it.ruleId == "AEGIS-PE-004" })
    }

    @Test
    fun truncatedPe_failsInsteadOfReportingClean() = runTest {
        val file = temp.newFile("t.exe").also { it.writeBytes(TestFiles.pe().copyOf(0x90)) }
        assertTrue(PeEngine().analyze(TestFiles.input(file, FileFormat.PE_EXECUTABLE)) is EngineResult.Failed)
    }

    @Test
    fun elf_executableStackAndMissingSections_areFlagged() = runTest {
        val file = temp.newFile("bin").also { it.writeBytes(TestFiles.elf64(stackFlags = 7)) }
        val facts = (ElfEngine().analyze(TestFiles.input(file, FileFormat.ELF)) as EngineResult.Completed).facts.single() as ElfFacts
        assertEquals("x86-64", facts.machine)
        assertTrue(facts.executableStack)
        val ids = rules.evaluate(listOf(facts)).map { it.ruleId }
        assertTrue("AEGIS-ELF-001" in ids)
        assertTrue("AEGIS-ELF-003" in ids)
    }

    @Test
    fun elf_nonExecutableStack_isNotFlagged() = runTest {
        val file = temp.newFile("ok").also { it.writeBytes(TestFiles.elf64(stackFlags = 6)) }
        val facts = (ElfEngine().analyze(TestFiles.input(file, FileFormat.ELF)) as EngineResult.Completed).facts.single() as ElfFacts
        assertFalse(facts.executableStack)
    }
}
