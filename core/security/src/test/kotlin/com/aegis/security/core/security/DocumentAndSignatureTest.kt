package com.aegis.security.core.security

import com.aegis.security.core.security.pdf.PdfEngine
import com.aegis.security.core.security.pdf.PdfFacts
import com.aegis.security.core.security.rules.DefaultRuleEngine
import com.aegis.security.core.security.rules.DocumentRules
import com.aegis.security.core.security.rules.GeneralRules
import com.aegis.security.core.security.signature.EicarEngine
import com.aegis.security.core.security.signature.SignatureFacts
import com.aegis.security.core.security.testing.TestFiles
import com.aegis.security.domain.analysis.CommonFacts
import com.aegis.security.domain.analysis.EngineResult
import com.aegis.security.domain.analysis.Severity
import com.aegis.security.domain.model.FileFormat
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class DocumentAndSignatureTest {
    @get:Rule
    val temp = TemporaryFolder()

    private suspend fun pdf(text: ByteArray): PdfFacts {
        val file = temp.newFile("doc.pdf").also { it.writeBytes(text) }
        return (PdfEngine().analyze(TestFiles.input(file, FileFormat.PDF)) as EngineResult.Completed).facts.single() as PdfFacts
    }

    @Test
    fun plainPdf_hasMetadata_andNoActiveContent() = runTest {
        val facts = pdf("%PDF-1.7\n1 0 obj << /Title (Relatório anual) /Producer (Teste) >> endobj\n%%EOF\n".toByteArray(Charsets.ISO_8859_1))
        assertEquals("1.7", facts.version)
        assertEquals("Relatório anual", facts.metadata["Title"])
        assertEquals(1, facts.eofMarkers)
        assertTrue(DefaultRuleEngine(setOf(DocumentRules())).evaluate(listOf(facts)).isEmpty())
    }

    @Test
    fun javascriptWithOpenAction_andObfuscatedNames_areHighSeverity() = runTest {
        val facts = pdf("%PDF-1.4\n1 0 obj << /OpenAction 2 0 R >> endobj\n2 0 obj << /S /J#61vaScript /JS (app.alert(1)) >> endobj\n%%EOF".toByteArray())
        assertEquals(listOf("JavaScript"), facts.obfuscatedNames)
        val findings = DefaultRuleEngine(setOf(DocumentRules())).evaluate(listOf(facts))
        assertEquals(Severity.HIGH, findings.first { it.ruleId == "AEGIS-PDF-001" }.severity)
        assertTrue(findings.any { it.ruleId == "AEGIS-PDF-005" })
    }

    @Test
    fun compressedObjectStreams_areInspected() = runTest {
        val hidden = TestFiles.zlib("<< /Launch << /F (cmd.exe) >> >>".toByteArray())
        val bytes = "%PDF-1.5\n3 0 obj << /Type /ObjStm /Filter /FlateDecode /Length ${hidden.size} >>\nstream\n".toByteArray() +
            hidden + "\nendstream\nendobj\n%%EOF".toByteArray()
        val facts = pdf(bytes)
        assertEquals(1, facts.objectStreamsInspected)
        assertEquals(1, facts.count("Launch"))
    }

    @Test
    fun eicarTestFile_isConfirmedThreat_onlyWhenExact() = runTest {
        val eicar = temp.newFile("eicar.com").also { it.writeBytes(EicarEngine.EICAR + "\r\n".toByteArray()) }
        val result = EicarEngine().analyze(TestFiles.input(eicar, FileFormat.UNKNOWN)) as EngineResult.Completed
        val finding = DefaultRuleEngine(setOf(GeneralRules())).evaluate(result.facts).single { it.ruleId == "AEGIS-GEN-001" }
        assertTrue(finding.confirmsThreat)

        val embedded = temp.newFile("texto.txt").also { it.writeBytes("prefixo ".toByteArray() + EicarEngine.EICAR) }
        assertFalse(EicarEngine.isEicar(embedded))
    }

    @Test
    fun fakeExtension_executableDisguisedAsDocument_isHigh() {
        val findings = DefaultRuleEngine(setOf(GeneralRules())).evaluate(
            listOf(CommonFacts("foto.jpg", "jpg", FileFormat.PE_EXECUTABLE, 100), SignatureFacts(false)),
        )
        assertEquals(Severity.HIGH, findings.single { it.ruleId == "AEGIS-GEN-002" }.severity)
    }

    @Test
    fun fileWithoutExtension_hasNoExtensionFinding() {
        val findings = DefaultRuleEngine(setOf(GeneralRules())).evaluate(listOf(CommonFacts("binario", null, FileFormat.ELF, 100)))
        assertTrue(findings.none { it.ruleId == "AEGIS-GEN-002" })
    }

    @Test
    fun doubleExtensionName_isFlagged() {
        val findings = DefaultRuleEngine(setOf(GeneralRules())).evaluate(listOf(CommonFacts("boleto.pdf.exe", "exe", FileFormat.PE_EXECUTABLE, 100)))
        assertTrue(findings.any { it.ruleId == "AEGIS-GEN-003" })
    }
}
