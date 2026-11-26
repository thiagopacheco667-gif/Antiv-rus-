package com.aegis.security.domain.usecase

import com.aegis.security.domain.analysis.AnalysisEngine
import com.aegis.security.domain.analysis.AnalysisInput
import com.aegis.security.domain.analysis.EngineDescriptor
import com.aegis.security.domain.analysis.EngineResult
import com.aegis.security.domain.model.FileFormat
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GetScannerStatusUseCaseTest {

    @Test
    fun noRegisteredEngines_meansScannerIsNotOperational() {
        val status = GetScannerStatusUseCase(emptySet())()

        assertFalse(status.isOperational)
        assertTrue(status.supportedFormats.isEmpty())
    }

    @Test
    fun registeredEngines_defineSupportedFormats() {
        val status = GetScannerStatusUseCase(
            setOf(
                StubEngine("zip", setOf(FileFormat.ZIP, FileFormat.JAR)),
                StubEngine("apk", setOf(FileFormat.APK)),
            ),
        )()

        assertTrue(status.isOperational)
        assertEquals(setOf(FileFormat.ZIP, FileFormat.JAR, FileFormat.APK), status.supportedFormats)
        assertEquals(listOf("apk", "zip"), status.engines.map { it.id })
    }

    @Test(expected = IllegalArgumentException::class)
    fun duplicatedEngineIds_areRejected() {
        GetScannerStatusUseCase(
            setOf(StubEngine("dup", setOf(FileFormat.PDF)), StubEngine("dup", setOf(FileFormat.ELF))),
        )()
    }

    /** Usado apenas para descrever o registro; [analyze] não é exercitado nestes testes. */
    private class StubEngine(id: String, formats: Set<FileFormat>) : AnalysisEngine {
        override val descriptor = EngineDescriptor(id = id, displayName = id, supportedFormats = formats)
        override suspend fun analyze(input: AnalysisInput): EngineResult = EngineResult.NotApplicable
    }
}
