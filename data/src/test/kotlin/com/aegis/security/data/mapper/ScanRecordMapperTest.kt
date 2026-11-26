package com.aegis.security.data.mapper

import com.aegis.security.core.database.model.ScanRecordEntity
import com.aegis.security.domain.model.AnalysisOrigin
import com.aegis.security.domain.model.FileFormat
import com.aegis.security.domain.model.ScanRecord
import com.aegis.security.domain.model.Verdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class ScanRecordMapperTest {

    @Test
    fun roundTrip_preservesAllFields() {
        val record = ScanRecord(
            id = 7,
            fileName = "relatorio.pdf",
            sha256 = "a".repeat(64),
            format = FileFormat.PDF,
            sizeBytes = 2048,
            scannedAtEpochMillis = 1_700_000_000_000,
            verdict = Verdict.SUSPICIOUS,
            origin = AnalysisOrigin.LOCAL,
            evidenceSummary = "JavaScript embutido",
        )

        assertEquals(record, record.asEntity().asDomain())
    }

    @Test
    fun unreadableVerdict_isNeverMappedToSafe() {
        val mapped = entity(verdict = "VALOR_CORROMPIDO").asDomain()

        assertEquals(Verdict.INCONCLUSIVE, mapped.verdict)
        assertNotEquals(Verdict.SAFE_BY_CHECKS, mapped.verdict)
    }

    @Test
    fun unknownFormatAndOrigin_fallBackToUnknown() {
        val mapped = entity(format = "XYZ", origin = "OUTRA").asDomain()

        assertEquals(FileFormat.UNKNOWN, mapped.format)
        assertEquals(AnalysisOrigin.UNKNOWN, mapped.origin)
    }

    private fun entity(
        verdict: String = "INCONCLUSIVE",
        format: String = "UNKNOWN",
        origin: String = "LOCAL",
    ) = ScanRecordEntity(
        id = 1,
        fileName = "x",
        sha256 = "0".repeat(64),
        format = format,
        sizeBytes = null,
        scannedAtEpochMillis = 0,
        verdict = verdict,
        origin = origin,
        evidenceSummary = "",
    )
}
