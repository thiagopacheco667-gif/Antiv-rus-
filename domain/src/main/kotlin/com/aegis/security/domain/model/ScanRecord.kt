package com.aegis.security.domain.model

/**
 * Registro de histórico de uma análise concluída.
 * Contém apenas metadados — nunca uma cópia do arquivo analisado.
 */
data class ScanRecord(
    val id: Long = 0,
    val fileName: String,
    val sha256: String,
    val format: FileFormat,
    val sizeBytes: Long?,
    val scannedAtEpochMillis: Long,
    val verdict: Verdict,
    val origin: AnalysisOrigin,
    val evidenceSummary: String,
)
