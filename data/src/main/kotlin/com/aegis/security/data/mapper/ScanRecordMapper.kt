package com.aegis.security.data.mapper

import com.aegis.security.core.database.model.ScanRecordEntity
import com.aegis.security.domain.model.AnalysisOrigin
import com.aegis.security.domain.model.FileFormat
import com.aegis.security.domain.model.ScanRecord
import com.aegis.security.domain.model.Verdict

internal inline fun <reified T : Enum<T>> String.toEnumOrNull(): T? =
    enumValues<T>().firstOrNull { it.name == this }

/**
 * Converte a linha persistida para o modelo de domínio.
 *
 * Um veredito ilegível (dado corrompido ou de versão futura) vira [Verdict.INCONCLUSIVE]:
 * o app nunca deve exibir "seguro" a partir de um valor que não conseguiu interpretar.
 */
internal fun ScanRecordEntity.asDomain(): ScanRecord = ScanRecord(
    id = id,
    fileName = fileName,
    sha256 = sha256,
    format = format.toEnumOrNull<FileFormat>() ?: FileFormat.UNKNOWN,
    sizeBytes = sizeBytes,
    scannedAtEpochMillis = scannedAtEpochMillis,
    verdict = verdict.toEnumOrNull<Verdict>() ?: Verdict.INCONCLUSIVE,
    origin = origin.toEnumOrNull<AnalysisOrigin>() ?: AnalysisOrigin.UNKNOWN,
    evidenceSummary = evidenceSummary,
)

internal fun ScanRecord.asEntity(): ScanRecordEntity = ScanRecordEntity(
    id = id,
    fileName = fileName,
    sha256 = sha256,
    format = format.name,
    sizeBytes = sizeBytes,
    scannedAtEpochMillis = scannedAtEpochMillis,
    verdict = verdict.name,
    origin = origin.name,
    evidenceSummary = evidenceSummary,
)
