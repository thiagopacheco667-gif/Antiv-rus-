package com.aegis.security.data.mapper

import com.aegis.security.core.database.model.ScanRecordEntity
import com.aegis.security.domain.model.AnalysisOrigin
import com.aegis.security.domain.model.AnalysisReport
import com.aegis.security.domain.model.FileFormat
import com.aegis.security.domain.model.ScanRecord
import com.aegis.security.domain.model.Verdict
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

internal inline fun <reified T : Enum<T>> String.toEnumOrNull(): T? =
    enumValues<T>().firstOrNull { it.name == this }

internal val ReportJson = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
}

internal fun decodeReport(json: String?): AnalysisReport? = json?.let {
    try {
        ReportJson.decodeFromString(AnalysisReport.serializer(), it)
    } catch (error: SerializationException) {
        null
    } catch (error: IllegalArgumentException) {
        null
    }
}

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
    report = decodeReport(reportJson),
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
    reportJson = report?.let { ReportJson.encodeToString(AnalysisReport.serializer(), it) },
)
