package com.aegis.security.domain.usecase

import com.aegis.security.domain.analysis.Classification
import com.aegis.security.domain.analysis.RiskClassifier
import com.aegis.security.domain.model.AnalysisReport
import com.aegis.security.domain.model.OnlineReputation
import com.aegis.security.domain.model.ReputationFailure
import com.aegis.security.domain.model.ScanRecord
import com.aegis.security.domain.repository.ReputationRepository
import com.aegis.security.domain.repository.ScanHistoryRepository
import com.aegis.security.domain.repository.UploadOutcome
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class ObserveScanRecordUseCase @Inject constructor(
    private val history: ScanHistoryRepository,
) {
    operator fun invoke(id: Long): Flow<ScanRecord?> = history.observeRecord(id)
}

/** Reaplica a classificação com o novo resultado online e persiste no histórico. */
internal suspend fun ScanHistoryRepository.applyOnlineResult(record: ScanRecord, online: OnlineReputation): ScanRecord {
    val report = requireNotNull(record.report) { "Registro sem relatório" }
    val local = Classification(report.localVerdict, report.localExplanation)
    val combined = RiskClassifier.combine(local, online)
    val updatedReport: AnalysisReport = report.copy(
        online = online,
        verdict = combined.verdict,
        explanation = combined.reasons,
    )
    val updated = updatedReport.toRecord(id = record.id)
    update(updated)
    return updated
}

/** Consulta de reputação por hash. Exige consentimento prévio, coletado pela UI. */
class LookupReputationUseCase @Inject constructor(
    private val history: ScanHistoryRepository,
    private val reputation: ReputationRepository,
) {
    suspend operator fun invoke(recordId: Long): OnlineReputation {
        val record = history.getRecord(recordId) ?: error("Registro $recordId não encontrado")
        val sha256 = record.report?.hashes?.sha256 ?: error("Registro sem hash")
        val online = reputation.lookup(sha256)
        history.applyOnlineResult(record, online)
        return online
    }
}

/** Upload do arquivo completo. Exige confirmação separada e explícita, coletada pela UI. */
class UploadForAnalysisUseCase @Inject constructor(
    private val history: ScanHistoryRepository,
    private val reputation: ReputationRepository,
) {
    suspend operator fun invoke(
        recordId: Long,
        uri: String,
        onUploadProgress: (Float) -> Unit,
        onStatus: (String) -> Unit,
        nowMillis: () -> Long = System::currentTimeMillis,
    ): OnlineReputation {
        val record = history.getRecord(recordId) ?: error("Registro $recordId não encontrado")
        val report = record.report ?: error("Registro sem relatório")
        val sha256 = report.hashes?.sha256 ?: error("Registro sem hash")
        val online = when (val upload = reputation.upload(uri, record.fileName, sha256, onUploadProgress)) {
            is UploadOutcome.Failed -> OnlineReputation.Failed(upload.kind, upload.message, nowMillis())
            is UploadOutcome.Accepted -> reputation.awaitAnalysis(upload.analysisId, sha256, onStatus)
        }
        // Falhas de upload não sobrescrevem um resultado online já obtido anteriormente.
        val previous = report.online
        if (online is OnlineReputation.Failed && previous is OnlineReputation.Found) return online
        if (online is OnlineReputation.Failed && online.kind == ReputationFailure.HASH_MISMATCH) return online
        history.applyOnlineResult(record, online)
        return online
    }
}
