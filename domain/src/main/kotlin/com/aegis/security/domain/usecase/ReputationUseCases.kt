package com.aegis.security.domain.usecase

import com.aegis.security.domain.analysis.Classification
import com.aegis.security.domain.analysis.ExecutablePartExtractor
import com.aegis.security.domain.analysis.ExtractedPart
import com.aegis.security.domain.analysis.RiskClassifier
import com.aegis.security.domain.model.AnalysisReport
import com.aegis.security.domain.model.OnlineReputation
import com.aegis.security.domain.model.PartReputation
import com.aegis.security.domain.model.ReputationFailure
import com.aegis.security.domain.model.ScanRecord
import com.aegis.security.domain.repository.FileStager
import com.aegis.security.domain.repository.ReputationRepository
import com.aegis.security.domain.repository.ScanHistoryRepository
import com.aegis.security.domain.repository.UploadOutcome
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import java.io.File
import java.security.DigestInputStream
import java.security.MessageDigest
import javax.inject.Inject

class ObserveScanRecordUseCase @Inject constructor(
    private val history: ScanHistoryRepository,
) {
    operator fun invoke(id: Long): Flow<ScanRecord?> = history.observeRecord(id)
}

/** Reclassifica com todas as evidências externas (arquivo inteiro e partes) e persiste. */
internal suspend fun ScanHistoryRepository.applyReputation(
    record: ScanRecord,
    online: OnlineReputation = record.report!!.online,
    parts: List<PartReputation> = record.report!!.parts,
): ScanRecord {
    val report = requireNotNull(record.report) { "Registro sem relatório" }
    val local = Classification(report.localVerdict, report.localExplanation)
    val combined = RiskClassifier.combineParts(RiskClassifier.combine(local, online), parts)
    val updatedReport: AnalysisReport = report.copy(
        online = online,
        parts = parts,
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
        history.applyReputation(record, online = online)
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
        if (online is OnlineReputation.Failed && report.online is OnlineReputation.Found) return online
        if (online is OnlineReputation.Failed && online.kind == ReputationFailure.HASH_MISMATCH) return online
        history.applyReputation(record, online = online)
        return online
    }
}

/** Partes extraídas e mantidas no cache privado até o envio ou o descarte. */
class PartsSession internal constructor(
    val workDir: File,
    val parts: List<ExtractedPart>,
)

class FileMismatchException : IllegalStateException("o arquivo selecionado é diferente do analisado (SHA-256 não confere)")

/**
 * APKs grandes ou desconhecidos: extrai somente o código executável, confere que o arquivo
 * selecionado é o mesmo analisado (SHA-256) e consulta o hash de cada parte. Exige consentimento.
 */
class InspectExecutablePartsUseCase @Inject constructor(
    private val history: ScanHistoryRepository,
    private val reputation: ReputationRepository,
    private val stager: FileStager,
    private val extractor: ExecutablePartExtractor,
) {
    sealed interface Progress {
        data class Extracting(val part: String) : Progress
        data class Checking(val index: Int, val total: Int, val part: String) : Progress
    }

    suspend operator fun invoke(recordId: Long, uri: String, onProgress: (Progress) -> Unit): PartsSession {
        val record = history.getRecord(recordId) ?: error("Registro $recordId não encontrado")
        val expected = record.report?.hashes?.sha256 ?: error("Registro sem hash")
        val workDir = stager.newWorkDir()
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            val parts = withContext(Dispatchers.IO) {
                stager.open(uri).use { raw ->
                    val hashing = DigestInputStream(raw, digest)
                    val extracted = extractor.extract(hashing, workDir, MAX_UPLOAD_BYTES) { onProgress(Progress.Extracting(it)) }
                    // Consome o restante para concluir o hash do arquivo inteiro.
                    val buffer = ByteArray(64 * 1024)
                    while (hashing.read(buffer) >= 0) Unit
                    extracted
                }
            }
            val actual = digest.digest().joinToString("") { "%02x".format(it) }
            if (!actual.equals(expected, ignoreCase = true)) throw FileMismatchException()

            val results = parts.mapIndexed { index, part ->
                onProgress(Progress.Checking(index + 1, parts.size, part.name))
                PartReputation(part.name, part.sizeBytes, part.sha256, reputation.lookup(part.sha256))
            }
            history.applyReputation(history.getRecord(recordId) ?: record, parts = results)
            return PartsSession(workDir, parts)
        } catch (error: Throwable) {
            stager.deleteWorkDir(workDir)
            throw error
        }
    }

    companion object {
        const val MAX_UPLOAD_BYTES = 650L * 1024 * 1024
    }
}

/** Envia as partes desconhecidas pelo VirusTotal. Exige confirmação separada, coletada pela UI. */
class UploadUnknownPartsUseCase @Inject constructor(
    private val history: ScanHistoryRepository,
    private val reputation: ReputationRepository,
    private val stager: FileStager,
) {
    suspend operator fun invoke(
        recordId: Long,
        session: PartsSession,
        onProgress: (index: Int, total: Int, part: String, fraction: Float) -> Unit,
        nowMillis: () -> Long = System::currentTimeMillis,
    ): List<PartReputation> {
        try {
            val record = history.getRecord(recordId) ?: error("Registro $recordId não encontrado")
            val current = record.report?.parts.orEmpty()
            val pending = session.parts.filter { part ->
                part.file != null && current.firstOrNull { it.sha256 == part.sha256 }?.online is OnlineReputation.NotFound
            }
            val updated = current.toMutableList()
            pending.forEachIndexed { index, part ->
                val outcome = reputation.uploadPart(part.file!!, part.name, part.sha256) { onProgress(index + 1, pending.size, part.name, it) }
                val online = when (outcome) {
                    is UploadOutcome.Failed -> OnlineReputation.Failed(outcome.kind, outcome.message, nowMillis())
                    is UploadOutcome.Accepted -> reputation.awaitAnalysis(outcome.analysisId, part.sha256) {}
                }
                val position = updated.indexOfFirst { it.sha256 == part.sha256 }
                if (position >= 0) updated[position] = updated[position].copy(online = online)
            }
            history.applyReputation(history.getRecord(recordId) ?: record, parts = updated)
            return updated
        } finally {
            stager.deleteWorkDir(session.workDir)
        }
    }
}

/** Descarta as partes extraídas sem enviar nada. */
class DiscardPartsUseCase @Inject constructor(private val stager: FileStager) {
    operator fun invoke(session: PartsSession) = stager.deleteWorkDir(session.workDir)
}
