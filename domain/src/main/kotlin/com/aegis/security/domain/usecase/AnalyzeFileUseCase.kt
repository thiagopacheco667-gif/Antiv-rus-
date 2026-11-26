package com.aegis.security.domain.usecase

import com.aegis.security.domain.analysis.AnalysisEngine
import com.aegis.security.domain.analysis.AnalysisFact
import com.aegis.security.domain.analysis.AnalysisInput
import com.aegis.security.domain.analysis.Classification
import com.aegis.security.domain.analysis.CommonFacts
import com.aegis.security.domain.analysis.EngineResult
import com.aegis.security.domain.analysis.Finding
import com.aegis.security.domain.analysis.FormatIdentifier
import com.aegis.security.domain.analysis.RiskClassifier
import com.aegis.security.domain.analysis.RuleEngine
import com.aegis.security.domain.analysis.ScanEvent
import com.aegis.security.domain.analysis.ScanStep
import com.aegis.security.domain.model.AnalysisOrigin
import com.aegis.security.domain.model.AnalysisReport
import com.aegis.security.domain.model.EngineOutcome
import com.aegis.security.domain.model.EngineStatus
import com.aegis.security.domain.model.FileFormat
import com.aegis.security.domain.model.FileMetadata
import com.aegis.security.domain.model.OnlineReputation
import com.aegis.security.domain.model.ScanRecord
import com.aegis.security.domain.model.Verdict
import com.aegis.security.domain.repository.FileAccessException
import com.aegis.security.domain.repository.FileStager
import com.aegis.security.domain.repository.FileTooLargeException
import com.aegis.security.domain.repository.ScanHistoryRepository
import com.aegis.security.domain.repository.StagedFile
import com.aegis.security.domain.repository.UserPreferencesRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOn
import java.io.IOException
import javax.inject.Inject

/**
 * Orquestra a análise local: identificação → hash → inspeção estrutural → regras → relatório.
 * Executa fora da thread principal, é cancelável a qualquer momento e sempre remove a cópia
 * temporária do arquivo. A consulta online nunca é feita aqui (exige consentimento posterior).
 */
class AnalyzeFileUseCase @Inject constructor(
    private val stager: FileStager,
    private val identifier: FormatIdentifier,
    private val engines: Set<@JvmSuppressWildcards AnalysisEngine>,
    private val ruleEngine: RuleEngine,
    private val history: ScanHistoryRepository,
    private val preferences: UserPreferencesRepository,
) {
    operator fun invoke(uri: String, nowMillis: () -> Long = System::currentTimeMillis): Flow<ScanEvent> = channelFlow {
        val startedAt = nowMillis()
        send(ScanEvent.Progress(ScanStep.IDENTIFYING))
        val limits = preferences.analysisLimits.first()

        val metadata = try {
            stager.describe(uri)
        } catch (error: IOException) {
            send(ScanEvent.Completed(saveFailure(FileMetadata(fileName = uri.substringAfterLast('/')), error, startedAt, nowMillis)))
            return@channelFlow
        }

        val declaredSize = metadata.sizeBytes
        if (declaredSize != null && declaredSize > limits.maxFileSizeBytes) {
            send(
                ScanEvent.Completed(
                    saveFailure(metadata, FileTooLargeException(limits.maxFileSizeBytes), startedAt, nowMillis, Verdict.INCONCLUSIVE),
                ),
            )
            return@channelFlow
        }

        val headerFormat = try {
            identifier.identifyHeader(stager.readHeader(uri, HEADER_BYTES))
        } catch (error: IOException) {
            send(ScanEvent.Completed(saveFailure(metadata, error, startedAt, nowMillis)))
            return@channelFlow
        }

        send(ScanEvent.Progress(ScanStep.HASHING, 0f))
        val staged: StagedFile = try {
            var lastReported = -1
            stager.stage(uri, limits.maxFileSizeBytes) { read ->
                val total = declaredSize ?: 0L
                if (total > 0) {
                    val percent = ((read * 100) / total).toInt().coerceIn(0, 100)
                    if (percent != lastReported) {
                        lastReported = percent
                        send(ScanEvent.Progress(ScanStep.HASHING, percent / 100f))
                    }
                }
            }
        } catch (error: FileTooLargeException) {
            send(ScanEvent.Completed(saveFailure(metadata, error, startedAt, nowMillis, Verdict.INCONCLUSIVE)))
            return@channelFlow
        } catch (error: IOException) {
            send(ScanEvent.Completed(saveFailure(metadata, error, startedAt, nowMillis)))
            return@channelFlow
        }

        try {
            send(ScanEvent.Progress(ScanStep.INSPECTING))
            val format = runCatchingIo { identifier.refine(staged.file, headerFormat) } ?: headerFormat
            val input = AnalysisInput(
                fileName = metadata.fileName,
                declaredExtension = metadata.declaredExtension,
                sizeBytes = staged.sizeBytes,
                format = format,
                file = staged.file,
                limits = limits,
            )
            val facts = mutableListOf<AnalysisFact>(
                CommonFacts(metadata.fileName, metadata.declaredExtension, format, staged.sizeBytes),
            )
            val outcomes = engines.sortedBy { it.descriptor.id }.mapIndexed { index, engine ->
                ensureActive()
                send(ScanEvent.Progress(ScanStep.INSPECTING, index.toFloat() / engines.size))
                runEngine(engine, input, facts)
            }

            send(ScanEvent.Progress(ScanStep.CHECKING_INDICATORS))
            val findings = ruleEngine.evaluate(facts).sortedByDescending { it.severity }
            val local = RiskClassifier.classifyLocal(outcomes, findings, staged.sizeBytes)
            val final = RiskClassifier.combine(local, OnlineReputation.NotRequested)

            send(ScanEvent.StepSkipped(ScanStep.ONLINE_REPUTATION))
            send(ScanEvent.Progress(ScanStep.FINALIZING))
            val report = AnalysisReport(
                metadata = metadata.copy(sizeBytes = staged.sizeBytes),
                hashes = staged.hashes,
                format = format,
                analyzedAtEpochMillis = startedAt,
                durationMillis = nowMillis() - startedAt,
                engines = outcomes,
                findings = findings,
                localVerdict = local.verdict,
                localExplanation = local.reasons,
                verdict = final.verdict,
                explanation = final.reasons,
            )
            val id = history.save(report.toRecord())
            send(ScanEvent.Completed(id))
        } finally {
            stager.release(staged)
        }
    }.buffer(capacity = 64).flowOn(Dispatchers.IO)

    private suspend fun runEngine(
        engine: AnalysisEngine,
        input: AnalysisInput,
        facts: MutableList<AnalysisFact>,
    ): EngineOutcome {
        val descriptor = engine.descriptor
        if (input.format !in descriptor.supportedFormats) {
            return EngineOutcome(descriptor.id, descriptor.displayName, EngineStatus.NOT_APPLICABLE, descriptor.structural)
        }
        val result = try {
            engine.analyze(input)
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (error: Exception) {
            // Arquivos malformados não podem derrubar a análise: a falha é registrada.
            EngineResult.Failed(error.message ?: error.javaClass.simpleName, error)
        } catch (error: OutOfMemoryError) {
            EngineResult.Failed("memória insuficiente para inspecionar o arquivo")
        }
        return when (result) {
            is EngineResult.Completed -> {
                facts += result.facts
                EngineOutcome(descriptor.id, descriptor.displayName, EngineStatus.COMPLETED, descriptor.structural, details = result.details)
            }
            is EngineResult.Failed ->
                EngineOutcome(descriptor.id, descriptor.displayName, EngineStatus.FAILED, descriptor.structural, failureReason = result.reason)
            EngineResult.NotApplicable ->
                EngineOutcome(descriptor.id, descriptor.displayName, EngineStatus.NOT_APPLICABLE, descriptor.structural)
        }
    }

    private suspend fun saveFailure(
        metadata: FileMetadata,
        error: IOException,
        startedAt: Long,
        nowMillis: () -> Long,
        verdict: Verdict = Verdict.ANALYSIS_ERROR,
    ): Long {
        val reason = when (error) {
            is FileTooLargeException ->
                "O arquivo excede o limite configurado de ${error.limitBytes / (1024 * 1024)} MB e não foi analisado."
            is FileAccessException -> "Não foi possível ler o arquivo: ${error.message}."
            else -> "Falha de leitura: ${error.message ?: error.javaClass.simpleName}."
        }
        val classification = Classification(verdict, listOf(reason, "Nenhuma conclusão de segurança pode ser tirada."))
        val report = AnalysisReport(
            metadata = metadata,
            format = FileFormat.UNKNOWN,
            analyzedAtEpochMillis = startedAt,
            durationMillis = nowMillis() - startedAt,
            localVerdict = classification.verdict,
            localExplanation = classification.reasons,
            verdict = classification.verdict,
            explanation = classification.reasons,
            failure = reason,
        )
        return history.save(report.toRecord())
    }

    private inline fun <T> runCatchingIo(block: () -> T): T? = try {
        block()
    } catch (error: IOException) {
        null
    }

    companion object {
        const val HEADER_BYTES = 8 * 1024
    }
}

/** Constrói o registro de histórico a partir do relatório (somente metadados). */
fun AnalysisReport.toRecord(id: Long = 0): ScanRecord = ScanRecord(
    id = id,
    fileName = metadata.fileName,
    sha256 = hashes?.sha256.orEmpty(),
    format = format,
    sizeBytes = metadata.sizeBytes,
    scannedAtEpochMillis = analyzedAtEpochMillis,
    verdict = verdict,
    origin = if (online is OnlineReputation.Found || online is OnlineReputation.NotFound) {
        AnalysisOrigin.LOCAL_AND_VIRUSTOTAL
    } else {
        AnalysisOrigin.LOCAL
    },
    evidenceSummary = summarizeEvidence(findings, failure),
    report = this,
)

private fun summarizeEvidence(findings: List<Finding>, failure: String?): String = when {
    failure != null -> failure
    findings.isEmpty() -> "Nenhum indicador encontrado"
    else -> findings.take(3).joinToString(" · ") { it.description } +
        if (findings.size > 3) " · +${findings.size - 3}" else ""
}
