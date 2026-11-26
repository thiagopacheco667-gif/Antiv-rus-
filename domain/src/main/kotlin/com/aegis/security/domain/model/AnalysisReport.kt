package com.aegis.security.domain.model

import com.aegis.security.domain.analysis.DetailSection
import com.aegis.security.domain.analysis.Finding
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class FileHashes(val sha256: String, val sha1: String, val md5: String)

@Serializable
data class FileMetadata(
    val fileName: String,
    val declaredExtension: String? = null,
    val sizeBytes: Long? = null,
    val mimeType: String? = null,
    val lastModifiedEpochMillis: Long? = null,
    val provider: String? = null,
)

@Serializable
enum class EngineStatus { COMPLETED, FAILED, NOT_APPLICABLE }

@Serializable
data class EngineOutcome(
    val engineId: String,
    val engineName: String,
    val status: EngineStatus,
    val structural: Boolean,
    val failureReason: String? = null,
    val details: List<DetailSection> = emptyList(),
    /** Inspeção concluída, mas parcial: o resultado não pode ser "seguro". */
    val incomplete: List<String> = emptyList(),
)

@Serializable
data class DetectionStats(
    val malicious: Int,
    val suspicious: Int,
    val undetected: Int,
    val harmless: Int,
    val timeout: Int = 0,
    val failure: Int = 0,
    val typeUnsupported: Int = 0,
) {
    init {
        require(listOf(malicious, suspicious, undetected, harmless, timeout, failure, typeUnsupported).all { it >= 0 })
    }

    /** Mecanismos que não chegaram a um resultado (tempo esgotado, falha, tipo não suportado). */
    val inconclusive: Int get() = timeout + failure + typeUnsupported
    val notDetected: Int get() = undetected + harmless
}

@Serializable
data class EngineDetection(val engine: String, val category: String, val result: String? = null)

@Serializable
enum class ReputationFailure {
    NOT_CONFIGURED,
    NO_CONNECTION,
    TIMEOUT,
    UNAUTHORIZED,
    FORBIDDEN,
    RATE_LIMITED,
    INVALID_RESPONSE,
    SERVER_ERROR,
    FILE_UNAVAILABLE,
    HASH_MISMATCH,
    FILE_TOO_LARGE,
}

/** Resultado da consulta externa. Falhas nunca são interpretadas como resultado seguro. */
@Serializable
sealed interface OnlineReputation {
    @Serializable
    @SerialName("not_requested")
    data object NotRequested : OnlineReputation

    @Serializable
    @SerialName("not_found")
    data class NotFound(val checkedAtEpochMillis: Long) : OnlineReputation

    @Serializable
    @SerialName("found")
    data class Found(
        val stats: DetectionStats,
        val detections: List<EngineDetection>,
        val analysisDateEpochSeconds: Long?,
        val permalink: String?,
        val viaUpload: Boolean,
        val checkedAtEpochMillis: Long,
    ) : OnlineReputation

    @Serializable
    @SerialName("failed")
    data class Failed(
        val kind: ReputationFailure,
        val message: String,
        val checkedAtEpochMillis: Long,
    ) : OnlineReputation
}

/** Relatório completo de uma análise. Contém somente metadados e evidências — nunca o conteúdo do arquivo. */
@Serializable
data class AnalysisReport(
    val metadata: FileMetadata,
    val hashes: FileHashes? = null,
    val format: FileFormat,
    val analyzedAtEpochMillis: Long,
    val durationMillis: Long,
    val engines: List<EngineOutcome> = emptyList(),
    val findings: List<Finding> = emptyList(),
    val localVerdict: Verdict,
    val localExplanation: List<String>,
    val online: OnlineReputation = OnlineReputation.NotRequested,
    val verdict: Verdict,
    val explanation: List<String>,
    /** Falha técnica que impediu a análise (quando houver). */
    val failure: String? = null,
)
