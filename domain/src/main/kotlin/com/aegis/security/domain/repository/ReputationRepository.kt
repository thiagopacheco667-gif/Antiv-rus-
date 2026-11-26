package com.aegis.security.domain.repository

import com.aegis.security.domain.model.BackendStatus
import com.aegis.security.domain.model.OnlineReputation
import com.aegis.security.domain.model.ReputationFailure

sealed interface UploadOutcome {
    data class Accepted(val analysisId: String) : UploadOutcome
    data class Failed(val kind: ReputationFailure, val message: String) : UploadOutcome
}

/**
 * Reputação online via backend AEGIS (VirusTotal API v3).
 * Nenhum método lança exceção para falhas de rede: falhas viram [OnlineReputation.Failed],
 * nunca um resultado seguro. Somente cancelamento é propagado.
 */
interface ReputationRepository {
    suspend fun status(): Result<BackendStatus>

    suspend fun lookup(sha256: String): OnlineReputation

    suspend fun upload(
        uri: String,
        fileName: String,
        expectedSha256: String,
        onProgress: (Float) -> Unit,
    ): UploadOutcome

    suspend fun awaitAnalysis(
        analysisId: String,
        expectedSha256: String,
        onStatus: (String) -> Unit,
    ): OnlineReputation
}
