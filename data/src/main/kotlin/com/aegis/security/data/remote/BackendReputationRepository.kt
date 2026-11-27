package com.aegis.security.data.remote

import com.aegis.security.core.common.dispatchers.AegisDispatchers
import com.aegis.security.core.common.dispatchers.Dispatcher
import com.aegis.security.core.network.AegisBackendClient
import com.aegis.security.core.network.BackendApi
import com.aegis.security.core.network.BackendHttpException
import com.aegis.security.core.network.DetectionDto
import com.aegis.security.core.network.InvalidBackendResponseException
import com.aegis.security.core.network.StatsDto
import com.aegis.security.core.network.VirusTotalDirectClient
import com.aegis.security.domain.model.OnlineMode
import com.aegis.security.domain.model.BackendStatus
import com.aegis.security.domain.model.DetectionStats
import com.aegis.security.domain.model.EngineDetection
import com.aegis.security.domain.model.OnlineReputation
import com.aegis.security.domain.model.ReputationFailure
import com.aegis.security.domain.repository.FileAccessException
import com.aegis.security.domain.repository.FileStager
import com.aegis.security.domain.repository.ReputationRepository
import com.aegis.security.domain.repository.UploadOutcome
import com.aegis.security.domain.repository.UserPreferencesRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.io.InterruptedIOException
import java.security.MessageDigest
import javax.inject.Inject

/** Erro já classificado, usado internamente pelas retentativas. */
internal class ClassifiedFailure(val kind: ReputationFailure, override val message: String) : Exception(message)

/** Escolhe o cliente conforme o modo configurado (chave pessoal ou servidor AEGIS). */
fun interface ReputationApis {
    fun of(mode: OnlineMode): BackendApi
}

internal class DefaultReputationApis @Inject constructor(
    private val backend: AegisBackendClient,
    private val direct: VirusTotalDirectClient,
) : ReputationApis {
    override fun of(mode: OnlineMode): BackendApi = when (mode) {
        OnlineMode.DIRECT -> direct
        OnlineMode.BACKEND -> backend
    }
}

internal data class Credentials(val api: BackendApi, val url: String, val token: String)

internal class BackendReputationRepository @Inject constructor(
    private val apis: ReputationApis,
    private val preferences: UserPreferencesRepository,
    private val stager: FileStager,
    @Dispatcher(AegisDispatchers.IO) private val io: CoroutineDispatcher,
    private val clock: Clock,
    private val sleeper: Sleeper,
) : ReputationRepository {

    override suspend fun status(): Result<BackendStatus> = withContext(io) {
        try {
            val (api, url, token) = credentials()
            val health = retrying { api.health(url, token) }
            Result.success(BackendStatus(health.mode, health.uploadsEnabled, health.dailyQuotaRemaining))
        } catch (failure: ClassifiedFailure) {
            Result.failure(failure)
        }
    }

    override suspend fun lookup(sha256: String): OnlineReputation = withContext(io) {
        try {
            val (api, url, token) = credentials()
            val report = retrying { api.fileReport(url, token, sha256) }
            if (report.status == "not_found") {
                OnlineReputation.NotFound(clock.now())
            } else {
                OnlineReputation.Found(
                    stats = report.stats!!.toDomain(),
                    detections = report.detections.toDomain(),
                    analysisDateEpochSeconds = report.lastAnalysisDate,
                    permalink = report.permalink?.takeIf { it.startsWith("https://www.virustotal.com/") } ?: permalink(sha256),
                    viaUpload = false,
                    checkedAtEpochMillis = clock.now(),
                )
            }
        } catch (failure: ClassifiedFailure) {
            OnlineReputation.Failed(failure.kind, failure.message, clock.now())
        }
    }

    override suspend fun upload(
        uri: String,
        fileName: String,
        expectedSha256: String,
        onProgress: (Float) -> Unit,
    ): UploadOutcome = withContext(io) {
        try {
            val (api, url, token) = credentials()
            val size = verifyFile(uri, expectedSha256)
            if (size > MAX_UPLOAD_BYTES) throw ClassifiedFailure(ReputationFailure.FILE_TOO_LARGE, "o VirusTotal aceita arquivos de até 650 MB")
            // Upload não é repetido automaticamente para evitar envios duplicados.
            val result = classify { api.upload(url, token, fileName, size, { stager.open(uri) }, onProgress) }
            UploadOutcome.Accepted(result.analysisId)
        } catch (failure: ClassifiedFailure) {
            UploadOutcome.Failed(failure.kind, failure.message)
        }
    }

    override suspend fun uploadPart(
        file: File,
        name: String,
        sha256: String,
        onProgress: (Float) -> Unit,
    ): UploadOutcome = withContext(io) {
        try {
            val (api, url, token) = credentials()
            val size = file.length()
            if (!file.exists() || size == 0L) throw ClassifiedFailure(ReputationFailure.FILE_UNAVAILABLE, "parte extraída não está mais disponível")
            if (size > MAX_UPLOAD_BYTES) throw ClassifiedFailure(ReputationFailure.FILE_TOO_LARGE, "a parte excede 650 MB")
            val result = classify { api.upload(url, token, name.substringAfterLast('/'), size, { file.inputStream() }, onProgress) }
            UploadOutcome.Accepted(result.analysisId)
        } catch (failure: ClassifiedFailure) {
            UploadOutcome.Failed(failure.kind, failure.message)
        }
    }

    override suspend fun awaitAnalysis(
        analysisId: String,
        expectedSha256: String,
        onStatus: (String) -> Unit,
    ): OnlineReputation = withContext(io) {
        try {
            val (api, url, token) = credentials()
            repeat(MAX_POLLS) {
                val analysis = retrying { api.analysis(url, token, analysisId) }
                if (analysis.status == "completed") {
                    if (analysis.sha256 != null && !analysis.sha256.equals(expectedSha256, ignoreCase = true)) {
                        throw ClassifiedFailure(ReputationFailure.HASH_MISMATCH, "a análise retornada não corresponde ao arquivo enviado")
                    }
                    return@withContext OnlineReputation.Found(
                        stats = analysis.stats!!.toDomain(),
                        detections = analysis.detections.toDomain(),
                        analysisDateEpochSeconds = analysis.date,
                        permalink = permalink(expectedSha256),
                        viaUpload = true,
                        checkedAtEpochMillis = clock.now(),
                    )
                }
                onStatus(analysis.status)
                sleeper.sleep(POLL_INTERVAL_MILLIS)
            }
            OnlineReputation.Failed(ReputationFailure.TIMEOUT, "a análise externa não terminou no tempo esperado", clock.now())
        } catch (failure: ClassifiedFailure) {
            OnlineReputation.Failed(failure.kind, failure.message, clock.now())
        }
    }

    private suspend fun credentials(): Credentials {
        val config = preferences.onlineServiceConfig.first()
        val token = preferences.credential(config.mode)
        if (!config.isConfigured || token.isNullOrBlank()) {
            throw ClassifiedFailure(ReputationFailure.NOT_CONFIGURED, "o serviço online não está configurado")
        }
        val url = if (config.mode == OnlineMode.DIRECT) VirusTotalDirectClient.BASE_URL else config.baseUrl
        return Credentials(apis.of(config.mode), url, token)
    }

    /** Recalcula o SHA-256 antes do envio: garante que o arquivo é o mesmo analisado localmente. */
    private suspend fun verifyFile(uri: String, expectedSha256: String): Long {
        val digest = MessageDigest.getInstance("SHA-256")
        var size = 0L
        try {
            stager.open(uri).use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    digest.update(buffer, 0, n)
                    size += n
                }
            }
        } catch (error: FileAccessException) {
            throw ClassifiedFailure(ReputationFailure.FILE_UNAVAILABLE, "o arquivo não está mais acessível; selecione-o novamente")
        } catch (error: IOException) {
            throw ClassifiedFailure(ReputationFailure.FILE_UNAVAILABLE, "falha ao ler o arquivo: ${error.message}")
        }
        val actual = digest.digest().joinToString("") { "%02x".format(it) }
        if (!actual.equals(expectedSha256, ignoreCase = true)) {
            throw ClassifiedFailure(ReputationFailure.HASH_MISMATCH, "o arquivo selecionado é diferente do analisado (SHA-256 não confere)")
        }
        return size
    }

    /** Até 3 tentativas para falhas transitórias; 429 respeita Retry-After (máx. 60 s). */
    private suspend fun <T> retrying(block: suspend () -> T): T {
        var attempt = 0
        while (true) {
            try {
                return classify(block)
            } catch (failure: ClassifiedFailure) {
                attempt++
                val retryable = failure.kind in setOf(ReputationFailure.NO_CONNECTION, ReputationFailure.TIMEOUT, ReputationFailure.SERVER_ERROR, ReputationFailure.RATE_LIMITED)
                if (!retryable || attempt >= MAX_ATTEMPTS) throw failure
                val wait = if (failure.kind == ReputationFailure.RATE_LIMITED) {
                    (lastRetryAfter ?: 15L).coerceIn(1L, 60L) * 1000
                } else {
                    BASE_BACKOFF_MILLIS shl (attempt - 1)
                }
                sleeper.sleep(wait)
            }
        }
    }

    private var lastRetryAfter: Long? = null

    private suspend fun <T> classify(block: suspend () -> T): T = try {
        block()
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (error: BackendHttpException) {
        lastRetryAfter = error.retryAfterSeconds
        throw when (error.code) {
            401 -> ClassifiedFailure(ReputationFailure.UNAUTHORIZED, "token de acesso inválido ou expirado")
            403 -> ClassifiedFailure(ReputationFailure.FORBIDDEN, error.message ?: "acesso negado pelo serviço")
            404 -> ClassifiedFailure(ReputationFailure.INVALID_RESPONSE, "recurso não encontrado no backend")
            413 -> ClassifiedFailure(ReputationFailure.FILE_TOO_LARGE, "arquivo maior que o permitido pelo serviço")
            429 -> ClassifiedFailure(ReputationFailure.RATE_LIMITED, "limite de consultas atingido; tente mais tarde")
            504 -> ClassifiedFailure(ReputationFailure.TIMEOUT, "o VirusTotal não respondeu a tempo")
            in 500..599 -> ClassifiedFailure(ReputationFailure.SERVER_ERROR, "serviço indisponível (HTTP ${error.code})")
            else -> ClassifiedFailure(ReputationFailure.INVALID_RESPONSE, "resposta inesperada (HTTP ${error.code})")
        }
    } catch (error: InvalidBackendResponseException) {
        throw ClassifiedFailure(ReputationFailure.INVALID_RESPONSE, error.message ?: "resposta inválida")
    } catch (error: InterruptedIOException) {
        throw ClassifiedFailure(ReputationFailure.TIMEOUT, "tempo de conexão esgotado")
    } catch (error: IOException) {
        throw ClassifiedFailure(ReputationFailure.NO_CONNECTION, "sem conexão com o serviço")
    } catch (error: IllegalArgumentException) {
        throw ClassifiedFailure(ReputationFailure.INVALID_RESPONSE, error.message ?: "dados inválidos")
    }

    private fun StatsDto.toDomain() = try {
        DetectionStats(malicious, suspicious, undetected, harmless, timeout, failure, typeUnsupported)
    } catch (error: IllegalArgumentException) {
        throw ClassifiedFailure(ReputationFailure.INVALID_RESPONSE, "estatísticas inválidas")
    }

    private fun List<DetectionDto>.toDomain() = take(MAX_DETECTIONS).map {
        EngineDetection(it.engine.take(80), it.category.take(40), it.result?.take(160))
    }

    private fun permalink(sha256: String) = "https://www.virustotal.com/gui/file/${sha256.lowercase()}"

    companion object {
        const val MAX_UPLOAD_BYTES = 650L * 1024 * 1024
        const val MAX_ATTEMPTS = 3
        const val BASE_BACKOFF_MILLIS = 2_000L
        const val POLL_INTERVAL_MILLIS = 20_000L
        const val MAX_POLLS = 45
        const val MAX_DETECTIONS = 120
    }
}

/** Abstrações de tempo para testes determinísticos. */
interface Clock {
    fun now(): Long
}

interface Sleeper {
    suspend fun sleep(millis: Long)
}

internal class SystemClock @Inject constructor() : Clock {
    override fun now() = System.currentTimeMillis()
}

internal class CoroutineSleeper @Inject constructor() : Sleeper {
    override suspend fun sleep(millis: Long) = delay(millis)
}
