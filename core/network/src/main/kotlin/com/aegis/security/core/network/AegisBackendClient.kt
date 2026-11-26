package com.aegis.security.core.network

import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.Callback
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okio.BufferedSink
import okio.source
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Resposta HTTP de erro do backend. Nunca representa um resultado seguro. */
class BackendHttpException(
    val code: Int,
    val errorCode: String?,
    val retryAfterSeconds: Long?,
    message: String,
) : IOException(message)

/** Resposta que não respeita o contrato esperado. */
class InvalidBackendResponseException(message: String) : IOException(message)

/**
 * Cliente do backend AEGIS. A chave do VirusTotal fica somente no servidor; o app envia um
 * token de acesso pessoal (Bearer), armazenado cifrado no aparelho. Somente HTTPS.
 */
interface BackendApi {
    suspend fun health(baseUrl: String, token: String): HealthDto
    suspend fun fileReport(baseUrl: String, token: String, sha256: String): FileReportDto
    suspend fun upload(
        baseUrl: String,
        token: String,
        fileName: String,
        sizeBytes: Long,
        open: () -> InputStream,
        onProgress: (Float) -> Unit,
    ): UploadDto
    suspend fun analysis(baseUrl: String, token: String, analysisId: String): AnalysisDto
}

class AegisBackendClient @Inject constructor(
    private val client: OkHttpClient,
    private val json: Json,
) : BackendApi {
    override suspend fun health(baseUrl: String, token: String): HealthDto =
        execute(get(url(baseUrl, "v1", "health"), token), HealthDto.serializer())

    override suspend fun fileReport(baseUrl: String, token: String, sha256: String): FileReportDto {
        require(SHA256.matches(sha256)) { "SHA-256 inválido" }
        val report = execute(get(url(baseUrl, "v1", "files", sha256), token), FileReportDto.serializer())
        if (report.status != "found" && report.status != "not_found") throw InvalidBackendResponseException("status desconhecido: ${report.status}")
        if (report.status == "found" && (report.stats == null || !report.sha256.equals(sha256, ignoreCase = true))) {
            throw InvalidBackendResponseException("relatório não corresponde ao hash consultado")
        }
        return report
    }

    override suspend fun upload(
        baseUrl: String,
        token: String,
        fileName: String,
        sizeBytes: Long,
        open: () -> InputStream,
        onProgress: (Float) -> Unit,
    ): UploadDto {
        val body = object : RequestBody() {
            override fun contentType() = OCTET_STREAM
            override fun contentLength() = sizeBytes
            override fun writeTo(sink: BufferedSink) {
                open().source().use { source ->
                    var written = 0L
                    while (true) {
                        val read = source.read(sink.buffer, UPLOAD_CHUNK)
                        if (read < 0) break
                        written += read
                        sink.emitCompleteSegments()
                        onProgress((written.toDouble() / sizeBytes.coerceAtLeast(1)).toFloat().coerceIn(0f, 1f))
                    }
                    if (written != sizeBytes) throw IOException("o arquivo mudou durante o envio")
                }
            }
        }
        val request = Request.Builder()
            .url(url(baseUrl, "v1", "files"))
            .header("Authorization", "Bearer $token")
            .header("X-File-Name", fileName.filter { it.code in 0x20..0x7E }.take(200).ifBlank { "arquivo" })
            .post(body)
            .build()
        val uploadClient = client.newBuilder().writeTimeout(10, TimeUnit.MINUTES).readTimeout(5, TimeUnit.MINUTES).build()
        val result = execute(request, UploadDto.serializer(), uploadClient)
        if (!ANALYSIS_ID.matches(result.analysisId)) throw InvalidBackendResponseException("identificador de análise inválido")
        return result
    }

    override suspend fun analysis(baseUrl: String, token: String, analysisId: String): AnalysisDto {
        require(ANALYSIS_ID.matches(analysisId)) { "identificador de análise inválido" }
        val dto = execute(get(url(baseUrl, "v1", "analyses", analysisId), token), AnalysisDto.serializer())
        if (dto.status !in setOf("queued", "in-progress", "completed")) throw InvalidBackendResponseException("status desconhecido: ${dto.status}")
        if (dto.status == "completed" && dto.stats == null) throw InvalidBackendResponseException("análise concluída sem estatísticas")
        return dto
    }

    private fun url(baseUrl: String, vararg segments: String): HttpUrl {
        val base = baseUrl.toHttpUrlOrNull() ?: throw IllegalArgumentException("URL do backend inválida")
        require(base.isHttps) { "O backend precisa usar HTTPS" }
        return base.newBuilder().apply { segments.forEach { addPathSegment(it) } }.build()
    }

    private fun get(url: HttpUrl, token: String) = Request.Builder()
        .url(url)
        .header("Authorization", "Bearer $token")
        .header("Accept", "application/json")
        .get()
        .build()

    private suspend fun <T> execute(request: Request, serializer: KSerializer<T>, http: OkHttpClient = client): T {
        val response = http.newCall(request).await()
        response.use {
            val text = readLimited(it)
            if (!it.isSuccessful) {
                val error = runCatching { json.decodeFromString(ErrorDto.serializer(), text) }.getOrNull()
                throw BackendHttpException(
                    code = it.code,
                    errorCode = error?.error,
                    retryAfterSeconds = it.header("Retry-After")?.toLongOrNull(),
                    message = error?.message ?: "HTTP ${it.code}",
                )
            }
            return try {
                json.decodeFromString(serializer, text)
            } catch (error: IllegalArgumentException) {
                throw InvalidBackendResponseException("resposta fora do formato esperado")
            }
        }
    }

    private fun readLimited(response: Response): String {
        val body = response.body ?: return ""
        val source = body.source()
        if (!source.request(MAX_RESPONSE_BYTES + 1)) return source.buffer.readUtf8()
        throw InvalidBackendResponseException("resposta maior que o limite permitido")
    }

    private suspend fun Call.await(): Response = suspendCancellableCoroutine { continuation ->
        continuation.invokeOnCancellation { cancel() }
        enqueue(
            object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    if (continuation.isActive) continuation.resumeWithException(e)
                }

                override fun onResponse(call: Call, response: Response) {
                    if (continuation.isActive) continuation.resume(response) else response.close()
                }
            },
        )
    }

    companion object {
        val SHA256 = Regex("^[0-9a-fA-F]{64}$")
        val ANALYSIS_ID = Regex("^[A-Za-z0-9=_\\-]{1,200}$")
        private val OCTET_STREAM = "application/octet-stream".toMediaType()
        private const val UPLOAD_CHUNK = 64L * 1024
        private const val MAX_RESPONSE_BYTES = 2L * 1024 * 1024
    }
}
