package com.aegis.security.core.network

import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.InputStream
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Acesso direto à VirusTotal API v3 com a chave pessoal do usuário (digitada por ele e cifrada no
 * aparelho; nunca embutida no APK). Endpoints oficiais: GET /files/{id}, POST /files,
 * GET /files/upload_url (> 32 MB), GET /analyses/{id}. Respeita o limite da API pública
 * (4 requisições por minuto) esperando a vez, em vez de falhar.
 */
@Singleton
class VirusTotalDirectClient internal constructor(
    private val client: OkHttpClient,
    private val json: Json,
    private val base: HttpUrl,
    private val clock: () -> Long,
) : BackendApi {

    @Inject
    constructor(client: OkHttpClient, json: Json) : this(client, json, BASE_URL.toHttpUrl(), System::currentTimeMillis)

    private val mutex = Mutex()
    private val recent = ArrayDeque<Long>()

    /** Janela deslizante de 60 s com no máximo [PUBLIC_PER_MINUTE] requisições. */
    private suspend fun throttle() = mutex.withLock {
        while (true) {
            val now = clock()
            while (recent.isNotEmpty() && now - recent.first() >= 60_000) recent.removeFirst()
            if (recent.size < PUBLIC_PER_MINUTE) {
                recent.addLast(now)
                return@withLock
            }
            delay(60_000 - (now - recent.first()) + 250)
        }
    }

    override suspend fun health(baseUrl: String, token: String): HealthDto {
        throttle()
        val response = client.newCall(get(base.newBuilder().addPathSegments("users").addPathSegment(token).addPathSegment("overall_quotas").build(), token)).await()
        response.use {
            val text = it.readLimited()
            if (it.code == 401 || it.code == 403 || it.code == 429) throw httpError(it.code, it.header("Retry-After"))
            if (!it.isSuccessful) {
                // Algumas contas não expõem as cotas: valida a chave com o hash público do arquivo de teste EICAR.
                fileReport(baseUrl, token, EICAR_SHA256)
                return HealthDto("ok", "direta", uploadsEnabled = true, dailyQuotaRemaining = null)
            }
            val daily = runCatching { parse(text).obj("data")?.obj("api_requests_daily")?.obj("user") }.getOrNull()
            val allowed = daily?.int("allowed")
            val used = daily?.int("used")
            val remaining = if (allowed != null && used != null) (allowed - used).coerceAtLeast(0) else null
            return HealthDto("ok", "direta", uploadsEnabled = true, dailyQuotaRemaining = remaining)
        }
    }

    override suspend fun fileReport(baseUrl: String, token: String, sha256: String): FileReportDto {
        require(AegisBackendClient.SHA256.matches(sha256)) { "SHA-256 inválido" }
        throttle()
        client.newCall(get(base.newBuilder().addPathSegment("files").addPathSegment(sha256.lowercase()).build(), token)).await().use {
            val text = it.readLimited(MAX_REPORT_BYTES)
            if (it.code == 404) return FileReportDto(status = "not_found")
            if (!it.isSuccessful) throw httpError(it.code, it.header("Retry-After"))
            return VtJson.fileReport(parse(text), sha256.lowercase())
        }
    }

    override suspend fun upload(
        baseUrl: String,
        token: String,
        fileName: String,
        sizeBytes: Long,
        open: () -> InputStream,
        onProgress: (Float) -> Unit,
    ): UploadDto {
        val target = if (sizeBytes > DIRECT_UPLOAD_LIMIT) uploadUrl(token) else base.newBuilder().addPathSegment("files").build()
        val safeName = fileName.filter { it.code in 0x20..0x7E && it != '"' }.take(200).ifBlank { "arquivo" }
        val body = MultipartBody.Builder()
            .setType(MultipartBody.FORM)
            .addFormDataPart("file", safeName, streamingBody(sizeBytes, open, onProgress))
            .build()
        val request = Request.Builder().url(target).header("x-apikey", token).header("Accept", "application/json").post(body).build()
        throttle()
        val uploadClient = client.newBuilder().writeTimeout(15, TimeUnit.MINUTES).readTimeout(5, TimeUnit.MINUTES).build()
        uploadClient.newCall(request).await().use {
            val text = it.readLimited()
            if (!it.isSuccessful) throw httpError(it.code, it.header("Retry-After"))
            val id = (parse(text).obj("data")?.get("id") as? JsonPrimitive)?.contentOrNull
            if (id == null || !AegisBackendClient.ANALYSIS_ID.matches(id)) throw InvalidBackendResponseException("identificador de análise inválido")
            return UploadDto(id)
        }
    }

    override suspend fun analysis(baseUrl: String, token: String, analysisId: String): AnalysisDto {
        require(AegisBackendClient.ANALYSIS_ID.matches(analysisId)) { "identificador de análise inválido" }
        throttle()
        client.newCall(get(base.newBuilder().addPathSegment("analyses").addPathSegment(analysisId).build(), token)).await().use {
            val text = it.readLimited(MAX_REPORT_BYTES)
            if (!it.isSuccessful) throw httpError(it.code, it.header("Retry-After"))
            return VtJson.analysis(parse(text))
        }
    }

    private suspend fun uploadUrl(token: String): HttpUrl {
        throttle()
        client.newCall(get(base.newBuilder().addPathSegments("files/upload_url").build(), token)).await().use {
            val text = it.readLimited()
            if (!it.isSuccessful) throw httpError(it.code, it.header("Retry-After"))
            val url = (parse(text)["data"] as? JsonPrimitive)?.contentOrNull?.toHttpUrlOrNull()
                ?: throw InvalidBackendResponseException("URL de upload inválida")
            val trusted = url.isHttps && (url.host == "www.virustotal.com" || url.host.endsWith(".virustotal.com"))
            if (!trusted && base.host == "www.virustotal.com") throw InvalidBackendResponseException("URL de upload não confiável")
            return url
        }
    }

    private fun get(url: HttpUrl, token: String) =
        Request.Builder().url(url).header("x-apikey", token).header("Accept", "application/json").get().build()

    private fun parse(text: String): JsonObject = try {
        json.parseToJsonElement(text).jsonObject
    } catch (error: IllegalArgumentException) {
        throw InvalidBackendResponseException("resposta do VirusTotal fora do formato esperado")
    }

    /** No modo direto, 401/403 do VirusTotal significam chave inválida ou sem permissão. */
    private fun httpError(code: Int, retryAfter: String?) = BackendHttpException(
        code = code,
        errorCode = null,
        retryAfterSeconds = retryAfter?.toLongOrNull() ?: if (code == 429) 60 else null,
        message = when (code) {
            401 -> "chave do VirusTotal inválida"
            403 -> "a chave não tem permissão para esta operação"
            429 -> "cota da chave do VirusTotal excedida"
            else -> "erro do VirusTotal (HTTP $code)"
        },
    )

    companion object {
        const val BASE_URL = "https://www.virustotal.com/api/v3/"
        const val PUBLIC_PER_MINUTE = 4
        private const val DIRECT_UPLOAD_LIMIT = 32L * 1024 * 1024
        private const val MAX_REPORT_BYTES = 8L * 1024 * 1024
        private const val EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    }
}

internal fun JsonObject.obj(key: String): JsonObject? = this[key] as? JsonObject
internal fun JsonObject.int(key: String): Int? = (this[key] as? JsonPrimitive)?.intOrNull
internal fun JsonObject.long(key: String): Long? = (this[key] as? JsonPrimitive)?.longOrNull
internal fun JsonObject.string(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull

/** Conversão das respostas JSON da API v3 para o contrato interno (testável na JVM). */
object VtJson {
    fun stats(raw: JsonObject?): StatsDto {
        fun n(key: String) = (raw?.int(key) ?: 0).coerceAtLeast(0)
        return StatsDto(
            malicious = n("malicious"),
            suspicious = n("suspicious"),
            undetected = n("undetected"),
            harmless = n("harmless"),
            timeout = n("timeout") + n("confirmed-timeout"),
            failure = n("failure"),
            typeUnsupported = n("type-unsupported"),
        )
    }

    fun detections(raw: JsonObject?): List<DetectionDto> = (raw ?: emptyMap<String, JsonElement>()).entries.take(200).mapNotNull { (engine, value) ->
        val result = value as? JsonObject ?: return@mapNotNull null
        DetectionDto(
            engine = (result.string("engine_name") ?: engine).take(80),
            category = (result.string("category") ?: "unknown").take(40),
            result = result.string("result")?.take(160),
        )
    }

    fun fileReport(root: JsonObject, sha256: String): FileReportDto {
        val attributes = root.obj("data")?.obj("attributes") ?: throw InvalidBackendResponseException("relatório sem atributos")
        val reported = attributes.string("sha256")?.lowercase()
        if (reported != sha256) throw InvalidBackendResponseException("relatório não corresponde ao hash consultado")
        return FileReportDto(
            status = "found",
            sha256 = sha256,
            stats = stats(attributes.obj("last_analysis_stats")),
            detections = detections(attributes.obj("last_analysis_results")),
            lastAnalysisDate = attributes.long("last_analysis_date"),
            permalink = "https://www.virustotal.com/gui/file/$sha256",
        )
    }

    fun analysis(root: JsonObject): AnalysisDto {
        val attributes = root.obj("data")?.obj("attributes") ?: throw InvalidBackendResponseException("análise sem atributos")
        val status = attributes.string("status")
        if (status !in setOf("queued", "in-progress", "completed")) throw InvalidBackendResponseException("estado de análise desconhecido")
        val completed = status == "completed"
        return AnalysisDto(
            status = status!!,
            sha256 = root.obj("meta")?.obj("file_info")?.string("sha256")?.lowercase(),
            stats = if (completed) stats(attributes.obj("stats")) else null,
            detections = if (completed) detections(attributes.obj("results")) else emptyList(),
            date = attributes.long("date"),
        )
    }
}

