package com.aegis.security.data.remote

import com.aegis.security.core.network.AnalysisDto
import com.aegis.security.core.network.BackendApi
import com.aegis.security.core.network.BackendHttpException
import com.aegis.security.core.network.FileReportDto
import com.aegis.security.core.network.HealthDto
import com.aegis.security.core.network.InvalidBackendResponseException
import com.aegis.security.core.network.StatsDto
import com.aegis.security.core.network.UploadDto
import com.aegis.security.domain.model.AnalysisLimits
import com.aegis.security.domain.model.FileMetadata
import com.aegis.security.domain.model.OnlineReputation
import com.aegis.security.domain.model.OnlineServiceConfig
import com.aegis.security.domain.model.ReputationFailure
import com.aegis.security.domain.model.ThemePreference
import com.aegis.security.domain.repository.FileStager
import com.aegis.security.domain.repository.StagedFile
import com.aegis.security.domain.repository.UploadOutcome
import com.aegis.security.domain.repository.UserPreferencesRepository
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest

class BackendReputationRepositoryTest {
    private val content = "conteúdo de teste inofensivo".toByteArray()
    private val sha256 = MessageDigest.getInstance("SHA-256").digest(content).joinToString("") { "%02x".format(it) }

    private open class FakeApi : BackendApi {
        var calls = 0
        open var report: suspend () -> FileReportDto = { FileReportDto(status = "not_found") }
        open var analysis: suspend () -> AnalysisDto = { AnalysisDto(status = "completed", stats = StatsDto(malicious = 0, undetected = 70)) }
        open var uploadBehavior: suspend () -> UploadDto = { UploadDto("abc123==") }
        override suspend fun health(baseUrl: String, token: String) = HealthDto("ok", "public", true, 500)
        override suspend fun fileReport(baseUrl: String, token: String, sha256: String): FileReportDto { calls++; return report() }
        override suspend fun upload(baseUrl: String, token: String, fileName: String, sizeBytes: Long, open: () -> InputStream, onProgress: (Float) -> Unit): UploadDto {
            calls++
            return uploadBehavior()
        }
        override suspend fun analysis(baseUrl: String, token: String, analysisId: String): AnalysisDto { calls++; return analysis() }
    }

    private class Prefs(configured: Boolean) : UserPreferencesRepository {
        override val themePreference = MutableStateFlow(ThemePreference.DARK)
        override val analysisLimits = MutableStateFlow(AnalysisLimits())
        override val onlineServiceConfig = MutableStateFlow(if (configured) OnlineServiceConfig("https://aegis.test", true) else OnlineServiceConfig.Empty)
        private val token = if (configured) "token" else null
        override suspend fun setThemePreference(preference: ThemePreference) = Unit
        override suspend fun setAnalysisLimits(limits: AnalysisLimits) = Unit
        override suspend fun setOnlineServiceConfig(baseUrl: String, accessToken: String?) = Unit
        override suspend fun accessToken() = token
    }

    private inner class Stager(private val bytes: ByteArray = content) : FileStager {
        override suspend fun describe(uri: String) = FileMetadata("x")
        override suspend fun readHeader(uri: String, maxBytes: Int) = ByteArray(0)
        override suspend fun stage(uri: String, maxBytes: Long, onProgress: suspend (Long) -> Unit): StagedFile = error("não usado")
        override fun release(staged: StagedFile) = Unit
        override fun open(uri: String): InputStream = ByteArrayInputStream(bytes)
    }

    private class NoSleep : Sleeper {
        val waits = mutableListOf<Long>()
        override suspend fun sleep(millis: Long) { waits += millis }
    }

    private val clock = object : Clock { override fun now() = 42L }

    private fun repository(api: BackendApi, configured: Boolean = true, stager: FileStager = Stager(), sleeper: Sleeper = NoSleep()) =
        BackendReputationRepository(api, Prefs(configured), stager, Dispatchers.Unconfined, clock, sleeper)

    @Test
    fun notConfigured_isFailure_neverSafe() = runTest {
        val result = repository(FakeApi(), configured = false).lookup(sha256)
        assertEquals(ReputationFailure.NOT_CONFIGURED, (result as OnlineReputation.Failed).kind)
    }

    @Test
    fun noConnection_isRetried_thenFails() = runTest {
        val api = FakeApi().apply { report = { throw IOException("offline") } }
        val result = repository(api).lookup(sha256)
        assertEquals(ReputationFailure.NO_CONNECTION, (result as OnlineReputation.Failed).kind)
        assertEquals(BackendReputationRepository.MAX_ATTEMPTS, api.calls)
    }

    @Test
    fun rateLimited_respectsRetryAfter_thenFails() = runTest {
        val sleeper = NoSleep()
        val api = FakeApi().apply { report = { throw BackendHttpException(429, "rate_limited", 7, "limite") } }
        val result = repository(api, sleeper = sleeper).lookup(sha256)
        assertEquals(ReputationFailure.RATE_LIMITED, (result as OnlineReputation.Failed).kind)
        assertTrue(sleeper.waits.all { it == 7_000L })
    }

    @Test
    fun unauthorizedAndForbidden_areNotRetried() = runTest {
        val api = FakeApi().apply { report = { throw BackendHttpException(401, "unauthorized", null, "x") } }
        assertEquals(ReputationFailure.UNAUTHORIZED, (repository(api).lookup(sha256) as OnlineReputation.Failed).kind)
        assertEquals(1, api.calls)
        val forbidden = FakeApi().apply { report = { throw BackendHttpException(403, "forbidden", null, "quota") } }
        assertEquals(ReputationFailure.FORBIDDEN, (repository(forbidden).lookup(sha256) as OnlineReputation.Failed).kind)
    }

    @Test
    fun unknownHash_isNotFound_notSafe() = runTest {
        assertTrue(repository(FakeApi()).lookup(sha256) is OnlineReputation.NotFound)
    }

    @Test
    fun responseWithoutReport_isInvalidResponse() = runTest {
        val api = FakeApi().apply { report = { throw InvalidBackendResponseException("relatório ausente") } }
        assertEquals(ReputationFailure.INVALID_RESPONSE, (repository(api).lookup(sha256) as OnlineReputation.Failed).kind)
    }

    @Test
    fun uploadOfDifferentFile_isRejectedBeforeSending() = runTest {
        val api = FakeApi()
        val outcome = repository(api, stager = Stager("outro conteúdo".toByteArray())).upload("uri", "x", sha256) {}
        assertEquals(ReputationFailure.HASH_MISMATCH, (outcome as UploadOutcome.Failed).kind)
        assertEquals(0, api.calls)
    }

    @Test
    fun upload_thenPolling_untilCompleted() = runTest {
        var polls = 0
        val api = FakeApi().apply {
            analysis = {
                polls++
                if (polls < 3) AnalysisDto("queued") else AnalysisDto("completed", sha256, StatsDto(malicious = 4, undetected = 60))
            }
        }
        val repo = repository(api)
        val outcome = repo.upload("uri", "x", sha256) {} as UploadOutcome.Accepted
        val statuses = mutableListOf<String>()
        val result = repo.awaitAnalysis(outcome.analysisId, sha256) { statuses += it } as OnlineReputation.Found
        assertEquals(4, result.stats.malicious)
        assertTrue(result.viaUpload)
        assertEquals(listOf("queued", "queued"), statuses)
    }

    @Test
    fun cancelledUpload_propagatesCancellation_andReturnsNothing() = runTest {
        val started = CompletableDeferred<Unit>()
        val api = FakeApi().apply {
            uploadBehavior = {
                started.complete(Unit)
                awaitCancellation()
            }
        }
        var result: UploadOutcome? = null
        val job = launch { result = repository(api).upload("uri", "x", sha256) {} }
        started.await()
        job.cancel()
        job.join()
        assertEquals(null, result)
    }
}
