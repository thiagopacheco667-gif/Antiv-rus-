package com.aegis.security.core.network

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class VtJsonTest {
    private val sha = "a".repeat(64)

    private fun parse(text: String) = Json.parseToJsonElement(text).jsonObject

    @Test
    fun fileReport_mapsDocumentedV3Fields() {
        val dto = VtJson.fileReport(
            parse(
                """{"data":{"attributes":{"sha256":"$sha","last_analysis_date":1700000000,
                "last_analysis_stats":{"malicious":3,"suspicious":1,"undetected":50,"harmless":2,"timeout":1,"confirmed-timeout":2,"type-unsupported":4},
                "last_analysis_results":{"Eng":{"category":"malicious","engine_name":"Eng","result":"Android.Trojan"}}}}}""",
            ),
            sha,
        )
        assertEquals(StatsDto(3, 1, 50, 2, timeout = 3, failure = 0, typeUnsupported = 4), dto.stats)
        assertEquals("Android.Trojan", dto.detections.single().result)
        assertEquals(1700000000L, dto.lastAnalysisDate)
    }

    @Test(expected = InvalidBackendResponseException::class)
    fun fileReport_forOtherHash_isRejected() {
        VtJson.fileReport(parse("""{"data":{"attributes":{"sha256":"${"b".repeat(64)}"}}}"""), sha)
    }

    @Test
    fun analysis_inProgress_hasNoStats_andCompletedHasHash() {
        assertNull(VtJson.analysis(parse("""{"data":{"attributes":{"status":"queued"}}}""")).stats)
        val done = VtJson.analysis(parse("""{"data":{"attributes":{"status":"completed","stats":{"malicious":0,"undetected":70}}},"meta":{"file_info":{"sha256":"${sha.uppercase()}"}}}"""))
        assertEquals(sha, done.sha256)
        assertEquals(70, done.stats!!.undetected)
    }

    @Test(expected = InvalidBackendResponseException::class)
    fun analysis_unknownStatus_isRejected() {
        VtJson.analysis(parse("""{"data":{"attributes":{"status":"hacked"}}}"""))
    }
}
