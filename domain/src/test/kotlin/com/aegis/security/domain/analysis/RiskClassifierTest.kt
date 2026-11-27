package com.aegis.security.domain.analysis

import com.aegis.security.domain.model.DetectionStats
import com.aegis.security.domain.model.EngineOutcome
import com.aegis.security.domain.model.EngineStatus
import com.aegis.security.domain.model.OnlineReputation
import com.aegis.security.domain.model.PartReputation
import com.aegis.security.domain.model.ReputationFailure
import com.aegis.security.domain.model.Verdict
import org.junit.Assert.assertEquals
import org.junit.Test

class RiskClassifierTest {
    private val completed = listOf(EngineOutcome("zip", "ZIP", EngineStatus.COMPLETED, structural = true))
    private val safe = RiskClassifier.classifyLocal(completed, emptyList(), sizeBytes = 10)

    private fun found(malicious: Int, suspicious: Int = 0) = OnlineReputation.Found(
        DetectionStats(malicious, suspicious, undetected = 60, harmless = 0),
        emptyList(),
        analysisDateEpochSeconds = 1,
        permalink = null,
        viaUpload = false,
        checkedAtEpochMillis = 1,
    )

    @Test
    fun permissionsOrLowFindingsAlone_doNotMakeThreats() {
        val low = Finding("A", "permissões sensíveis", FindingCategory.PERMISSION, Severity.LOW, "SMS", "r")
        assertEquals(Verdict.SAFE_BY_CHECKS, RiskClassifier.classifyLocal(completed, listOf(low), 10).verdict)
    }

    @Test
    fun connectionFailure_neverImprovesOrDeclaresSafety() {
        val suspicious = Classification(Verdict.SUSPICIOUS, listOf("x"))
        val failed = OnlineReputation.Failed(ReputationFailure.NO_CONNECTION, "sem conexão", 1)
        assertEquals(Verdict.SUSPICIOUS, RiskClassifier.combine(suspicious, failed).verdict)
        val inconclusive = Classification(Verdict.INCONCLUSIVE, listOf("x"))
        assertEquals(Verdict.INCONCLUSIVE, RiskClassifier.combine(inconclusive, failed).verdict)
    }

    @Test
    fun unknownHash_keepsLocalVerdict() {
        val inconclusive = Classification(Verdict.INCONCLUSIVE, listOf("x"))
        assertEquals(Verdict.INCONCLUSIVE, RiskClassifier.combine(inconclusive, OnlineReputation.NotFound(1)).verdict)
    }

    @Test
    fun externalDetections_followDocumentedThresholds() {
        assertEquals(Verdict.SAFE_BY_CHECKS, RiskClassifier.combine(safe, found(0)).verdict)
        assertEquals(Verdict.SUSPICIOUS, RiskClassifier.combine(safe, found(1)).verdict)
        assertEquals(Verdict.SUSPICIOUS, RiskClassifier.combine(safe, found(0, suspicious = 2)).verdict)
        assertEquals(Verdict.THREAT_DETECTED, RiskClassifier.combine(safe, found(RiskClassifier.EXTERNAL_THREAT_MIN_ENGINES)).verdict)
    }

    @Test
    fun externalDetections_neverDowngradeLocalThreat() {
        val threat = Classification(Verdict.THREAT_DETECTED, listOf("EICAR"))
        assertEquals(Verdict.THREAT_DETECTED, RiskClassifier.combine(threat, found(1)).verdict)
    }

    @Test
    fun partialInspection_isInconclusive_neverSafe() {
        val partial = listOf(EngineOutcome("zip", "ZIP", EngineStatus.COMPLETED, structural = true, incomplete = listOf("limite de entradas atingido")))
        assertEquals(Verdict.INCONCLUSIVE, RiskClassifier.classifyLocal(partial, emptyList(), 10).verdict)
    }

    @Test
    fun parts_detectionsRaiseVerdict_unknownPartsDoNot() {
        fun part(online: OnlineReputation) = PartReputation("lib/arm64-v8a/libx.so", 10, "a".repeat(64), online)
        assertEquals(Verdict.SAFE_BY_CHECKS, RiskClassifier.combineParts(safe, listOf(part(OnlineReputation.NotFound(1)))).verdict)
        assertEquals(Verdict.SUSPICIOUS, RiskClassifier.combineParts(safe, listOf(part(found(1)))).verdict)
        assertEquals(Verdict.THREAT_DETECTED, RiskClassifier.combineParts(safe, listOf(part(found(5)))).verdict)
    }
}
