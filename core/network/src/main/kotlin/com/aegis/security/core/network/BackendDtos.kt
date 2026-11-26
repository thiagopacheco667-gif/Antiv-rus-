package com.aegis.security.core.network

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Contrato JSON do backend AEGIS (ver backend/README.md). */

@Serializable
data class HealthDto(
    val status: String,
    val mode: String,
    @SerialName("uploads_enabled") val uploadsEnabled: Boolean,
    @SerialName("daily_quota_remaining") val dailyQuotaRemaining: Int? = null,
)

@Serializable
data class StatsDto(
    val malicious: Int = 0,
    val suspicious: Int = 0,
    val undetected: Int = 0,
    val harmless: Int = 0,
    val timeout: Int = 0,
    val failure: Int = 0,
    @SerialName("type_unsupported") val typeUnsupported: Int = 0,
)

@Serializable
data class DetectionDto(val engine: String, val category: String, val result: String? = null)

@Serializable
data class FileReportDto(
    /** "found" ou "not_found". */
    val status: String,
    val sha256: String? = null,
    val stats: StatsDto? = null,
    val detections: List<DetectionDto> = emptyList(),
    @SerialName("last_analysis_date") val lastAnalysisDate: Long? = null,
    val permalink: String? = null,
)

@Serializable
data class UploadDto(@SerialName("analysis_id") val analysisId: String)

@Serializable
data class AnalysisDto(
    /** "queued", "in-progress" ou "completed". */
    val status: String,
    val sha256: String? = null,
    val stats: StatsDto? = null,
    val detections: List<DetectionDto> = emptyList(),
    val date: Long? = null,
)

@Serializable
data class ErrorDto(val error: String, val message: String? = null)
