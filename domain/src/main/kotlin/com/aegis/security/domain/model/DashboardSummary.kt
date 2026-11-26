package com.aegis.security.domain.model

/** Números do dashboard, sempre derivados do histórico real. */
data class DashboardSummary(
    val totalScans: Int,
    val threatsDetected: Int,
    val lastScan: ScanRecord?,
    val recentScans: List<ScanRecord>,
) {
    val hasHistory: Boolean get() = totalScans > 0
}
