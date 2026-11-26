package com.aegis.security.domain.usecase

import com.aegis.security.domain.model.DashboardSummary
import com.aegis.security.domain.model.ScanRecord
import com.aegis.security.domain.model.Verdict
import com.aegis.security.domain.repository.ScanHistoryRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import javax.inject.Inject

class ObserveDashboardSummaryUseCase @Inject constructor(
    private val repository: ScanHistoryRepository,
) {
    operator fun invoke(recentLimit: Int = DEFAULT_RECENT_LIMIT): Flow<DashboardSummary> {
        require(recentLimit > 0) { "recentLimit deve ser positivo" }
        return combine(
            repository.observeTotalCount(),
            repository.observeCountByVerdict(Verdict.THREAT_DETECTED),
            repository.observeRecent(recentLimit),
        ) { total, threats, recent ->
            DashboardSummary(
                totalScans = total,
                threatsDetected = threats,
                lastScan = recent.firstOrNull(),
                recentScans = recent,
            )
        }
    }

    companion object {
        const val DEFAULT_RECENT_LIMIT = 5
    }
}

class ObserveHistoryUseCase @Inject constructor(
    private val repository: ScanHistoryRepository,
) {
    operator fun invoke(): Flow<List<ScanRecord>> = repository.observeHistory()
}

class ObserveScanCountUseCase @Inject constructor(
    private val repository: ScanHistoryRepository,
) {
    operator fun invoke(): Flow<Int> = repository.observeTotalCount()
}

class DeleteScanRecordUseCase @Inject constructor(
    private val repository: ScanHistoryRepository,
) {
    suspend operator fun invoke(id: Long) = repository.delete(id)
}

class ClearHistoryUseCase @Inject constructor(
    private val repository: ScanHistoryRepository,
) {
    suspend operator fun invoke() = repository.clear()
}
