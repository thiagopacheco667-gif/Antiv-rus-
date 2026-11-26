package com.aegis.security.domain.repository

import com.aegis.security.domain.model.ScanRecord
import com.aegis.security.domain.model.Verdict
import kotlinx.coroutines.flow.Flow

interface ScanHistoryRepository {
    /** Histórico completo, do mais recente para o mais antigo. */
    fun observeHistory(): Flow<List<ScanRecord>>

    fun observeRecent(limit: Int): Flow<List<ScanRecord>>

    fun observeTotalCount(): Flow<Int>

    fun observeCountByVerdict(verdict: Verdict): Flow<Int>

    fun observeRecord(id: Long): Flow<ScanRecord?>

    suspend fun getRecord(id: Long): ScanRecord?

    /** Persiste um registro e devolve o id gerado. */
    suspend fun save(record: ScanRecord): Long

    suspend fun update(record: ScanRecord)

    suspend fun delete(id: Long)

    suspend fun clear()
}
