package com.aegis.security.domain.testing

import com.aegis.security.domain.model.ScanRecord
import com.aegis.security.domain.model.Verdict
import com.aegis.security.domain.repository.ScanHistoryRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update

/** Implementação em memória com a mesma ordenação do DAO (mais recente primeiro). */
class FakeScanHistoryRepository : ScanHistoryRepository {
    val records = MutableStateFlow<List<ScanRecord>>(emptyList())
    private var nextId = 1L

    private fun ordered(list: List<ScanRecord>) =
        list.sortedWith(compareByDescending<ScanRecord> { it.scannedAtEpochMillis }.thenByDescending { it.id })

    override fun observeHistory(): Flow<List<ScanRecord>> = records.map(::ordered)

    override fun observeRecent(limit: Int): Flow<List<ScanRecord>> = records.map { ordered(it).take(limit) }

    override fun observeTotalCount(): Flow<Int> = records.map { it.size }

    override fun observeCountByVerdict(verdict: Verdict): Flow<Int> =
        records.map { list -> list.count { it.verdict == verdict } }

    override fun observeRecord(id: Long): Flow<ScanRecord?> = records.map { list -> list.firstOrNull { it.id == id } }

    override suspend fun getRecord(id: Long): ScanRecord? = records.value.firstOrNull { it.id == id }

    override suspend fun save(record: ScanRecord): Long {
        val id = if (record.id == 0L) nextId++ else record.id
        records.update { it + record.copy(id = id) }
        return id
    }

    override suspend fun update(record: ScanRecord) {
        records.update { list -> list.map { if (it.id == record.id) record else it } }
    }

    override suspend fun delete(id: Long) {
        records.update { list -> list.filterNot { it.id == id } }
    }

    override suspend fun clear() {
        records.value = emptyList()
    }
}
