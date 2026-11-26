package com.aegis.security.data.repository

import com.aegis.security.core.database.dao.ScanRecordDao
import com.aegis.security.data.mapper.asDomain
import com.aegis.security.data.mapper.asEntity
import com.aegis.security.domain.model.ScanRecord
import com.aegis.security.domain.model.Verdict
import com.aegis.security.domain.repository.ScanHistoryRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject

internal class RoomScanHistoryRepository @Inject constructor(
    private val dao: ScanRecordDao,
) : ScanHistoryRepository {

    override fun observeHistory(): Flow<List<ScanRecord>> =
        dao.observeAll().map { rows -> rows.map { it.asDomain() } }

    override fun observeRecent(limit: Int): Flow<List<ScanRecord>> =
        dao.observeRecent(limit).map { rows -> rows.map { it.asDomain() } }

    override fun observeTotalCount(): Flow<Int> = dao.observeCount()

    override fun observeCountByVerdict(verdict: Verdict): Flow<Int> =
        dao.observeCountByVerdict(verdict.name)

    override fun observeRecord(id: Long): Flow<ScanRecord?> = dao.observeById(id).map { it?.asDomain() }

    override suspend fun getRecord(id: Long): ScanRecord? = dao.getById(id)?.asDomain()

    override suspend fun save(record: ScanRecord): Long = dao.insert(record.asEntity())

    override suspend fun update(record: ScanRecord) {
        check(dao.update(record.asEntity()) == 1) { "Registro ${record.id} não existe mais" }
    }

    override suspend fun delete(id: Long) {
        dao.deleteById(id)
    }

    override suspend fun clear() {
        dao.deleteAll()
    }
}
