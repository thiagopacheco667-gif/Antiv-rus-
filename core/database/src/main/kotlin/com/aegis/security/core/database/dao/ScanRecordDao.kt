package com.aegis.security.core.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.aegis.security.core.database.model.ScanRecordEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ScanRecordDao {
    @Query("SELECT * FROM scan_records ORDER BY scanned_at DESC, id DESC")
    fun observeAll(): Flow<List<ScanRecordEntity>>

    @Query("SELECT * FROM scan_records ORDER BY scanned_at DESC, id DESC LIMIT :limit")
    fun observeRecent(limit: Int): Flow<List<ScanRecordEntity>>

    @Query("SELECT COUNT(*) FROM scan_records")
    fun observeCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM scan_records WHERE verdict = :verdict")
    fun observeCountByVerdict(verdict: String): Flow<Int>

    @Query("SELECT * FROM scan_records WHERE id = :id")
    fun observeById(id: Long): Flow<ScanRecordEntity?>

    @Query("SELECT * FROM scan_records WHERE id = :id")
    suspend fun getById(id: Long): ScanRecordEntity?

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(entity: ScanRecordEntity): Long

    @Update
    suspend fun update(entity: ScanRecordEntity): Int

    @Query("DELETE FROM scan_records WHERE id = :id")
    suspend fun deleteById(id: Long): Int

    @Query("DELETE FROM scan_records")
    suspend fun deleteAll(): Int
}
