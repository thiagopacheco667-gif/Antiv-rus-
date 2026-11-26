package com.aegis.security.core.database.model

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Linha do histórico. Guarda somente metadados e o resumo das evidências;
 * o conteúdo do arquivo analisado nunca é armazenado.
 */
@Entity(
    tableName = "scan_records",
    indices = [
        Index(value = ["scanned_at"]),
        Index(value = ["sha256"]),
    ],
)
data class ScanRecordEntity(
    @PrimaryKey(autoGenerate = true)
    @ColumnInfo(name = "id")
    val id: Long = 0,
    @ColumnInfo(name = "file_name")
    val fileName: String,
    @ColumnInfo(name = "sha256")
    val sha256: String,
    @ColumnInfo(name = "format")
    val format: String,
    @ColumnInfo(name = "size_bytes")
    val sizeBytes: Long?,
    @ColumnInfo(name = "scanned_at")
    val scannedAtEpochMillis: Long,
    @ColumnInfo(name = "verdict")
    val verdict: String,
    @ColumnInfo(name = "origin")
    val origin: String,
    @ColumnInfo(name = "evidence_summary")
    val evidenceSummary: String,
)
