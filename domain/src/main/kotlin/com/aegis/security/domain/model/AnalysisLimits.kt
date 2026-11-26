package com.aegis.security.domain.model

import kotlinx.serialization.Serializable

/** Limites configuráveis que protegem o aparelho contra arquivos maliciosos ou gigantes. */
@Serializable
data class AnalysisLimits(
    val maxFileSizeMb: Int = 512,
    val maxArchiveEntries: Int = 10_000,
    val maxTotalUncompressedMb: Int = 2_048,
    val maxCompressionRatio: Int = 100,
    val maxNestingDepth: Int = 3,
    val maxContentScanMb: Int = 64,
) {
    init {
        require(maxFileSizeMb in 1..8_192)
        require(maxArchiveEntries in 1..1_000_000)
        require(maxTotalUncompressedMb in 1..65_536)
        require(maxCompressionRatio in 2..10_000)
        require(maxNestingDepth in 0..10)
        require(maxContentScanMb in 1..1_024)
    }

    val maxFileSizeBytes: Long get() = maxFileSizeMb.toLong() * MB
    val maxTotalUncompressedBytes: Long get() = maxTotalUncompressedMb.toLong() * MB
    val maxContentScanBytes: Long get() = maxContentScanMb.toLong() * MB

    companion object {
        const val MB = 1024L * 1024L
        val FileSizeOptionsMb = listOf(64, 128, 256, 512, 1024, 2048)
        val ArchiveEntryOptions = listOf(1_000, 5_000, 10_000, 50_000)
        val TotalUncompressedOptionsMb = listOf(256, 512, 1024, 2048, 4096)
        val CompressionRatioOptions = listOf(20, 50, 100, 200, 500)
        val NestingDepthOptions = listOf(0, 1, 2, 3, 5)
        val ContentScanOptionsMb = listOf(16, 32, 64, 128, 256)
    }
}
