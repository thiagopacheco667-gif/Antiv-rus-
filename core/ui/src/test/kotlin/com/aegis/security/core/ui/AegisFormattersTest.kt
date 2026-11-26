package com.aegis.security.core.ui

import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Locale

class AegisFormattersTest {

    @Test
    fun fileSize_usesBinaryUnits() {
        assertEquals("0 B", AegisFormatters.fileSize(0, Locale.ROOT))
        assertEquals("1023 B", AegisFormatters.fileSize(1023, Locale.ROOT))
        assertEquals("1.0 KB", AegisFormatters.fileSize(1024, Locale.ROOT))
        assertEquals("32.0 MB", AegisFormatters.fileSize(32L * 1024 * 1024, Locale.ROOT))
        assertEquals("1.5 GB", AegisFormatters.fileSize(1536L * 1024 * 1024, Locale.ROOT))
    }

    @Test(expected = IllegalArgumentException::class)
    fun fileSize_rejectsNegativeValues() {
        AegisFormatters.fileSize(-1)
    }

    @Test
    fun shortHash_keepsBothEnds_andLeavesShortValuesIntact() {
        val sha256 = "0123456789abcdef".repeat(4)
        assertEquals("01234567…89abcdef", AegisFormatters.shortHash(sha256))
        assertEquals("abc", AegisFormatters.shortHash("abc"))
    }
}
