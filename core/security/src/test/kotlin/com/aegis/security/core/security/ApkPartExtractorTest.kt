package com.aegis.security.core.security

import com.aegis.security.core.security.apk.ApkPartExtractor
import com.aegis.security.core.security.testing.TestFiles
import com.aegis.security.core.security.testing.TestFiles.ZipSpec
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.security.MessageDigest

class ApkPartExtractorTest {
    @get:Rule
    val temp = TemporaryFolder()

    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    @Test
    fun extractsOnlyCode_fromOneAbi_andSkipsResources() = runTest {
        val dex = ByteArray(100) { 1 }
        val apk = TestFiles.zip(
            listOf(
                ZipSpec("AndroidManifest.xml", ByteArray(10)),
                ZipSpec("classes.dex", dex, deflate = true),
                ZipSpec("lib/arm64-v8a/libgame.so", ByteArray(50) { 2 }, deflate = true),
                ZipSpec("lib/armeabi-v7a/libgame.so", ByteArray(50) { 3 }),
                ZipSpec("assets/hidden.dex", ByteArray(20) { 4 }),
                ZipSpec("assets/textures/big.png", ByteArray(5000)),
            ),
        )
        val parts = ApkPartExtractor().extract(apk.inputStream(), temp.root, maxPartBytes = 1_000) {}
        assertEquals(listOf("classes.dex", "assets/hidden.dex", "lib/arm64-v8a/libgame.so"), parts.map { it.name })
        assertEquals(sha(dex), parts.first().sha256)
        assertTrue(parts.all { it.file?.exists() == true })
        assertEquals(3, temp.root.listFiles()!!.size)
    }

    @Test
    fun partsAboveUploadLimit_areHashedButNotKept() = runTest {
        val apk = TestFiles.zip(listOf(ZipSpec("classes.dex", ByteArray(4096) { 5 }, deflate = true)))
        val part = ApkPartExtractor().extract(apk.inputStream(), temp.root, maxPartBytes = 1_000) {}.single()
        assertEquals(4096, part.sizeBytes)
        assertNull(part.file)
        assertEquals(0, temp.root.listFiles()!!.size)
    }
}
