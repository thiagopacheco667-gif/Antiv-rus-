package com.aegis.security.core.security

import com.aegis.security.core.security.identify.DefaultFormatIdentifier
import com.aegis.security.core.security.testing.TestFiles
import com.aegis.security.core.security.testing.TestFiles.ZipSpec
import com.aegis.security.domain.model.FileFormat
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class FormatIdentifierTest {
    @get:Rule
    val temp = TemporaryFolder()
    private val identifier = DefaultFormatIdentifier()

    @Test
    fun identifiesByContent_notByExtension() {
        assertEquals(FileFormat.PE_EXECUTABLE, identifier.identifyHeader(TestFiles.pe()))
        assertEquals(FileFormat.ELF, identifier.identifyHeader(TestFiles.elf64()))
        assertEquals(FileFormat.PDF, identifier.identifyHeader("%PDF-1.7\n".toByteArray()))
        assertEquals(FileFormat.DEX, identifier.identifyHeader("dex\n035\u0000".toByteArray()))
        assertEquals(FileFormat.ZIP, identifier.identifyHeader(TestFiles.zip(listOf(ZipSpec("a.txt", "a".toByteArray())))))
        assertEquals(FileFormat.UNKNOWN, identifier.identifyHeader("texto simples".toByteArray()))
    }

    @Test
    fun emptyFile_isUnknown() {
        assertEquals(FileFormat.UNKNOWN, identifier.identifyHeader(ByteArray(0)))
    }

    @Test
    fun pdfHeaderMayBeShiftedWithin1024Bytes() {
        assertEquals(FileFormat.PDF, identifier.identifyHeader(ByteArray(100) + "%PDF-1.4".toByteArray()))
    }

    @Test
    fun zipIsRefinedToApkOrJar_byEntries() {
        val apk = temp.newFile("disfarcado.pdf").apply {
            writeBytes(TestFiles.zip(listOf(ZipSpec("AndroidManifest.xml", ByteArray(8)), ZipSpec("classes.dex", ByteArray(8)))))
        }
        assertEquals(FileFormat.APK, identifier.refine(apk, FileFormat.ZIP))
        val jar = temp.newFile("lib.zip").apply { writeBytes(TestFiles.zip(listOf(ZipSpec("META-INF/MANIFEST.MF", "x".toByteArray())))) }
        assertEquals(FileFormat.JAR, identifier.refine(jar, FileFormat.ZIP))
    }

    @Test
    fun peIsRefinedToDll_byCharacteristics() {
        val dll = temp.newFile("x.exe").apply { writeBytes(TestFiles.pe(dll = true)) }
        assertEquals(FileFormat.PE_LIBRARY, identifier.refine(dll, FileFormat.PE_EXECUTABLE))
    }
}
