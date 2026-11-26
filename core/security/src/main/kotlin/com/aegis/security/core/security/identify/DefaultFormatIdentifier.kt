package com.aegis.security.core.security.identify

import com.aegis.security.core.security.util.BinaryFile
import com.aegis.security.core.security.util.startsWith
import com.aegis.security.core.security.zip.ZipDirectoryParser
import com.aegis.security.domain.analysis.FormatIdentifier
import com.aegis.security.domain.model.FileFormat
import java.io.File
import java.io.IOException
import javax.inject.Inject

/**
 * Identificação pelo conteúdo (assinaturas mágicas), nunca pela extensão.
 * Referências: PKWARE APPNOTE (ZIP), Dalvik Executable format (DEX),
 * Microsoft PE/COFF, System V ABI (ELF), ISO 32000 (PDF).
 */
class DefaultFormatIdentifier @Inject constructor() : FormatIdentifier {

    override fun identifyHeader(header: ByteArray): FileFormat = when {
        header.startsWith(ZIP_LOCAL) || header.startsWith(ZIP_EMPTY) -> FileFormat.ZIP
        isDex(header) -> FileFormat.DEX
        header.startsWith(MZ) -> FileFormat.PE_EXECUTABLE
        header.startsWith(ELF) -> FileFormat.ELF
        pdfHeaderOffset(header) >= 0 -> FileFormat.PDF
        else -> FileFormat.UNKNOWN
    }

    override fun refine(file: File, headerFormat: FileFormat): FileFormat = when (headerFormat) {
        FileFormat.ZIP -> refineZip(file)
        FileFormat.PE_EXECUTABLE -> refinePe(file)
        else -> headerFormat
    }

    private fun refineZip(file: File): FileFormat = try {
        val names = ZipDirectoryParser.parse(file, maxEntries = 100_000).entries.map { it.name }
        when {
            "AndroidManifest.xml" in names && names.any { DEX_ENTRY.matches(it) } -> FileFormat.APK
            "META-INF/MANIFEST.MF" in names || names.any { it.endsWith(".class") } -> FileFormat.JAR
            else -> FileFormat.ZIP
        }
    } catch (error: IOException) {
        FileFormat.ZIP
    }

    private fun refinePe(file: File): FileFormat = try {
        BinaryFile(file).use { bin ->
            val peOffset = bin.u32(0x3C)
            if (!bin.contains(peOffset, 24) || !bin.bytes(peOffset, 4).startsWith(PE_SIGNATURE)) {
                FileFormat.PE_EXECUTABLE
            } else {
                val characteristics = bin.u16(peOffset + 22)
                if (characteristics and IMAGE_FILE_DLL != 0) FileFormat.PE_LIBRARY else FileFormat.PE_EXECUTABLE
            }
        }
    } catch (error: IOException) {
        FileFormat.PE_EXECUTABLE
    }

    companion object {
        private val ZIP_LOCAL = byteArrayOf(0x50, 0x4B, 0x03, 0x04)
        private val ZIP_EMPTY = byteArrayOf(0x50, 0x4B, 0x05, 0x06)
        private val MZ = byteArrayOf(0x4D, 0x5A)
        private val ELF = byteArrayOf(0x7F, 0x45, 0x4C, 0x46)
        private val PDF = "%PDF-".toByteArray()
        internal val PE_SIGNATURE = byteArrayOf(0x50, 0x45, 0, 0)
        internal const val IMAGE_FILE_DLL = 0x2000
        private val DEX_ENTRY = Regex("^classes\\d*\\.dex$")

        internal fun isDex(header: ByteArray): Boolean =
            header.size >= 8 && header.startsWith("dex\n".toByteArray()) &&
                (4..6).all { header[it] in '0'.code.toByte()..'9'.code.toByte() } && header[7] == 0.toByte()

        /** O cabeçalho PDF pode aparecer nos primeiros 1024 bytes (ISO 32000, nota de implementação). */
        internal fun pdfHeaderOffset(header: ByteArray): Int {
            val limit = minOf(header.size, 1024)
            for (i in 0..limit - PDF.size) if (header.startsWith(PDF, i)) return i
            return -1
        }
    }
}
