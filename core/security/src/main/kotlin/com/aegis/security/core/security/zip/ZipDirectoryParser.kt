package com.aegis.security.core.security.zip

import com.aegis.security.core.security.util.BinaryFile
import com.aegis.security.core.security.util.MalformedFileException
import com.aegis.security.core.security.util.le
import com.aegis.security.core.security.util.startsWith
import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream

internal data class ZipEntryInfo(
    val name: String,
    val compressedSize: Long,
    val uncompressedSize: Long,
    val method: Int,
    val flags: Int,
    val localHeaderOffset: Long,
    val crc32: Long,
) {
    val isDirectory: Boolean get() = name.endsWith('/')
    val isEncrypted: Boolean get() = flags and 0x1 != 0
}

internal data class ZipDirectory(
    val entries: List<ZipEntryInfo>,
    val declaredEntryCount: Long,
    val centralDirectoryOffset: Long,
    val centralDirectorySize: Long,
    val eocdOffset: Long,
    val zip64: Boolean,
    val commentLength: Int,
    /** `true` quando o diretório declara mais entradas que o limite configurado. */
    val truncated: Boolean,
    /** Bloco de assinatura APK v2+ ("APK Sig Block 42") imediatamente antes do diretório central. */
    val hasApkSigningBlock: Boolean,
)

/**
 * Leitor próprio do diretório central ZIP (PKWARE APPNOTE 6.3.x).
 *
 * Não usamos java.util.zip.ZipFile porque, no Android 14+, ele rejeita nomes com "../" — exatamente
 * o que precisamos detectar — e porque ele não expõe entradas duplicadas. Nada é extraído aqui.
 */
internal object ZipDirectoryParser {
    private const val EOCD_SIGNATURE = 0x06054b50L
    private const val ZIP64_LOCATOR_SIGNATURE = 0x07064b50L
    private const val ZIP64_EOCD_SIGNATURE = 0x06064b50L
    private const val CENTRAL_SIGNATURE = 0x02014b50L
    private const val LOCAL_SIGNATURE = 0x04034b50L
    private const val EOCD_MIN = 22
    private const val MAX_COMMENT = 0xFFFF
    private val APK_SIG_BLOCK_MAGIC = "APK Sig Block 42".toByteArray()

    fun parse(file: File, maxEntries: Int): ZipDirectory = BinaryFile(file).use { bin ->
        if (bin.length < EOCD_MIN) throw MalformedFileException("Arquivo pequeno demais para ser um ZIP")
        val eocd = findEocd(bin)
        var totalEntries = bin.u16(eocd + 10).toLong()
        var cdSize = bin.u32(eocd + 12)
        var cdOffset = bin.u32(eocd + 16)
        val commentLength = bin.u16(eocd + 20)
        var zip64 = false

        if (totalEntries == 0xFFFFL || cdSize == 0xFFFFFFFFL || cdOffset == 0xFFFFFFFFL) {
            val locator = eocd - 20
            if (locator >= 0 && bin.u32(locator) == ZIP64_LOCATOR_SIGNATURE) {
                val zip64Eocd = bin.u64(locator + 8)
                if (bin.u32(zip64Eocd) != ZIP64_EOCD_SIGNATURE) throw MalformedFileException("Registro ZIP64 inválido")
                totalEntries = bin.u64(zip64Eocd + 32)
                cdSize = bin.u64(zip64Eocd + 40)
                cdOffset = bin.u64(zip64Eocd + 48)
                zip64 = true
            }
        }
        if (!bin.contains(cdOffset, cdSize) || cdOffset + cdSize > eocd) {
            throw MalformedFileException("Diretório central fora dos limites do arquivo")
        }

        val hasSigBlock = cdOffset >= 16 && bin.bytes(cdOffset - 16, 16).startsWith(APK_SIG_BLOCK_MAGIC)
        val entries = readCentralDirectory(file, cdOffset, cdSize, maxEntries)
        ZipDirectory(
            entries = entries,
            declaredEntryCount = totalEntries,
            centralDirectoryOffset = cdOffset,
            centralDirectorySize = cdSize,
            eocdOffset = eocd,
            zip64 = zip64,
            commentLength = commentLength,
            truncated = totalEntries > maxEntries || entries.size >= maxEntries,
            hasApkSigningBlock = hasSigBlock,
        )
    }

    /** Offset do início dos dados de uma entrada (após o cabeçalho local). */
    fun dataOffset(bin: BinaryFile, entry: ZipEntryInfo): Long {
        val header = entry.localHeaderOffset
        if (bin.u32(header) != LOCAL_SIGNATURE) throw MalformedFileException("Cabeçalho local inválido para ${entry.name}")
        val nameLength = bin.u16(header + 26)
        val extraLength = bin.u16(header + 28)
        return header + 30 + nameLength + extraLength
    }

    private fun findEocd(bin: BinaryFile): Long {
        val searchSize = minOf(bin.length, (EOCD_MIN + MAX_COMMENT).toLong()).toInt()
        val start = bin.length - searchSize
        val tail = bin.bytes(start, searchSize)
        for (i in tail.size - EOCD_MIN downTo 0) {
            if (tail.le(i, 4) == EOCD_SIGNATURE) {
                val commentLength = tail.le(i + 20, 2).toInt()
                if (i + EOCD_MIN + commentLength <= tail.size) return start + i
            }
        }
        throw MalformedFileException("Registro de fim do diretório central (EOCD) não encontrado")
    }

    private fun readCentralDirectory(file: File, offset: Long, size: Long, maxEntries: Int): List<ZipEntryInfo> {
        val entries = ArrayList<ZipEntryInfo>()
        BufferedInputStream(FileInputStream(file), 64 * 1024).use { input ->
            skipFully(input, offset)
            var consumed = 0L
            val fixed = ByteArray(46)
            while (consumed + 46 <= size && entries.size < maxEntries) {
                readFully(input, fixed)
                if (fixed.le(0, 4) != CENTRAL_SIGNATURE) throw MalformedFileException("Entrada do diretório central inválida")
                val flags = fixed.le(8, 2).toInt()
                val method = fixed.le(10, 2).toInt()
                val crc = fixed.le(16, 4)
                var compressed = fixed.le(20, 4)
                var uncompressed = fixed.le(24, 4)
                val nameLength = fixed.le(28, 2).toInt()
                val extraLength = fixed.le(30, 2).toInt()
                val commentLength = fixed.le(32, 2).toInt()
                var localOffset = fixed.le(42, 4)
                val variableLength = nameLength + extraLength + commentLength
                if (consumed + 46 + variableLength > size) throw MalformedFileException("Entrada truncada no diretório central")

                val nameBytes = ByteArray(nameLength).also { readFully(input, it) }
                val extra = ByteArray(extraLength).also { readFully(input, it) }
                skipFully(input, commentLength.toLong())

                if (compressed == 0xFFFFFFFFL || uncompressed == 0xFFFFFFFFL || localOffset == 0xFFFFFFFFL) {
                    val zip64 = parseZip64Extra(extra, uncompressed == 0xFFFFFFFFL, compressed == 0xFFFFFFFFL, localOffset == 0xFFFFFFFFL)
                    zip64.uncompressed?.let { uncompressed = it }
                    zip64.compressed?.let { compressed = it }
                    zip64.offset?.let { localOffset = it }
                }
                val utf8 = flags and 0x800 != 0
                val name = String(nameBytes, if (utf8) Charsets.UTF_8 else Charsets.ISO_8859_1)
                entries += ZipEntryInfo(name, compressed, uncompressed, method, flags, localOffset, crc)
                consumed += 46 + variableLength
            }
        }
        return entries
    }

    private class Zip64Values(val uncompressed: Long?, val compressed: Long?, val offset: Long?)

    private fun parseZip64Extra(extra: ByteArray, needU: Boolean, needC: Boolean, needO: Boolean): Zip64Values {
        var i = 0
        while (i + 4 <= extra.size) {
            val id = extra.le(i, 2).toInt()
            val length = extra.le(i + 2, 2).toInt()
            if (i + 4 + length > extra.size) break
            if (id == 0x0001) {
                var p = i + 4
                fun next(): Long? = if (p + 8 <= i + 4 + length) extra.le(p, 8).also { p += 8 } else null
                val u = if (needU) next() else null
                val c = if (needC) next() else null
                val o = if (needO) next() else null
                if (listOfNotNull(u, c, o).any { it < 0 }) throw MalformedFileException("Campo ZIP64 inválido")
                return Zip64Values(u, c, o)
            }
            i += 4 + length
        }
        return Zip64Values(null, null, null)
    }

    private fun readFully(input: BufferedInputStream, target: ByteArray) {
        var read = 0
        while (read < target.size) {
            val n = input.read(target, read, target.size - read)
            if (n < 0) throw MalformedFileException("Fim inesperado do arquivo")
            read += n
        }
    }

    private fun skipFully(input: BufferedInputStream, count: Long) {
        var remaining = count
        while (remaining > 0) {
            val skipped = input.skip(remaining)
            if (skipped <= 0) {
                if (input.read() < 0) throw MalformedFileException("Fim inesperado do arquivo")
                remaining--
            } else {
                remaining -= skipped
            }
        }
    }
}
