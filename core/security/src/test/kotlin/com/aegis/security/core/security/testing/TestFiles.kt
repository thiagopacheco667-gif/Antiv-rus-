package com.aegis.security.core.security.testing

import com.aegis.security.domain.analysis.AnalysisInput
import com.aegis.security.domain.model.AnalysisLimits
import com.aegis.security.domain.model.FileFormat
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.DeflaterOutputStream

/**
 * Geradores de arquivos de teste inofensivos, criados byte a byte. Nenhum malware real é usado:
 * os "indicadores" são estruturas sintéticas (nomes, flags, cabeçalhos) sem código executável.
 */
object TestFiles {

    class ZipSpec(val name: String, val data: ByteArray, val deflate: Boolean = false, val declaredSize: Long? = null)

    /** ZIP mínimo escrito manualmente: permite nomes "../", duplicados e tamanhos declarados arbitrários. */
    fun zip(entries: List<ZipSpec>, prefix: ByteArray = ByteArray(0)): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(prefix)
        val central = ByteArrayOutputStream()
        entries.forEach { e ->
            val payload = if (e.deflate) deflateRaw(e.data) else e.data
            val crc = CRC32().apply { update(e.data) }.value
            val name = e.name.toByteArray(Charsets.UTF_8)
            val offset = out.size()
            val size = e.declaredSize ?: e.data.size.toLong()
            out.write(le(4, 0x04034b50), le(2, 20), le(2, 0x800), le(2, if (e.deflate) 8 else 0), le(2, 0), le(2, 0), le(4, crc), le(4, payload.size.toLong()), le(4, size), le(2, name.size.toLong()), le(2, 0))
            out.write(name)
            out.write(payload)
            central.write(le(4, 0x02014b50), le(2, 20), le(2, 20), le(2, 0x800), le(2, if (e.deflate) 8 else 0), le(2, 0), le(2, 0), le(4, crc), le(4, payload.size.toLong()), le(4, size), le(2, name.size.toLong()), le(2, 0), le(2, 0), le(2, 0), le(2, 0), le(4, 0), le(4, offset.toLong()))
            central.write(name)
        }
        val cdOffset = out.size()
        val cd = central.toByteArray()
        out.write(cd)
        out.write(le(4, 0x06054b50), le(2, 0), le(2, 0), le(2, entries.size.toLong()), le(2, entries.size.toLong()), le(4, cd.size.toLong()), le(4, cdOffset.toLong()), le(2, 0))
        return out.toByteArray()
    }

    fun deflateRaw(data: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        DeflaterOutputStream(out, Deflater(Deflater.BEST_COMPRESSION, true)).use { it.write(data) }
        return out.toByteArray()
    }

    fun zlib(data: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        DeflaterOutputStream(out, Deflater(Deflater.BEST_COMPRESSION, false)).use { it.write(data) }
        return out.toByteArray()
    }

    /** PE32 mínimo (x86, console, uma seção) sem código real: a seção contém apenas zeros. */
    fun pe(sectionCharacteristics: Long = 0x60000020, sectionName: String = ".text", dll: Boolean = false, entryRva: Long = 0x1000): ByteArray {
        val buffer = ByteBuffer.allocate(0x400).order(ByteOrder.LITTLE_ENDIAN)
        buffer.put(0, 'M'.code.toByte()).put(1, 'Z'.code.toByte())
        buffer.putInt(0x3C, 0x80)
        buffer.put(0x80, 'P'.code.toByte()).put(0x81, 'E'.code.toByte())
        buffer.putShort(0x84, 0x14C.toShort())
        buffer.putShort(0x86, 1)
        buffer.putShort(0x94, 0xE0.toShort())
        buffer.putShort(0x96, (if (dll) 0x2102 else 0x0102).toShort())
        val opt = 0x98
        buffer.putShort(opt, 0x10B.toShort())
        buffer.putInt(opt + 16, entryRva.toInt())
        buffer.putShort(opt + 68, 3)
        buffer.putInt(opt + 92, 16)
        val section = opt + 0xE0
        sectionName.toByteArray().copyOf(8).forEachIndexed { i, b -> buffer.put(section + i, b) }
        buffer.putInt(section + 8, 0x200)
        buffer.putInt(section + 12, 0x1000)
        buffer.putInt(section + 16, 0x200)
        buffer.putInt(section + 20, 0x200)
        buffer.putInt(section + 36, sectionCharacteristics.toInt())
        return buffer.array()
    }

    /** ELF64 mínimo com um cabeçalho de programa PT_GNU_STACK e sem seções. */
    fun elf64(stackFlags: Int = 6): ByteArray {
        val buffer = ByteBuffer.allocate(64 + 56).order(ByteOrder.LITTLE_ENDIAN)
        buffer.put(byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte(), 2, 1, 1))
        buffer.putShort(16, 2)
        buffer.putShort(18, 0x3E)
        buffer.putLong(24, 0x401000)
        buffer.putLong(32, 64)
        buffer.putLong(40, 0)
        buffer.putShort(52, 64)
        buffer.putShort(54, 56)
        buffer.putShort(56, 1)
        buffer.putShort(58, 64)
        buffer.putShort(60, 0)
        buffer.putInt(64, 0x6474E551)
        buffer.putInt(68, stackFlags)
        return buffer.array()
    }

    fun input(file: File, format: FileFormat, limits: AnalysisLimits = AnalysisLimits()) = AnalysisInput(
        fileName = file.name,
        declaredExtension = file.name.substringAfterLast('.', "").takeIf { file.name.contains('.') },
        sizeBytes = file.length(),
        format = format,
        file = file,
        limits = limits,
    )

    private fun le(size: Int, value: Long): ByteArray = ByteArray(size) { i -> (value ushr (8 * i)).toByte() }

    private fun ByteArrayOutputStream.write(vararg parts: ByteArray) = parts.forEach { write(it) }
}
