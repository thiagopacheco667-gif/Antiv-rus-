package com.aegis.security.core.security.util

import java.io.Closeable
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile

class MalformedFileException(message: String) : IOException(message)

/**
 * Leitura aleatória com verificação de limites. Toda leitura fora do arquivo gera
 * [MalformedFileException] em vez de dados inválidos ou exceções genéricas.
 */
internal class BinaryFile(file: File) : Closeable {
    private val raf = RandomAccessFile(file, "r")
    val length: Long = raf.length()

    fun bytes(offset: Long, size: Int): ByteArray {
        check(offset, size.toLong())
        val buffer = ByteArray(size)
        raf.seek(offset)
        raf.readFully(buffer)
        return buffer
    }

    /** Lê até [size] bytes, truncando no fim do arquivo. */
    fun bytesUpTo(offset: Long, size: Int): ByteArray {
        if (offset < 0 || offset >= length) return ByteArray(0)
        val available = minOf(size.toLong(), length - offset).toInt()
        return bytes(offset, available)
    }

    fun u8(offset: Long): Int = bytes(offset, 1)[0].toInt() and 0xFF

    fun u16(offset: Long, bigEndian: Boolean = false): Int {
        val b = bytes(offset, 2)
        return if (bigEndian) b.be(0, 2).toInt() else b.le(0, 2).toInt()
    }

    fun u32(offset: Long, bigEndian: Boolean = false): Long {
        val b = bytes(offset, 4)
        return if (bigEndian) b.be(0, 4) else b.le(0, 4)
    }

    /** Valores acima de Long.MAX_VALUE são tratados como malformados. */
    fun u64(offset: Long, bigEndian: Boolean = false): Long {
        val b = bytes(offset, 8)
        val value = if (bigEndian) b.be(0, 8) else b.le(0, 8)
        if (value < 0) throw MalformedFileException("Valor de 64 bits fora do intervalo em $offset")
        return value
    }

    /** String terminada em zero, com tamanho máximo. */
    fun cString(offset: Long, maxLength: Int = 256): String {
        val raw = bytesUpTo(offset, maxLength)
        val end = raw.indexOf(0.toByte()).let { if (it < 0) raw.size else it }
        return String(raw, 0, end, Charsets.ISO_8859_1)
    }

    fun contains(offset: Long, size: Long): Boolean =
        offset >= 0 && size >= 0 && offset <= length && size <= length - offset

    private fun check(offset: Long, size: Long) {
        if (!contains(offset, size)) {
            throw MalformedFileException("Leitura fora dos limites do arquivo (offset $offset, $size bytes)")
        }
    }

    override fun close() = raf.close()
}

internal fun ByteArray.le(offset: Int, size: Int): Long {
    var value = 0L
    for (i in size - 1 downTo 0) value = (value shl 8) or (this[offset + i].toLong() and 0xFF)
    return value
}

internal fun ByteArray.be(offset: Int, size: Int): Long {
    var value = 0L
    for (i in 0 until size) value = (value shl 8) or (this[offset + i].toLong() and 0xFF)
    return value
}

internal fun ByteArray.startsWith(prefix: ByteArray, at: Int = 0): Boolean {
    if (size - at < prefix.size) return false
    for (i in prefix.indices) if (this[at + i] != prefix[i]) return false
    return true
}

internal fun ByteArray.indexOf(pattern: ByteArray, from: Int = 0, until: Int = size): Int {
    if (pattern.isEmpty()) return from
    var i = from
    while (i <= until - pattern.size) {
        if (startsWith(pattern, i)) return i
        i++
    }
    return -1
}

internal fun hex(bytes: ByteArray): String = buildString(bytes.size * 2) {
    for (b in bytes) {
        val v = b.toInt() and 0xFF
        append(HEX[v ushr 4])
        append(HEX[v and 0x0F])
    }
}

private val HEX = "0123456789abcdef".toCharArray()

internal fun hex32(value: Long) = "0x" + value.toString(16).padStart(8, '0')

/** Lista com no máximo [max] itens e indicação do restante, para evidências legíveis. */
internal fun List<String>.summarize(max: Int = 5): String =
    if (size <= max) joinToString(", ") else take(max).joinToString(", ") + " (+${size - max})"
