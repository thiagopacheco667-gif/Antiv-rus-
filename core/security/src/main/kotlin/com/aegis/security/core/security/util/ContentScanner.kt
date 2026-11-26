package com.aegis.security.core.security.util

import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.File
import java.io.FileInputStream
import kotlin.math.ln

/** Resultado da varredura de conteúdo: padrões encontrados (com offset) e URLs legíveis. */
internal data class ContentScanResult(
    val matches: Map<String, Long>,
    val urls: List<String>,
    val bytesScanned: Long,
    val truncated: Boolean,
)

/**
 * Busca de padrões textuais (ASCII, sem diferenciar maiúsculas) em blocos, sem carregar o
 * arquivo inteiro na memória. Também coleta URLs legíveis. Nunca interpreta o conteúdo.
 */
internal object ContentScanner {
    private const val CHUNK = 64 * 1024
    private const val MAX_URLS = 25
    private const val MAX_URL_LENGTH = 200

    suspend fun scan(file: File, patterns: Collection<String>, maxBytes: Long): ContentScanResult {
        val lowered = patterns.distinct().map { it to it.lowercase().toByteArray(Charsets.ISO_8859_1) }
        val byFirst = Array(256) { mutableListOf<Pair<String, ByteArray>>() }
        lowered.forEach { (name, bytes) -> if (bytes.isNotEmpty()) byFirst[bytes[0].toInt() and 0xFF] += name to bytes }
        val maxPattern = lowered.maxOfOrNull { it.second.size } ?: 1
        val overlap = maxOf(maxPattern, MAX_URL_LENGTH)

        val matches = linkedMapOf<String, Long>()
        val urls = linkedSetOf<String>()
        val limit = minOf(maxBytes, file.length())
        var base = 0L
        val buffer = ByteArray(CHUNK + overlap)
        var carried = 0

        FileInputStream(file).use { input ->
            while (base + carried < limit) {
                currentCoroutineContext().ensureActive()
                val toRead = minOf((buffer.size - carried).toLong(), limit - base - carried).toInt()
                val read = input.read(buffer, carried, toRead)
                if (read <= 0) break
                val valid = carried + read
                val isLast = base + valid >= limit
                val searchEnd = if (isLast) valid else valid - overlap + 1
                for (i in 0 until maxOf(searchEnd, 0)) {
                    val first = lower(buffer[i])
                    for ((name, pattern) in byFirst[first]) {
                        if (name !in matches && matchesAt(buffer, i, valid, pattern)) matches[name] = base + i
                    }
                    if (urls.size < MAX_URLS && first == 'h'.code) extractUrl(buffer, i, valid)?.let(urls::add)
                }
                val consumed = maxOf(searchEnd, 0)
                carried = valid - consumed
                System.arraycopy(buffer, consumed, buffer, 0, carried)
                base += consumed
                if (isLast) break
            }
        }
        return ContentScanResult(matches, urls.toList(), limit, truncated = file.length() > maxBytes)
    }

    private fun lower(b: Byte): Int {
        val v = b.toInt() and 0xFF
        return if (v in 'A'.code..'Z'.code) v + 32 else v
    }

    private fun matchesAt(buffer: ByteArray, at: Int, end: Int, pattern: ByteArray): Boolean {
        if (end - at < pattern.size) return false
        for (j in pattern.indices) if (lower(buffer[at + j]) != (pattern[j].toInt() and 0xFF)) return false
        return true
    }

    private val HTTP = "http://".toByteArray()
    private val HTTPS = "https://".toByteArray()

    private fun extractUrl(buffer: ByteArray, at: Int, end: Int): String? {
        val prefix = when {
            matchesAt(buffer, at, end, HTTPS) -> HTTPS.size
            matchesAt(buffer, at, end, HTTP) -> HTTP.size
            else -> return null
        }
        var i = at + prefix
        while (i < end && i - at < MAX_URL_LENGTH) {
            val c = buffer[i].toInt() and 0xFF
            if (c <= 0x20 || c >= 0x7F || c == '"'.code || c == '\''.code || c == '<'.code || c == '>'.code) break
            i++
        }
        if (i - at - prefix < 4) return null
        val url = String(buffer, at, i - at, Charsets.ISO_8859_1)
        val host = url.substring(prefix).substringBefore('/')
        return if (host.contains('.') && host.all { it.isLetterOrDigit() || it in ".-:[]" }) url else null
    }
}

/** Entropia de Shannon (bits por byte, 0..8) de uma região, lida em blocos. */
internal fun BinaryFile.entropy(offset: Long, size: Long, maxBytes: Long = 16L * 1024 * 1024): Double {
    val total = minOf(size, maxBytes, maxOf(length - offset, 0))
    if (total <= 0) return 0.0
    val counts = LongArray(256)
    var position = offset
    var remaining = total
    while (remaining > 0) {
        val chunk = bytes(position, minOf(remaining, 64L * 1024).toInt())
        for (b in chunk) counts[b.toInt() and 0xFF]++
        position += chunk.size
        remaining -= chunk.size
    }
    var entropy = 0.0
    for (c in counts) {
        if (c == 0L) continue
        val p = c.toDouble() / total
        entropy -= p * (ln(p) / ln(2.0))
    }
    return entropy
}
