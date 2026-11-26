package com.aegis.security.core.security.pdf

import com.aegis.security.domain.analysis.AnalysisEngine
import com.aegis.security.domain.analysis.AnalysisFact
import com.aegis.security.domain.analysis.AnalysisInput
import com.aegis.security.domain.analysis.DetailEntry
import com.aegis.security.domain.analysis.DetailKind
import com.aegis.security.domain.analysis.DetailSection
import com.aegis.security.domain.analysis.EngineDescriptor
import com.aegis.security.domain.analysis.EngineResult
import com.aegis.security.domain.model.FileFormat
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.util.zip.DataFormatException
import java.util.zip.Inflater
import javax.inject.Inject

data class PdfFacts(
    val version: String?,
    val headerOffset: Int,
    val objectCount: Int,
    val streamCount: Int,
    val eofMarkers: Int,
    /** Contagem de nomes relevantes (após decodificar escapes #xx). */
    val keywords: Map<String, Int>,
    val obfuscatedNames: List<String>,
    val metadata: Map<String, String>,
    val uris: List<String>,
    val objectStreamsInspected: Int,
    val objectStreamsSkipped: Int,
    val truncatedScan: Boolean,
) : AnalysisFact {
    fun count(name: String) = keywords[name] ?: 0
}

/**
 * Inspeção estrutural de PDF sem renderizar nem executar conteúdo ativo.
 * Tokeniza nomes (/JavaScript, /OpenAction, /Launch...), decodifica escapes #xx usados para
 * ofuscação e inspeciona fluxos de objetos (/ObjStm) comprimidos com FlateDecode, com limites.
 */
class PdfEngine @Inject constructor() : AnalysisEngine {
    override val descriptor = EngineDescriptor("pdf", "Analisador de PDF", setOf(FileFormat.PDF))

    override suspend fun analyze(input: AnalysisInput): EngineResult {
        val facts = PdfScanner(input.limits.maxContentScanBytes).scan(input.file)
        if (facts.headerOffset < 0) return EngineResult.Failed("cabeçalho %PDF não encontrado")
        val details = listOf(
            DetailSection(
                DetailKind.METADATA,
                "Documento PDF",
                buildList {
                    add(DetailEntry("Versão", facts.version ?: "—"))
                    facts.metadata.forEach { (key, value) -> add(DetailEntry(METADATA_LABELS[key] ?: key, value)) }
                    add(DetailEntry("Criptografado", if (facts.count("Encrypt") > 0) "Sim" else "Não"))
                },
            ),
            DetailSection(
                DetailKind.STRUCTURE,
                "Estrutura do documento",
                buildList {
                    add(DetailEntry("Objetos", facts.objectCount.toString()))
                    add(DetailEntry("Fluxos (streams)", facts.streamCount.toString()))
                    add(DetailEntry("Revisões (%%EOF)", facts.eofMarkers.toString()))
                    add(DetailEntry("Fluxos de objetos inspecionados", "${facts.objectStreamsInspected} (não inspecionados: ${facts.objectStreamsSkipped})"))
                    INTERESTING.forEach { key -> facts.keywords[key]?.let { add(DetailEntry("/$key", it.toString(), monospace = true)) } }
                    if (facts.obfuscatedNames.isNotEmpty()) add(DetailEntry("Nomes ofuscados", facts.obfuscatedNames.joinToString(), monospace = true))
                    if (facts.uris.isNotEmpty()) add(DetailEntry("Links (URI)", facts.uris.joinToString("\n"), monospace = true))
                    if (facts.truncatedScan) add(DetailEntry("Inspeção", "Parcial (limite de conteúdo atingido)"))
                },
            ),
        )
        val incomplete = buildList {
            if (facts.truncatedScan) add("conteúdo além de ${input.limits.maxContentScanMb} MB não inspecionado")
            if (facts.objectStreamsSkipped > 0) add("${facts.objectStreamsSkipped} fluxo(s) de objetos não inspecionado(s)")
            if (facts.count("Encrypt") > 0) add("documento criptografado")
        }
        return EngineResult.Completed(details, listOf(facts), incomplete)
    }

    companion object {
        val INTERESTING = listOf(
            "JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "EmbeddedFiles", "URI",
            "SubmitForm", "ImportData", "GoToR", "GoToE", "AcroForm", "XFA", "RichMedia", "ObjStm",
            "Encrypt", "JBIG2Decode",
        )
        val METADATA_KEYS = setOf("Title", "Author", "Subject", "Creator", "Producer", "CreationDate", "ModDate")
        private val METADATA_LABELS = mapOf(
            "Title" to "Título", "Author" to "Autor", "Subject" to "Assunto", "Creator" to "Aplicativo de criação",
            "Producer" to "Gerador", "CreationDate" to "Criado em", "ModDate" to "Modificado em",
        )
    }
}

internal class PdfScanner(private val maxBytes: Long) {
    private val keywords = HashMap<String, Int>()
    private val obfuscated = linkedSetOf<String>()
    private val metadata = linkedMapOf<String, String>()
    private val uris = linkedSetOf<String>()
    private var objects = 0
    private var streams = 0
    private var eofs = 0
    private var objStmInspected = 0
    private var objStmSkipped = 0
    private var budgetForInflate = 32L * 1024 * 1024

    suspend fun scan(file: File): PdfFacts {
        val headerProbe = file.inputStream().use { it.readNBytesCompat(1024) }
        val headerOffset = String(headerProbe, Charsets.ISO_8859_1).indexOf("%PDF-")
        val version = if (headerOffset >= 0) {
            String(headerProbe, Charsets.ISO_8859_1).substring(headerOffset + 5).takeWhile { it.isDigit() || it == '.' }.take(4)
        } else {
            null
        }
        val truncated = file.length() > maxBytes
        BufferedInputStream(FileInputStream(file), 64 * 1024).use { raw ->
            tokenize(LimitedStream(raw, maxBytes), depth = 0)
        }
        return PdfFacts(
            version = version,
            headerOffset = headerOffset,
            objectCount = objects,
            streamCount = streams,
            eofMarkers = eofs,
            keywords = keywords.filterKeys { it in PdfEngine.INTERESTING },
            obfuscatedNames = obfuscated.take(20),
            metadata = metadata,
            uris = uris.take(20),
            objectStreamsInspected = objStmInspected,
            objectStreamsSkipped = objStmSkipped,
            truncatedScan = truncated,
        )
    }

    /** Tokenizador mínimo (ISO 32000-1 §7.2): nomes, palavras-chave, strings literais e comentários. */
    private suspend fun tokenize(input: InputStream, depth: Int) {
        var pendingMetadataKey: String? = null
        var pendingUri = false
        var dictNames = HashSet<String>()
        var counter = 0
        var c = input.read()
        while (c >= 0) {
            if (++counter and 0xFFFF == 0) currentCoroutineContext().ensureActive()
            when {
                c == '%'.code -> {
                    val comment = StringBuilder()
                    c = input.read()
                    while (c >= 0 && c != '\n'.code && c != '\r'.code) {
                        if (comment.length < 8) comment.append(c.toChar())
                        c = input.read()
                    }
                    if (comment.startsWith("%EOF")) eofs++
                    continue
                }
                c == '/'.code -> {
                    val (name, wasEscaped, next) = readName(input)
                    if (name.isNotEmpty()) {
                        // Só nomes relevantes são contados: evita crescimento ilimitado com nomes únicos.
                        if (name in PdfEngine.INTERESTING) keywords[name] = (keywords[name] ?: 0) + 1
                        if (wasEscaped && name in PdfEngine.INTERESTING) obfuscated += name
                        if (name in STREAM_NAMES) dictNames += name
                        pendingMetadataKey = if (name in PdfEngine.METADATA_KEYS) name else null
                        pendingUri = name == "URI"
                    }
                    c = next
                    continue
                }
                c == '('.code -> {
                    val text = readLiteralString(input)
                    pendingMetadataKey?.let { key -> if (key !in metadata && text.isNotBlank()) metadata[key] = text.take(200) }
                    if (pendingUri && uris.size < 20) uris += text.take(200)
                    pendingMetadataKey = null
                    pendingUri = false
                }
                isRegular(c) -> {
                    val word = StringBuilder()
                    while (c >= 0 && isRegular(c) && word.length < 16) {
                        word.append(c.toChar())
                        c = input.read()
                    }
                    when (word.toString()) {
                        "obj" -> {
                            objects++
                            dictNames = HashSet()
                        }
                        "stream" -> {
                            streams++
                            handleStream(input, c, dictNames, depth)
                            dictNames = HashSet()
                        }
                    }
                    pendingMetadataKey = null
                    pendingUri = false
                    continue
                }
            }
            c = input.read()
        }
    }

    /** Pula o conteúdo do fluxo; inspeciona /ObjStm com /FlateDecode até 16 MB descomprimidos. */
    private suspend fun handleStream(input: InputStream, current: Int, dictNames: Set<String>, depth: Int) {
        // Após "stream" vem EOL (CRLF ou LF); os dados começam no byte seguinte.
        if (current == '\r'.code) input.read()
        val inspect = depth == 0 && "ObjStm" in dictNames && "FlateDecode" in dictNames && dictNames.none { it in OTHER_FILTERS }
        val collected = if (inspect) ByteArrayOutputStream() else null
        val window = ByteArray(ENDSTREAM.size)
        var filled = 0
        var tooLarge = false
        while (true) {
            val b = input.read()
            if (b < 0) break
            if (filled < window.size) {
                window[filled++] = b.toByte()
            } else {
                collected?.let { if (it.size() < MAX_COLLECT) it.write(window[0].toInt()) else tooLarge = true }
                System.arraycopy(window, 1, window, 0, window.size - 1)
                window[window.size - 1] = b.toByte()
            }
            if (filled == window.size && window.contentEquals(ENDSTREAM)) break
        }
        if ("ObjStm" in dictNames) {
            if (collected == null || tooLarge) {
                objStmSkipped++
            } else {
                val inflated = inflate(collected.toByteArray())
                if (inflated == null) objStmSkipped++ else {
                    objStmInspected++
                    tokenize(inflated.inputStream(), depth + 1)
                }
            }
        }
    }

    private fun inflate(data: ByteArray): ByteArray? {
        val inflater = Inflater()
        return try {
            inflater.setInput(data)
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(16 * 1024)
            while (!inflater.finished()) {
                val n = inflater.inflate(buffer)
                if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) break
                out.write(buffer, 0, n)
                budgetForInflate -= n
                if (budgetForInflate < 0 || out.size() > MAX_INFLATED) return null
            }
            out.toByteArray()
        } catch (error: DataFormatException) {
            null
        } finally {
            inflater.end()
        }
    }

    private data class NameToken(val name: String, val escaped: Boolean, val next: Int)

    private fun readName(input: InputStream): NameToken {
        val bytes = StringBuilder()
        var escaped = false
        var c = input.read()
        while (c >= 0 && isRegular(c) && bytes.length < 64) {
            if (c == '#'.code) {
                val h1 = input.read()
                val h2 = input.read()
                val value = hexValue(h1) * 16 + hexValue(h2)
                if (hexValue(h1) >= 0 && hexValue(h2) >= 0) {
                    bytes.append(value.toChar())
                    escaped = true
                }
            } else {
                bytes.append(c.toChar())
            }
            c = input.read()
        }
        return NameToken(bytes.toString(), escaped, c)
    }

    private fun readLiteralString(input: InputStream): String {
        val out = StringBuilder()
        var nesting = 1
        var c = input.read()
        while (c >= 0) {
            when (c) {
                '\\'.code -> {
                    val e = input.read()
                    if (e < 0) break
                    when (e) {
                        'n'.code -> out.append('\n')
                        'r'.code -> out.append('\r')
                        't'.code -> out.append('\t')
                        in '0'.code..'7'.code -> out.append(e.toChar())
                        else -> out.append(e.toChar())
                    }
                }
                '('.code -> { nesting++; out.append('(') }
                ')'.code -> {
                    nesting--
                    if (nesting == 0) break
                    out.append(')')
                }
                else -> if (out.length < 512) out.append(c.toChar())
            }
            if (out.length > 4096) break
            c = input.read()
        }
        return out.toString().filter { it >= ' ' || it == '\n' }.trim()
    }

    private fun isRegular(c: Int): Boolean =
        c > 0x20 && c < 0x7F && c.toChar() !in "()<>[]{}/%"

    private fun hexValue(c: Int): Int = when (c) {
        in '0'.code..'9'.code -> c - '0'.code
        in 'a'.code..'f'.code -> c - 'a'.code + 10
        in 'A'.code..'F'.code -> c - 'A'.code + 10
        else -> -1
    }

    private class LimitedStream(private val inner: InputStream, private var remaining: Long) : InputStream() {
        override fun read(): Int {
            if (remaining <= 0) return -1
            remaining--
            return inner.read()
        }
    }

    companion object {
        private val ENDSTREAM = "endstream".toByteArray()
        private val OTHER_FILTERS = setOf("ASCIIHexDecode", "ASCII85Decode", "LZWDecode", "RunLengthDecode", "DCTDecode", "JPXDecode", "Crypt")
        private val STREAM_NAMES = OTHER_FILTERS + setOf("ObjStm", "FlateDecode")
        private const val MAX_COLLECT = 16 * 1024 * 1024
        private const val MAX_INFLATED = 16 * 1024 * 1024
    }
}

private fun InputStream.readNBytesCompat(n: Int): ByteArray {
    val buffer = ByteArray(n)
    var read = 0
    while (read < n) {
        val r = read(buffer, read, n - read)
        if (r < 0) break
        read += r
    }
    return buffer.copyOf(read)
}
