package com.aegis.security.core.security.zip

import com.aegis.security.core.security.util.BinaryFile
import com.aegis.security.core.security.util.MalformedFileException
import com.aegis.security.domain.analysis.AnalysisFact
import com.aegis.security.domain.model.AnalysisLimits
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.File
import java.io.FileOutputStream
import java.util.zip.DataFormatException
import java.util.zip.Inflater

/** Fatos estruturais de um arquivo compactado (inclui arquivos internos inspecionados). */
data class ZipFacts(
    val entryCount: Int,
    val declaredEntryCount: Long,
    val directoryCount: Int,
    val totalCompressedBytes: Long,
    val totalUncompressedBytes: Long,
    val maxCompressionRatio: Double,
    val encryptedEntries: List<String>,
    val traversalEntries: List<String>,
    val absolutePathEntries: List<String>,
    val executableEntries: List<String>,
    val doubleExtensionEntries: List<String>,
    val misleadingNameEntries: List<String>,
    val duplicateEntries: List<String>,
    val overlappingEntries: List<String>,
    val bombIndicators: List<String>,
    val entryLimitExceeded: Boolean,
    val nestedArchives: List<String>,
    val nestingLimitReached: Boolean,
    val nestedFailures: List<String>,
    val prependedBytes: Long,
    val zip64: Boolean,
    val hasApkSigningBlock: Boolean,
    val topLevelNames: List<String>,
) : AnalysisFact

/**
 * Inspeção de ZIP/JAR/APK sem extração para armazenamento público e sem executar nada.
 * Arquivos internos compactados são descomprimidos apenas para o cache privado, com limites de
 * tamanho, razão de compressão e profundidade (proteção contra ZIP bombs), e apagados em seguida.
 */
internal class ZipInspector(private val limits: AnalysisLimits, private val workDir: File) {
    private var uncompressedBudget = limits.maxTotalUncompressedBytes

    private val acc = Accumulator()

    suspend fun inspect(file: File): ZipFacts {
        val root = ZipDirectoryParser.parse(file, limits.maxArchiveEntries)
        inspectDirectory(file, root, prefix = "", depth = 0)
        return acc.toFacts(root)
    }

    private suspend fun inspectDirectory(file: File, dir: ZipDirectory, prefix: String, depth: Int) {
        if (dir.truncated) acc.entryLimitExceeded = true
        acc.declaredSizes += dir.entries.sumOf { it.uncompressedSize }

        val seen = HashSet<String>()
        for (entry in dir.entries) {
            currentCoroutineContext().ensureActive()
            val path = prefix + entry.name
            acc.entryCount++
            if (entry.isDirectory) acc.directoryCount++
            acc.totalCompressed += entry.compressedSize
            acc.totalUncompressed += entry.uncompressedSize
            if (!seen.add(entry.name)) acc.duplicates += path
            if (entry.isEncrypted) acc.encrypted += path

            val normalized = entry.name.replace('\\', '/')
            if (normalized.split('/').any { it == ".." }) acc.traversal += path
            if (normalized.startsWith("/") || DRIVE.containsMatchIn(normalized)) acc.absolute += path
            if (normalized.any { it in BIDI_CONTROLS }) acc.misleading += path

            val leaf = normalized.substringAfterLast('/')
            val extension = leaf.substringAfterLast('.', "").lowercase()
            if (!entry.isDirectory && extension in EXECUTABLE_EXTENSIONS) acc.executables += path
            if (!entry.isDirectory && isDoubleExtension(leaf)) acc.doubleExtensions += path

            if (entry.compressedSize > 0) {
                val ratio = entry.uncompressedSize.toDouble() / entry.compressedSize
                if (ratio > acc.maxRatio) acc.maxRatio = ratio
                if (ratio > limits.maxCompressionRatio && entry.uncompressedSize > RATIO_MIN_SIZE) {
                    acc.bomb += "$path: razão de compressão ${ratio.toInt()}:1 (limite ${limits.maxCompressionRatio}:1)"
                }
            }
        }
        if (depth == 0 && dir.entries.size <= 200) acc.topLevel += dir.entries.map { it.name }

        BinaryFile(file).use { bin ->
            detectOverlaps(bin, dir, prefix)
            if (depth == 0) {
                acc.prepended = dir.entries.minOfOrNull { it.localHeaderOffset } ?: 0L
            }
            if (!acc.declaredLimitReported && acc.declaredSizes > limits.maxTotalUncompressedBytes) {
                acc.declaredLimitReported = true
                acc.bomb += "Tamanho descompactado declarado (${acc.declaredSizes / AnalysisLimits.MB} MB) acima do limite de ${limits.maxTotalUncompressedMb} MB"
            }
            for (entry in dir.entries) {
                if (entry.isDirectory || entry.name.substringAfterLast('.', "").lowercase() !in ARCHIVE_EXTENSIONS) continue
                val path = prefix + entry.name
                acc.nested += path
                if (depth + 1 > limits.maxNestingDepth) {
                    acc.nestingLimitReached = true
                    continue
                }
                inspectNested(bin, entry, path, depth + 1)
            }
        }
    }

    private suspend fun inspectNested(bin: BinaryFile, entry: ZipEntryInfo, path: String, depth: Int) {
        if (entry.isEncrypted || (entry.method != STORED && entry.method != DEFLATED)) {
            acc.nestedFailures += "$path: compressão não suportada ou cifrada"
            return
        }
        val temp = File.createTempFile("nested", ".zip", workDir)
        try {
            val written = extractBounded(bin, entry, temp, path) ?: return
            if (written < 22) return
            val nested = try {
                ZipDirectoryParser.parse(temp, limits.maxArchiveEntries)
            } catch (error: MalformedFileException) {
                acc.nestedFailures += "$path: ${error.message}"
                return
            }
            inspectDirectory(temp, nested, "$path!/", depth)
        } finally {
            temp.delete()
        }
    }

    /** Descompacta para o cache com limites. Retorna null se a extração foi interrompida. */
    private suspend fun extractBounded(bin: BinaryFile, entry: ZipEntryInfo, target: File, path: String): Long? {
        val start = ZipDirectoryParser.dataOffset(bin, entry)
        if (!bin.contains(start, entry.compressedSize)) {
            acc.nestedFailures += "$path: dados fora dos limites do arquivo"
            return null
        }
        val ratioLimit = limits.maxCompressionRatio.toLong() * maxOf(entry.compressedSize, 1L)
        var written = 0L
        FileOutputStream(target).use { out ->
            if (entry.method == STORED) {
                var position = start
                var remaining = entry.compressedSize
                while (remaining > 0) {
                    currentCoroutineContext().ensureActive()
                    val chunk = bin.bytes(position, minOf(remaining, CHUNK.toLong()).toInt())
                    if (!consumeBudget(chunk.size.toLong(), path)) return null
                    out.write(chunk)
                    position += chunk.size
                    remaining -= chunk.size
                    written += chunk.size
                }
            } else {
                val inflater = Inflater(true)
                val output = ByteArray(CHUNK)
                try {
                    var position = start
                    var remaining = entry.compressedSize
                    while (!inflater.finished()) {
                        currentCoroutineContext().ensureActive()
                        if (inflater.needsInput()) {
                            if (remaining <= 0) break
                            val chunk = bin.bytes(position, minOf(remaining, CHUNK.toLong()).toInt())
                            position += chunk.size
                            remaining -= chunk.size
                            inflater.setInput(chunk)
                        }
                        val n = inflater.inflate(output)
                        if (n == 0 && inflater.needsDictionary()) break
                        if (n > 0) {
                            written += n
                            if (written > ratioLimit && written > RATIO_MIN_SIZE) {
                                acc.bomb += "$path: expansão real acima de ${limits.maxCompressionRatio}:1 — extração interrompida"
                                return null
                            }
                            if (!consumeBudget(n.toLong(), path)) return null
                            out.write(output, 0, n)
                        }
                    }
                } catch (error: DataFormatException) {
                    acc.nestedFailures += "$path: dados comprimidos inválidos"
                    return null
                } finally {
                    inflater.end()
                }
            }
        }
        if (entry.uncompressedSize != written) {
            acc.nestedFailures += "$path: tamanho real ($written bytes) difere do declarado (${entry.uncompressedSize} bytes)"
        }
        return written
    }

    private fun consumeBudget(bytes: Long, path: String): Boolean {
        uncompressedBudget -= bytes
        if (uncompressedBudget < 0) {
            acc.bomb += "$path: limite total de ${limits.maxTotalUncompressedMb} MB descompactados atingido — inspeção interrompida"
            return false
        }
        return true
    }

    /** Entradas cujos dados se sobrepõem indicam ZIP bombs não recursivas ou arquivos adulterados. */
    private fun detectOverlaps(bin: BinaryFile, dir: ZipDirectory, prefix: String) {
        val sorted = dir.entries.sortedBy { it.localHeaderOffset }
        var previousEnd = -1L
        var previousName = ""
        for (entry in sorted) {
            if (entry.localHeaderOffset < previousEnd) {
                acc.overlapping += "$prefix${entry.name} sobrepõe $prefix$previousName"
            }
            val dataStart = try {
                ZipDirectoryParser.dataOffset(bin, entry)
            } catch (error: MalformedFileException) {
                acc.nestedFailures += "$prefix${entry.name}: ${error.message}"
                continue
            }
            val end = dataStart + entry.compressedSize
            if (end > previousEnd) {
                previousEnd = end
                previousName = entry.name
            }
            if (acc.overlapping.size > 50) return
        }
    }

    private class Accumulator {
        var entryCount = 0
        var directoryCount = 0
        var totalCompressed = 0L
        var totalUncompressed = 0L
        var declaredSizes = 0L
        var maxRatio = 0.0
        var prepended = 0L
        var entryLimitExceeded = false
        var nestingLimitReached = false
        var declaredLimitReported = false
        val encrypted = mutableListOf<String>()
        val traversal = mutableListOf<String>()
        val absolute = mutableListOf<String>()
        val executables = mutableListOf<String>()
        val doubleExtensions = mutableListOf<String>()
        val misleading = mutableListOf<String>()
        val duplicates = mutableListOf<String>()
        val overlapping = mutableListOf<String>()
        val bomb = mutableListOf<String>()
        val nested = mutableListOf<String>()
        val nestedFailures = mutableListOf<String>()
        val topLevel = mutableListOf<String>()

        fun toFacts(root: ZipDirectory) = ZipFacts(
            entryCount = entryCount,
            declaredEntryCount = root.declaredEntryCount,
            directoryCount = directoryCount,
            totalCompressedBytes = totalCompressed,
            totalUncompressedBytes = totalUncompressed,
            maxCompressionRatio = maxRatio,
            encryptedEntries = encrypted,
            traversalEntries = traversal,
            absolutePathEntries = absolute,
            executableEntries = executables,
            doubleExtensionEntries = doubleExtensions,
            misleadingNameEntries = misleading,
            duplicateEntries = duplicates,
            overlappingEntries = overlapping,
            bombIndicators = bomb.distinct(),
            entryLimitExceeded = entryLimitExceeded,
            nestedArchives = nested,
            nestingLimitReached = nestingLimitReached,
            nestedFailures = nestedFailures,
            prependedBytes = prepended,
            zip64 = root.zip64,
            hasApkSigningBlock = root.hasApkSigningBlock,
            topLevelNames = topLevel,
        )
    }

    companion object {
        private const val STORED = 0
        private const val DEFLATED = 8
        private const val CHUNK = 64 * 1024
        private const val RATIO_MIN_SIZE = 1L * 1024 * 1024
        private val DRIVE = Regex("^[A-Za-z]:")

        /** Caracteres de controle bidirecional usados para disfarçar extensões (ex.: U+202E). */
        internal val BIDI_CONTROLS = setOf('‪', '‫', '‬', '‭', '‮', '⁦', '⁧', '⁨', '⁩', '‏')

        val EXECUTABLE_EXTENSIONS = setOf(
            "exe", "dll", "scr", "com", "pif", "cpl", "sys", "msi", "msp", "bat", "cmd", "ps1", "psm1",
            "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "reg", "jar", "apk", "dex", "so",
            "elf", "bin", "sh", "app", "docm", "xlsm", "pptm",
        )
        val ARCHIVE_EXTENSIONS = setOf("zip", "jar", "apk", "aar", "xapk", "apks")
        private val DOCUMENT_LIKE = setOf(
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif",
            "mp3", "mp4", "avi", "mov", "zip", "rar", "csv", "html", "htm",
        )

        /** "fatura.pdf.exe", "foto.jpg   .scr" e similares. */
        fun isDoubleExtension(fileName: String): Boolean {
            val parts = fileName.lowercase().split('.')
            if (parts.size < 3) return false
            val last = parts.last().trim()
            val previous = parts[parts.size - 2].trim()
            return last in EXECUTABLE_EXTENSIONS && previous in DOCUMENT_LIKE
        }
    }
}
