package com.aegis.security.core.security.apk

import com.aegis.security.domain.analysis.ExecutablePartExtractor
import com.aegis.security.domain.analysis.ExtractedPart
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipException
import java.util.zip.ZipInputStream
import javax.inject.Inject

/**
 * Extração em streaming (uma única leitura do APK) das partes que contêm código: classes*.dex,
 * bibliotecas nativas de uma única ABI e código embutido em assets/ ou res/. Recursos (imagens,
 * sons, dados de jogo), que são a maior parte do tamanho, são ignorados. Nada é executado.
 */
class ApkPartExtractor @Inject constructor() : ExecutablePartExtractor {

    override suspend fun extract(
        input: InputStream,
        workDir: File,
        maxPartBytes: Long,
        onPart: (String) -> Unit,
    ): List<ExtractedPart> {
        val candidates = mutableListOf<ExtractedPart>()
        try {
            val zip = ZipInputStream(input)
            while (true) {
                currentCoroutineContext().ensureActive()
                val entry = zip.nextEntry ?: break
                val name = entry.name
                if (entry.isDirectory || !isExecutablePart(name)) continue
                onPart(name)
                candidates += copyEntry(zip, name, workDir, maxPartBytes, candidates.size)
            }
        } catch (error: ZipException) {
            candidates.forEach { it.file?.delete() }
            throw IOException("a estrutura do APK impede a extração das partes: ${error.message}", error)
        }
        return select(candidates)
    }

    private suspend fun copyEntry(zip: ZipInputStream, name: String, workDir: File, maxPartBytes: Long, index: Int): ExtractedPart {
        val digest = MessageDigest.getInstance("SHA-256")
        val target = File(workDir, "part-$index.bin")
        var size = 0L
        var keep = true
        FileOutputStream(target).use { out ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                currentCoroutineContext().ensureActive()
                val n = zip.read(buffer)
                if (n < 0) break
                digest.update(buffer, 0, n)
                size += n
                if (keep && size > maxPartBytes) keep = false
                if (keep) out.write(buffer, 0, n)
            }
        }
        if (!keep) target.delete()
        return ExtractedPart(name, size, digest.digest().joinToString("") { "%02x".format(it) }, if (keep) target else null)
    }

    /** Mantém uma ABI (a mais comum em aparelhos atuais), remove duplicados e respeita o limite de partes. */
    private fun select(candidates: List<ExtractedPart>): List<ExtractedPart> {
        val abis = candidates.mapNotNull { NATIVE.matchEntire(it.name)?.groupValues?.get(1) }.distinct()
        val chosenAbi = ABI_PREFERENCE.firstOrNull { it in abis } ?: abis.firstOrNull()
        val selected = candidates
            .filter { part -> NATIVE.matchEntire(part.name)?.groupValues?.get(1)?.let { it == chosenAbi } ?: true }
            .distinctBy { it.sha256 }
            .sortedWith(compareBy({ !ROOT_DEX.matches(it.name) }, { it.name }))
            .take(ExecutablePartExtractor.MAX_PARTS)
        val keptFiles = selected.mapNotNull { it.file }.toSet()
        candidates.mapNotNull { it.file }.filterNot { it in keptFiles }.forEach { it.delete() }
        return selected
    }

    companion object {
        private val ROOT_DEX = Regex("^classes\\d*\\.dex$")
        private val NATIVE = Regex("^lib/([^/]+)/[^/]+\\.so$")
        private val EMBEDDED = Regex("^(assets|res)/.+\\.(dex|jar|apk|so|odex|vdex)$", RegexOption.IGNORE_CASE)
        private val ABI_PREFERENCE = listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

        fun isExecutablePart(name: String): Boolean =
            ROOT_DEX.matches(name) || NATIVE.matches(name) || EMBEDDED.matches(name)
    }
}
