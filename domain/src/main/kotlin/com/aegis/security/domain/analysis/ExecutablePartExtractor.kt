package com.aegis.security.domain.analysis

import java.io.File
import java.io.IOException
import java.io.InputStream

/** Parte executável extraída para o cache privado. [file] é nulo quando a parte excede o limite de envio. */
data class ExtractedPart(
    val name: String,
    val sizeBytes: Long,
    val sha256: String,
    val file: File?,
)

/**
 * Extrai de um APK apenas o código executável (classes*.dex, bibliotecas .so de uma ABI e código
 * embutido em assets/), em streaming, sem executar nada. Usado quando o APK inteiro é grande demais
 * para o VirusTotal (650 MB) ou desconhecido por ele.
 */
interface ExecutablePartExtractor {
    @Throws(IOException::class)
    suspend fun extract(
        input: InputStream,
        workDir: File,
        maxPartBytes: Long,
        onPart: (String) -> Unit,
    ): List<ExtractedPart>

    companion object {
        const val MAX_PARTS = 24
    }
}
