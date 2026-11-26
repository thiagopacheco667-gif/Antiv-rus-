package com.aegis.security.core.security.dex

import com.aegis.security.core.security.util.BinaryFile
import com.aegis.security.core.security.util.ContentScanner
import com.aegis.security.core.security.util.hex32
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
import java.security.MessageDigest
import java.util.zip.Adler32
import javax.inject.Inject

data class DexFacts(
    val version: String,
    val declaredFileSize: Long,
    val actualFileSize: Long,
    val checksumValid: Boolean,
    val signatureValid: Boolean,
    val endianTagValid: Boolean,
    val classDefs: Long,
    val methodIds: Long,
    val stringIds: Long,
    /** Referências de API relevantes encontradas nas strings (nome → descrição). */
    val apiReferences: List<String>,
) : AnalysisFact

/** DEX standalone: valida cabeçalho, checksum Adler-32 e assinatura SHA-1 (formato Dalvik). */
class DexEngine @Inject constructor() : AnalysisEngine {
    override val descriptor = EngineDescriptor("dex", "Analisador de DEX", setOf(FileFormat.DEX))

    override suspend fun analyze(input: AnalysisInput): EngineResult {
        var truncated = false
        val facts = BinaryFile(input.file).use { bin ->
            if (bin.length < HEADER_SIZE) return EngineResult.Failed("cabeçalho DEX truncado")
            val header = bin.bytes(0, HEADER_SIZE)
            val version = String(header, 4, 3, Charsets.US_ASCII)
            val storedChecksum = bin.u32(8)
            val storedSignature = header.copyOfRange(12, 32)

            val adler = Adler32()
            val sha1 = MessageDigest.getInstance("SHA-1")
            var offset = 12L
            while (offset < bin.length) {
                currentCoroutineContext().ensureActive()
                val chunk = bin.bytes(offset, minOf(64L * 1024, bin.length - offset).toInt())
                adler.update(chunk)
                val shaStart = maxOf(0, (32 - offset).toInt())
                if (shaStart < chunk.size) sha1.update(chunk, shaStart, chunk.size - shaStart)
                offset += chunk.size
            }

            val scan = ContentScanner.scan(input.file, API_PATTERNS.keys, input.limits.maxContentScanBytes)
            truncated = scan.truncated
            DexFacts(
                version = version,
                declaredFileSize = bin.u32(32),
                actualFileSize = bin.length,
                checksumValid = adler.value == storedChecksum,
                signatureValid = sha1.digest().contentEquals(storedSignature),
                endianTagValid = bin.u32(40) == ENDIAN_CONSTANT,
                classDefs = bin.u32(96),
                methodIds = bin.u32(88),
                stringIds = bin.u32(56),
                apiReferences = scan.matches.keys.mapNotNull { API_PATTERNS[it] },
            )
        }
        val details = DetailSection(
            DetailKind.STRUCTURE,
            "Estrutura DEX",
            listOf(
                DetailEntry("Versão", facts.version),
                DetailEntry("Classes", facts.classDefs.toString()),
                DetailEntry("Métodos referenciados", facts.methodIds.toString()),
                DetailEntry("Strings", facts.stringIds.toString()),
                DetailEntry("Tamanho declarado / real", "${facts.declaredFileSize} / ${facts.actualFileSize} bytes"),
                DetailEntry("Checksum Adler-32", if (facts.checksumValid) "Válido" else "Inválido"),
                DetailEntry("Assinatura SHA-1", if (facts.signatureValid) "Válida" else "Inválida"),
                DetailEntry("Marca de endianness", if (facts.endianTagValid) hex32(ENDIAN_CONSTANT) else "Inesperada"),
                DetailEntry("APIs relevantes", facts.apiReferences.ifEmpty { listOf("Nenhuma") }.joinToString("\n")),
            ),
        )
        val incomplete = if (truncated) listOf("varredura de strings limitada aos primeiros ${input.limits.maxContentScanMb} MB") else emptyList()
        return EngineResult.Completed(listOf(details), listOf(facts), incomplete)
    }

    companion object {
        private const val HEADER_SIZE = 0x70
        private const val ENDIAN_CONSTANT = 0x12345678L

        /** Descritores de tipo Dalvik de APIs usadas para carregar código ou executar comandos. */
        val API_PATTERNS = mapOf(
            "Ldalvik/system/DexClassLoader;" to "Carregamento dinâmico de código (DexClassLoader)",
            "Ldalvik/system/InMemoryDexClassLoader;" to "Carregamento de código em memória (InMemoryDexClassLoader)",
            "Ldalvik/system/PathClassLoader;" to "Carregamento de classes por caminho (PathClassLoader)",
            "Ljava/lang/Runtime;" to "Execução de comandos do sistema (Runtime)",
            "Ljava/lang/ProcessBuilder;" to "Criação de processos (ProcessBuilder)",
            "Landroid/telephony/SmsManager;" to "Envio de SMS (SmsManager)",
            "Landroid/accessibilityservice/AccessibilityService;" to "Serviço de acessibilidade",
            "Landroid/app/admin/DevicePolicyManager;" to "Administração do dispositivo (DevicePolicyManager)",
        ).mapKeys { it.key.lowercase() }
    }
}
