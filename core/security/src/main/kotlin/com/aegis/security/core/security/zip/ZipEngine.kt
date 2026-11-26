package com.aegis.security.core.security.zip

import com.aegis.security.core.security.util.MalformedFileException
import com.aegis.security.core.security.util.summarize
import com.aegis.security.domain.analysis.AnalysisEngine
import com.aegis.security.domain.analysis.AnalysisInput
import com.aegis.security.domain.analysis.DetailEntry
import com.aegis.security.domain.analysis.DetailKind
import com.aegis.security.domain.analysis.DetailSection
import com.aegis.security.domain.analysis.EngineDescriptor
import com.aegis.security.domain.analysis.EngineResult
import com.aegis.security.domain.model.FileFormat
import javax.inject.Inject

class ZipEngine @Inject constructor() : AnalysisEngine {
    override val descriptor = EngineDescriptor(
        id = "zip",
        displayName = "Analisador de arquivos compactados",
        supportedFormats = setOf(FileFormat.ZIP, FileFormat.JAR, FileFormat.APK),
    )

    override suspend fun analyze(input: AnalysisInput): EngineResult {
        val workDir = requireNotNull(input.file.parentFile) { "Diretório de trabalho indisponível" }
        val facts = try {
            ZipInspector(input.limits, workDir).inspect(input.file)
        } catch (error: MalformedFileException) {
            return EngineResult.Failed("arquivo compactado malformado: ${error.message}")
        }
        val details = DetailSection(
            kind = DetailKind.STRUCTURE,
            title = "Estrutura do arquivo compactado",
            entries = listOfNotNull(
                DetailEntry("Entradas", "${facts.entryCount} (declaradas: ${facts.declaredEntryCount})"),
                DetailEntry("Pastas", facts.directoryCount.toString()),
                DetailEntry("Tamanho compactado", "${facts.totalCompressedBytes} bytes"),
                DetailEntry("Tamanho descompactado declarado", "${facts.totalUncompressedBytes} bytes"),
                DetailEntry("Maior razão de compressão", "%.1f:1".format(facts.maxCompressionRatio)),
                DetailEntry("ZIP64", if (facts.zip64) "Sim" else "Não"),
                facts.nestedArchives.takeIf { it.isNotEmpty() }?.let { DetailEntry("Arquivos compactados internos", it.summarize(8)) },
                facts.executableEntries.takeIf { it.isNotEmpty() }?.let { DetailEntry("Executáveis internos", it.summarize(8)) },
                facts.encryptedEntries.takeIf { it.isNotEmpty() }?.let { DetailEntry("Entradas cifradas", it.size.toString()) },
                if (facts.prependedBytes > 0) DetailEntry("Dados antes do primeiro registro", "${facts.prependedBytes} bytes") else null,
                facts.nestedFailures.takeIf { it.isNotEmpty() }?.let { DetailEntry("Inspeções internas incompletas", it.summarize(5)) },
                facts.topLevelNames.takeIf { it.isNotEmpty() }?.let { DetailEntry("Conteúdo (até 200 itens)", it.joinToString("\n"), monospace = true) },
            ),
        )
        return EngineResult.Completed(details = listOf(details), facts = listOf(facts))
    }
}
