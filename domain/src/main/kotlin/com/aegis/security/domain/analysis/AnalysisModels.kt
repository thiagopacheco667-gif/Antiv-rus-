package com.aegis.security.domain.analysis

import com.aegis.security.domain.model.FileFormat
import java.io.IOException
import java.io.InputStream

/** Identificação pública de um mecanismo de análise registrado. */
data class EngineDescriptor(
    val id: String,
    val displayName: String,
    val supportedFormats: Set<FileFormat>,
) {
    init {
        require(id.isNotBlank()) { "O id do mecanismo não pode ser vazio" }
    }
}

/**
 * Fonte de bytes reabrível. Cada chamada a [openStream] devolve um novo fluxo posicionado
 * no início; quem abre é responsável por fechá-lo.
 */
fun interface ByteSource {
    @Throws(IOException::class)
    fun openStream(): InputStream
}

data class AnalysisInput(
    val displayName: String,
    val sizeBytes: Long?,
    val format: FileFormat,
    val source: ByteSource,
)

enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

enum class FindingCategory {
    PERMISSION,
    COMPONENT,
    SIGNATURE,
    STRUCTURE,
    OBFUSCATION,
    ARCHIVE,
    EXECUTABLE,
    DOCUMENT,
    REPUTATION,
}

/** Indicador produzido por uma regra. Toda constatação precisa de evidência e justificativa. */
data class Finding(
    val ruleId: String,
    val description: String,
    val category: FindingCategory,
    val severity: Severity,
    val evidence: String,
    val rationale: String,
)

sealed interface EngineResult {
    data class Completed(
        val findings: List<Finding>,
        val technicalDetails: Map<String, String> = emptyMap(),
    ) : EngineResult

    data class Failed(
        val reason: String,
        val cause: Throwable? = null,
    ) : EngineResult

    /** O mecanismo não se aplica ao formato recebido. */
    data object NotApplicable : EngineResult
}
