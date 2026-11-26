package com.aegis.security.domain.analysis

import com.aegis.security.domain.model.AnalysisLimits
import com.aegis.security.domain.model.FileFormat
import kotlinx.serialization.Serializable
import java.io.File

/** Identificação pública de um mecanismo de análise registrado. */
@Serializable
data class EngineDescriptor(
    val id: String,
    val displayName: String,
    val supportedFormats: Set<FileFormat>,
    /** `true` quando o mecanismo inspeciona a estrutura do formato (não apenas verificações genéricas). */
    val structural: Boolean = true,
) {
    init {
        require(id.isNotBlank()) { "O id do mecanismo não pode ser vazio" }
    }
}

/**
 * Entrada de um mecanismo. [file] é uma cópia privada (cache do app) do arquivo selecionado;
 * nunca é executada e é apagada ao fim da análise.
 */
data class AnalysisInput(
    val fileName: String,
    val declaredExtension: String?,
    val sizeBytes: Long,
    val format: FileFormat,
    val file: File,
    val limits: AnalysisLimits,
)

/** Fato técnico extraído por um mecanismo e avaliado pelo motor de regras. */
interface AnalysisFact

@Serializable
enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

@Serializable
enum class FindingCategory {
    GENERAL,
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

/** Indicador produzido por uma regra. Toda constatação tem evidência e justificativa técnica. */
@Serializable
data class Finding(
    val ruleId: String,
    val description: String,
    val category: FindingCategory,
    val severity: Severity,
    val evidence: String,
    val rationale: String,
    /** Só é `true` para assinaturas reais e verificáveis (ex.: arquivo de teste EICAR). */
    val confirmsThreat: Boolean = false,
)

@Serializable
enum class DetailKind { METADATA, HASHES, SIGNATURE, PERMISSIONS, COMPONENTS, STRUCTURE, INDICATORS, EXTERNAL }

@Serializable
data class DetailEntry(val label: String, val value: String, val monospace: Boolean = false)

@Serializable
data class DetailSection(val kind: DetailKind, val title: String, val entries: List<DetailEntry>)

sealed interface EngineResult {
    data class Completed(
        val details: List<DetailSection> = emptyList(),
        val facts: List<AnalysisFact> = emptyList(),
    ) : EngineResult

    data class Failed(val reason: String, val cause: Throwable? = null) : EngineResult

    data object NotApplicable : EngineResult
}

/** Fatos gerais do arquivo, disponíveis para todas as regras. */
data class CommonFacts(
    val fileName: String,
    val declaredExtension: String?,
    val format: FileFormat,
    val sizeBytes: Long,
) : AnalysisFact
