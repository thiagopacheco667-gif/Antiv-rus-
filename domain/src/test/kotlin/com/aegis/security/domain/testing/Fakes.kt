package com.aegis.security.domain.testing

import com.aegis.security.domain.analysis.AnalysisEngine
import com.aegis.security.domain.analysis.AnalysisFact
import com.aegis.security.domain.analysis.AnalysisInput
import com.aegis.security.domain.analysis.EngineDescriptor
import com.aegis.security.domain.analysis.EngineResult
import com.aegis.security.domain.analysis.Finding
import com.aegis.security.domain.analysis.FindingCategory
import com.aegis.security.domain.analysis.FormatIdentifier
import com.aegis.security.domain.analysis.RuleEngine
import com.aegis.security.domain.analysis.Severity
import com.aegis.security.domain.model.AnalysisLimits
import com.aegis.security.domain.model.FileFormat
import com.aegis.security.domain.model.FileHashes
import com.aegis.security.domain.model.FileMetadata
import com.aegis.security.domain.model.OnlineServiceConfig
import com.aegis.security.domain.model.ThemePreference
import com.aegis.security.domain.repository.FileAccessException
import com.aegis.security.domain.repository.FileStager
import com.aegis.security.domain.repository.FileTooLargeException
import com.aegis.security.domain.repository.StagedFile
import com.aegis.security.domain.repository.UserPreferencesRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import java.io.File
import java.io.InputStream

/** Stager sobre arquivos locais; "uri" é o caminho. */
class FakeFileStager(private val workDir: File) : FileStager {
    val released = mutableListOf<File>()
    var inaccessible = false

    override suspend fun describe(uri: String): FileMetadata {
        if (inaccessible) throw FileAccessException("sem permissão")
        val file = File(uri)
        if (!file.exists()) throw FileAccessException("não encontrado")
        val ext = file.name.substringAfterLast('.', "").takeIf { file.name.contains('.') }
        return FileMetadata(fileName = file.name, declaredExtension = ext, sizeBytes = file.length())
    }

    override suspend fun readHeader(uri: String, maxBytes: Int): ByteArray = File(uri).readBytes().take(maxBytes).toByteArray()

    override suspend fun stage(uri: String, maxBytes: Long, onProgress: suspend (Long) -> Unit): StagedFile {
        val source = File(uri)
        if (source.length() > maxBytes) throw FileTooLargeException(maxBytes)
        val copy = File.createTempFile("staged", ".bin", workDir)
        source.copyTo(copy, overwrite = true)
        onProgress(copy.length())
        return StagedFile(copy, copy.length(), FileHashes("0".repeat(64), "0".repeat(40), "0".repeat(32)))
    }

    override fun release(staged: StagedFile) {
        released += staged.file
        staged.file.delete()
    }

    override fun open(uri: String): InputStream = File(uri).inputStream()
}

class FakeIdentifier(private val format: FileFormat) : FormatIdentifier {
    override fun identifyHeader(header: ByteArray) = format
    override fun refine(file: File, headerFormat: FileFormat) = headerFormat
}

class FakeEngine(
    id: String,
    formats: Set<FileFormat>,
    structural: Boolean = true,
    private val behavior: suspend (AnalysisInput) -> EngineResult,
) : AnalysisEngine {
    override val descriptor = EngineDescriptor(id, id, formats, structural)
    override suspend fun analyze(input: AnalysisInput) = behavior(input)
}

data class MarkerFact(val severity: Severity, val confirms: Boolean = false) : AnalysisFact

/** Converte [MarkerFact] em indicadores. */
class FakeRuleEngine : RuleEngine {
    override val ruleCount = 1
    override fun evaluate(facts: List<AnalysisFact>): List<Finding> = facts.filterIsInstance<MarkerFact>().map {
        Finding("TEST-001", "indicador de teste", FindingCategory.GENERAL, it.severity, "evidência", "justificativa", it.confirms)
    }
}

class FakePreferences(limits: AnalysisLimits = AnalysisLimits()) : UserPreferencesRepository {
    override val themePreference: Flow<ThemePreference> = MutableStateFlow(ThemePreference.DARK)
    override val analysisLimits = MutableStateFlow(limits)
    override val onlineServiceConfig: Flow<OnlineServiceConfig> = MutableStateFlow(OnlineServiceConfig.Empty)
    override suspend fun setThemePreference(preference: ThemePreference) = Unit
    override suspend fun setAnalysisLimits(limits: AnalysisLimits) { analysisLimits.value = limits }
    override suspend fun setOnlineServiceConfig(baseUrl: String, accessToken: String?) = Unit
    override suspend fun accessToken(): String? = null
}
