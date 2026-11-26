package com.aegis.security.domain.analysis

import com.aegis.security.domain.model.FileFormat
import java.io.File

/**
 * Contrato de um mecanismo de análise. Registrado via multibinding (`@Binds @IntoSet`)
 * em `:core:security`; novos mecanismos não exigem mudanças no restante do app.
 *
 * Regras obrigatórias: nunca executar o conteúdo; ler em blocos; cooperar com cancelamento;
 * em falha, retornar [EngineResult.Failed] — nunca um resultado "limpo".
 */
interface AnalysisEngine {
    val descriptor: EngineDescriptor

    suspend fun analyze(input: AnalysisInput): EngineResult
}

/** Identifica o formato real pelo conteúdo, não pela extensão. */
interface FormatIdentifier {
    fun identifyHeader(header: ByteArray): FileFormat

    /** Refina a identificação com acesso ao arquivo completo (ex.: ZIP → APK/JAR, PE → DLL). */
    fun refine(file: File, headerFormat: FileFormat): FileFormat
}

/** Motor de regras locais: transforma fatos em indicadores. */
interface RuleEngine {
    val ruleCount: Int

    fun evaluate(facts: List<AnalysisFact>): List<Finding>
}

/**
 * Ponto de extensão para varredura por padrões (ex.: YARA). Nenhuma implementação é registrada
 * enquanto não houver um mecanismo real integrado e testado; a UI exibe "não integrado".
 */
interface PatternScanner {
    val name: String

    suspend fun scan(input: AnalysisInput): List<Finding>
}
