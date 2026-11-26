package com.aegis.security.domain.analysis

/**
 * Contrato de um mecanismo de análise (SHA-256, APK, ZIP, PE/ELF, PDF, regras locais, VirusTotal...).
 *
 * Cada mecanismo é registrado via multibinding do Hilt (`@Binds @IntoSet`) no módulo
 * `:core:security`. Assim, novos mecanismos são adicionados sem alterar o restante do app.
 *
 * Regras obrigatórias para implementações:
 * - nunca executar o conteúdo analisado;
 * - ler o arquivo em blocos via [AnalysisInput.source], sem carregá-lo inteiro na memória;
 * - cooperar com cancelamento de corrotinas;
 * - em caso de falha, retornar [EngineResult.Failed] — nunca um resultado "limpo".
 */
interface AnalysisEngine {
    val descriptor: EngineDescriptor

    suspend fun analyze(input: AnalysisInput): EngineResult
}
