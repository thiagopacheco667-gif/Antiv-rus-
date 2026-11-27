package com.aegis.security.domain.analysis

import com.aegis.security.domain.model.EngineOutcome
import com.aegis.security.domain.model.EngineStatus
import com.aegis.security.domain.model.OnlineReputation
import com.aegis.security.domain.model.PartReputation
import com.aegis.security.domain.model.Verdict

data class Classification(val verdict: Verdict, val reasons: List<String>)

/**
 * Classificação baseada em evidências. Princípios:
 * - nunca "seguro" quando a análise falhou ou o formato não foi inspecionado;
 * - permissões ou indicadores isolados não tornam um arquivo "ameaça";
 * - "ameaça detectada" exige assinatura verificável local ou detecções externas;
 * - ausência de detecção nunca é apresentada como garantia.
 */
object RiskClassifier {
    /**
     * Quantidade mínima de mecanismos externos independentes que classificam o arquivo como
     * malicioso para declarar ameaça. Uma ou duas detecções isoladas são tratadas como suspeitas,
     * pois falsos positivos isolados são comuns. Não é uma porcentagem.
     */
    const val EXTERNAL_THREAT_MIN_ENGINES = 3

    private const val NO_GUARANTEE =
        "Nenhuma verificação garante que o arquivo esteja livre de malware."

    fun classifyLocal(
        outcomes: List<EngineOutcome>,
        findings: List<Finding>,
        sizeBytes: Long,
    ): Classification {
        val confirmed = findings.filter { it.confirmsThreat }
        if (confirmed.isNotEmpty()) {
            return Classification(
                Verdict.THREAT_DETECTED,
                confirmed.map { "Assinatura confirmada localmente: ${it.description}." },
            )
        }

        val reasons = mutableListOf<String>()
        val severe = findings.filter { it.severity >= Severity.HIGH }
        val failed = outcomes.filter { it.status == EngineStatus.FAILED }
        val structuralCompleted = outcomes.any { it.structural && it.status == EngineStatus.COMPLETED }

        if (severe.isNotEmpty()) {
            reasons += "${severe.size} indicador(es) de risco elevado encontrado(s) na análise estática."
            if (failed.isNotEmpty()) reasons += failureReason(failed)
            reasons += "Indicadores estáticos não comprovam a presença de malware; recomenda-se cautela."
            return Classification(Verdict.SUSPICIOUS, reasons)
        }
        if (sizeBytes == 0L) {
            return Classification(Verdict.INCONCLUSIVE, listOf("O arquivo está vazio; não há conteúdo para analisar."))
        }
        if (failed.isNotEmpty()) {
            return Classification(Verdict.INCONCLUSIVE, listOf(failureReason(failed), NO_GUARANTEE))
        }
        val partial = outcomes.filter { it.status == EngineStatus.COMPLETED && it.incomplete.isNotEmpty() }
        if (partial.isNotEmpty()) {
            return Classification(
                Verdict.INCONCLUSIVE,
                listOf(
                    "Inspeção incompleta: " + partial.joinToString("; ") { "${it.engineName} (${it.incomplete.take(3).joinToString()})" } + ".",
                    "Partes não inspecionadas impedem classificar o arquivo como seguro.",
                    NO_GUARANTEE,
                ),
            )
        }
        if (!structuralCompleted) {
            return Classification(
                Verdict.INCONCLUSIVE,
                listOf(
                    "O formato deste arquivo não é inspecionado estruturalmente pelo AEGIS; " +
                        "apenas verificações genéricas foram executadas.",
                    NO_GUARANTEE,
                ),
            )
        }
        val minor = findings.size
        reasons += if (minor == 0) {
            "As verificações locais não encontraram indicadores de risco."
        } else {
            "Foram encontrados $minor indicador(es) de baixa ou média severidade, sem evidência de risco elevado."
        }
        reasons += NO_GUARANTEE
        return Classification(Verdict.SAFE_BY_CHECKS, reasons)
    }

    fun combine(local: Classification, online: OnlineReputation): Classification = when (online) {
        OnlineReputation.NotRequested ->
            local.copy(reasons = local.reasons + "A reputação online não foi consultada.")

        is OnlineReputation.NotFound -> local.copy(
            reasons = local.reasons +
                "O VirusTotal não conhece este hash. Isso não indica que o arquivo é seguro.",
        )

        is OnlineReputation.Failed -> local.copy(
            reasons = local.reasons + "A consulta online falhou (${online.message}); o resultado considera apenas a análise local.",
        )

        is OnlineReputation.Found -> {
            val stats = online.stats
            val summary = "VirusTotal: ${stats.malicious} mecanismo(s) detectaram ameaça, " +
                "${stats.suspicious} suspeita, ${stats.notDetected} não detectaram e ${stats.inconclusive} inconclusivo(s)."
            when {
                stats.malicious >= EXTERNAL_THREAT_MIN_ENGINES -> Classification(
                    Verdict.THREAT_DETECTED,
                    local.reasons + summary +
                        "Ao menos $EXTERNAL_THREAT_MIN_ENGINES mecanismos independentes classificaram o arquivo como malicioso.",
                )

                stats.malicious > 0 || stats.suspicious > 0 -> Classification(
                    moreSevere(local.verdict, Verdict.SUSPICIOUS),
                    local.reasons + summary + "Detecções externas isoladas podem ser falsos positivos, mas exigem cautela.",
                )

                else -> local.copy(
                    reasons = local.reasons + summary + "Ausência de detecções externas não garante segurança.",
                )
            }
        }
    }

    /** Incorpora a reputação das partes executáveis de um APK. Partes desconhecidas não melhoram o resultado. */
    fun combineParts(current: Classification, parts: List<PartReputation>): Classification {
        if (parts.isEmpty()) return current
        val found = parts.mapNotNull { (it.online as? OnlineReputation.Found)?.let { f -> it to f } }
        val unknown = parts.count { it.online is OnlineReputation.NotFound }
        val failed = parts.count { it.online is OnlineReputation.Failed }
        val reasons = current.reasons.toMutableList()
        reasons += "Partes executáveis consultadas: ${parts.size} (${found.size} conhecidas pelo VirusTotal, $unknown desconhecidas, $failed com falha)."
        if (unknown > 0) reasons += "Partes desconhecidas pelo VirusTotal não indicam que sejam seguras."
        val threat = found.filter { it.second.stats.malicious >= EXTERNAL_THREAT_MIN_ENGINES }
        val flagged = found.filter { it.second.stats.malicious > 0 || it.second.stats.suspicious > 0 }
        return when {
            threat.isNotEmpty() -> Classification(
                Verdict.THREAT_DETECTED,
                reasons + "Ameaça em: " + threat.joinToString { "${it.first.name} (${it.second.stats.malicious} mecanismos)" } + ".",
            )
            flagged.isNotEmpty() -> Classification(
                moreSevere(current.verdict, Verdict.SUSPICIOUS),
                reasons + "Detecções em: " + flagged.joinToString { "${it.first.name} (${it.second.stats.malicious} maliciosa(s), ${it.second.stats.suspicious} suspeita(s))" } + ".",
            )
            else -> current.copy(reasons = reasons)
        }
    }

    /** Ordem de gravidade usada ao combinar evidências. Erro de análise é tratado como inconclusivo. */
    private fun rank(verdict: Verdict): Int = when (verdict) {
        Verdict.SAFE_BY_CHECKS -> 0
        Verdict.INCONCLUSIVE, Verdict.ANALYSIS_ERROR -> 1
        Verdict.SUSPICIOUS -> 2
        Verdict.THREAT_DETECTED -> 3
    }

    fun moreSevere(a: Verdict, b: Verdict): Verdict = if (rank(a) >= rank(b)) a else b

    private fun failureReason(failed: List<EngineOutcome>): String =
        "Falha técnica em: " + failed.joinToString { "${it.engineName} (${it.failureReason ?: "erro"})" } + "."
}
