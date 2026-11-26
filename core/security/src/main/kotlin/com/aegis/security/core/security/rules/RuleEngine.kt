package com.aegis.security.core.security.rules

import com.aegis.security.domain.analysis.AnalysisFact
import com.aegis.security.domain.analysis.Finding
import com.aegis.security.domain.analysis.FindingCategory
import com.aegis.security.domain.analysis.RuleEngine
import com.aegis.security.domain.analysis.Severity
import javax.inject.Inject

/** Evidência concreta encontrada por uma regra; a severidade pode ser ajustada caso a caso. */
data class RuleHit(val evidence: String, val severity: Severity? = null)

class FactBag(val facts: List<AnalysisFact>) {
    inline fun <reified T : AnalysisFact> get(): T? = facts.filterIsInstance<T>().firstOrNull()
}

/**
 * Regra local. Cada regra possui identificador, descrição, categoria, severidade e justificativa
 * técnica; a evidência vem dos fatos extraídos do arquivo. Regras não executam o conteúdo analisado.
 */
class LocalRule(
    val id: String,
    val description: String,
    val category: FindingCategory,
    val severity: Severity,
    val rationale: String,
    val confirmsThreat: Boolean = false,
    val evaluate: (FactBag) -> List<RuleHit>,
)

/** Conjunto de regras de um domínio (APK, ZIP, PE...). Registrado via `@IntoSet`. */
interface RuleSet {
    val rules: List<LocalRule>
}

class DefaultRuleEngine @Inject constructor(
    ruleSets: Set<@JvmSuppressWildcards RuleSet>,
) : RuleEngine {
    private val rules: List<LocalRule> = ruleSets.flatMap { it.rules }.sortedBy { it.id }

    init {
        val duplicated = rules.groupBy { it.id }.filterValues { it.size > 1 }.keys
        require(duplicated.isEmpty()) { "Regras com id duplicado: $duplicated" }
    }

    override val ruleCount: Int get() = rules.size

    override fun evaluate(facts: List<AnalysisFact>): List<Finding> {
        val bag = FactBag(facts)
        return rules.mapNotNull { rule ->
            val hits = rule.evaluate(bag)
            if (hits.isEmpty()) return@mapNotNull null
            val severity = hits.mapNotNull { it.severity }.maxOrNull()?.let { maxOf(it, rule.severity) } ?: rule.severity
            Finding(
                ruleId = rule.id,
                description = rule.description,
                category = rule.category,
                severity = severity,
                evidence = hits.map { it.evidence }.distinct().let { evidences ->
                    if (evidences.size <= MAX_EVIDENCES) evidences.joinToString("; ")
                    else evidences.take(MAX_EVIDENCES).joinToString("; ") + " (+${evidences.size - MAX_EVIDENCES})"
                }.take(MAX_EVIDENCE_LENGTH),
                rationale = rule.rationale,
                confirmsThreat = rule.confirmsThreat,
            )
        }
    }

    private companion object {
        const val MAX_EVIDENCES = 6
        const val MAX_EVIDENCE_LENGTH = 900
    }
}

internal fun hitsFrom(items: List<String>, max: Int = 50): List<RuleHit> = items.take(max).map { RuleHit(it) }
