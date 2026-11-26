package com.aegis.security.domain.model

/**
 * Classificação final de uma análise.
 *
 * Os nomes das constantes fazem parte do esquema persistido (Room/DataStore):
 * não renomeie sem criar uma migração.
 *
 * Nenhum valor significa "livre de malware com certeza". [SAFE_BY_CHECKS] indica apenas
 * que as verificações executadas não encontraram evidências.
 */
enum class Verdict {
    SAFE_BY_CHECKS,
    SUSPICIOUS,
    THREAT_DETECTED,
    INCONCLUSIVE,
    ANALYSIS_ERROR,
}
