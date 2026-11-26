package com.aegis.security.domain.model

/** De onde vieram as evidências de uma análise. Nomes persistidos: não renomear. */
enum class AnalysisOrigin {
    LOCAL,
    LOCAL_AND_VIRUSTOTAL,

    /** Valor lido do armazenamento que não corresponde a nenhuma origem conhecida. */
    UNKNOWN,
}
