package com.aegis.security.domain.analysis

/** Etapas reais de uma análise, na ordem em que são executadas. */
enum class ScanStep {
    IDENTIFYING,
    HASHING,
    INSPECTING,
    CHECKING_INDICATORS,
    ONLINE_REPUTATION,
    FINALIZING,
}

sealed interface ScanEvent {
    /** [fraction] em 0..1 quando a etapa tem progresso mensurável (ex.: bytes lidos). */
    data class Progress(val step: ScanStep, val fraction: Float? = null) : ScanEvent

    /** A consulta online não faz parte da análise local; é oferecida depois, com consentimento. */
    data class StepSkipped(val step: ScanStep) : ScanEvent

    data class Completed(val recordId: Long) : ScanEvent
}
