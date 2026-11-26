package com.aegis.security.domain.usecase

import com.aegis.security.domain.analysis.AnalysisEngine
import com.aegis.security.domain.analysis.ScannerStatus
import javax.inject.Inject

/** Lê o conjunto de mecanismos registrados no grafo de DI (pode ser vazio). */
class GetScannerStatusUseCase @Inject constructor(
    private val engines: Set<@JvmSuppressWildcards AnalysisEngine>,
) {
    operator fun invoke(): ScannerStatus =
        ScannerStatus(engines.map { it.descriptor }.sortedBy { it.id })
}
