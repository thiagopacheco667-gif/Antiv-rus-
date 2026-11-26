package com.aegis.security.domain.analysis

import com.aegis.security.domain.model.FileFormat

/**
 * Estado real do scanner, derivado dos mecanismos efetivamente registrados no app.
 * Se nenhum mecanismo estiver registrado, o scanner não está operacional.
 */
data class ScannerStatus(val engines: List<EngineDescriptor>) {
    init {
        val duplicated = engines.groupBy { it.id }.filterValues { it.size > 1 }.keys
        require(duplicated.isEmpty()) { "Mecanismos com id duplicado: $duplicated" }
    }

    val isOperational: Boolean get() = engines.isNotEmpty()

    val supportedFormats: Set<FileFormat> get() = engines.flatMapTo(mutableSetOf()) { it.supportedFormats }
}
