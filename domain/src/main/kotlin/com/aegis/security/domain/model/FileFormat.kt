package com.aegis.security.domain.model

/**
 * Formato real de um arquivo, identificado pelo conteúdo (assinatura), não pela extensão.
 * Nomes persistidos: não renomear.
 */
enum class FileFormat {
    APK,
    ZIP,
    JAR,
    DEX,
    PE_EXECUTABLE,
    PE_LIBRARY,
    ELF,
    PDF,
    UNKNOWN,
    ;

    companion object {
        /** Formatos prioritários do produto, na ordem em que são apresentados ao usuário. */
        val prioritized: List<FileFormat> = listOf(APK, ZIP, JAR, DEX, PE_EXECUTABLE, PE_LIBRARY, ELF, PDF)
    }
}
