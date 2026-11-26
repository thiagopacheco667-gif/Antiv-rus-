package com.aegis.security.core.security.signature

import com.aegis.security.domain.analysis.AnalysisEngine
import com.aegis.security.domain.analysis.AnalysisFact
import com.aegis.security.domain.analysis.AnalysisInput
import com.aegis.security.domain.analysis.EngineDescriptor
import com.aegis.security.domain.analysis.EngineResult
import com.aegis.security.domain.model.FileFormat
import java.io.File
import javax.inject.Inject

data class SignatureFacts(val eicarTestFile: Boolean) : AnalysisFact

/**
 * Verificação da assinatura do arquivo de teste antivírus EICAR (eicar.org): uma string padrão,
 * inofensiva, que todo antivírus deve reconhecer. É a única assinatura local do AEGIS — o app não
 * possui nem inventa assinaturas de malware real.
 */
class EicarEngine @Inject constructor() : AnalysisEngine {
    override val descriptor = EngineDescriptor(
        id = "eicar",
        displayName = "Assinatura de teste EICAR",
        supportedFormats = FileFormat.entries.toSet(),
        structural = false,
    )

    override suspend fun analyze(input: AnalysisInput): EngineResult =
        EngineResult.Completed(facts = listOf(SignatureFacts(isEicar(input.file))))

    companion object {
        /** Montada em partes para que o próprio código-fonte não seja sinalizado por antivírus. */
        internal val EICAR: ByteArray = listOf(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}",
            "\$EICAR-STANDARD-ANTIVIRUS",
            "-TEST-FILE!\$H+H*",
        ).joinToString("").toByteArray(Charsets.US_ASCII)

        /** O padrão exige a string no início, seguida apenas de espaços em branco, até 128 bytes. */
        fun isEicar(file: File): Boolean {
            if (file.length() !in EICAR.size.toLong()..128L) return false
            val content = file.readBytes()
            if (!content.copyOfRange(0, EICAR.size).contentEquals(EICAR)) return false
            return content.drop(EICAR.size).all { it in WHITESPACE }
        }

        private val WHITESPACE = setOf(' ', '\t', '\r', '\n', '\u001A').map { it.code.toByte() }.toSet()
    }
}
