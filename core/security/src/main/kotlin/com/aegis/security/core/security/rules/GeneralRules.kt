package com.aegis.security.core.security.rules

import com.aegis.security.core.security.signature.SignatureFacts
import com.aegis.security.core.security.zip.ZipInspector
import com.aegis.security.domain.analysis.CommonFacts
import com.aegis.security.domain.analysis.FindingCategory
import com.aegis.security.domain.analysis.Severity
import com.aegis.security.domain.model.FileFormat
import javax.inject.Inject

class GeneralRules @Inject constructor() : RuleSet {
    override val rules = listOf(
        LocalRule(
            id = "AEGIS-GEN-001",
            description = "Arquivo de teste antivírus EICAR",
            category = FindingCategory.SIGNATURE,
            severity = Severity.CRITICAL,
            rationale = "O conteúdo corresponde exatamente à string padrão EICAR, criada para testar antivírus. " +
                "É inofensiva, mas todo antivírus deve tratá-la como detecção.",
            confirmsThreat = true,
        ) { bag -> if (bag.get<SignatureFacts>()?.eicarTestFile == true) listOf(RuleHit("Assinatura EICAR no início do arquivo")) else emptyList() },

        LocalRule(
            id = "AEGIS-GEN-002",
            description = "Extensão não corresponde ao formato real",
            category = FindingCategory.GENERAL,
            severity = Severity.MEDIUM,
            rationale = "O formato foi identificado pelo conteúdo. Extensões enganosas são usadas para fazer " +
                "executáveis parecerem documentos ou mídia.",
        ) { bag ->
            val common = bag.get<CommonFacts>() ?: return@LocalRule emptyList()
            val ext = common.declaredExtension?.lowercase() ?: return@LocalRule emptyList()
            val expected = EXPECTED_EXTENSIONS[common.format] ?: return@LocalRule emptyList()
            if (ext in expected) return@LocalRule emptyList()
            val executable = common.format in EXECUTABLE_FORMATS
            listOf(
                RuleHit(
                    "extensão .$ext, conteúdo ${common.format.name}",
                    severity = if (executable && ext in DISGUISE_EXTENSIONS) Severity.HIGH else null,
                ),
            )
        },

        LocalRule(
            id = "AEGIS-GEN-003",
            description = "Nome com extensão dupla",
            category = FindingCategory.GENERAL,
            severity = Severity.HIGH,
            rationale = "Nomes como \"fatura.pdf.exe\" escondem a extensão real em sistemas que ocultam extensões conhecidas.",
        ) { bag ->
            val name = bag.get<CommonFacts>()?.fileName ?: return@LocalRule emptyList()
            if (ZipInspector.isDoubleExtension(name)) listOf(RuleHit(name)) else emptyList()
        },

        LocalRule(
            id = "AEGIS-GEN-004",
            description = "Nome com caracteres de controle de direção",
            category = FindingCategory.GENERAL,
            severity = Severity.HIGH,
            rationale = "Caracteres como U+202E invertem a exibição do texto e são usados para disfarçar a extensão real.",
        ) { bag ->
            val name = bag.get<CommonFacts>()?.fileName ?: return@LocalRule emptyList()
            if (name.any { it in ZipInspector.BIDI_CONTROLS }) listOf(RuleHit("nome contém controle bidirecional")) else emptyList()
        },
    )

    companion object {
        private val EXPECTED_EXTENSIONS = mapOf(
            FileFormat.APK to setOf("apk", "apks", "xapk", "zip"),
            FileFormat.ZIP to setOf("zip", "apk", "jar", "aar", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "xpi", "crx", "apks", "xapk", "aab", "kmz", "ipa", "whl", "nupkg", "vsix", "3mf"),
            FileFormat.JAR to setOf("jar", "war", "ear", "aar", "zip"),
            FileFormat.DEX to setOf("dex", "odex"),
            FileFormat.PE_EXECUTABLE to setOf("exe", "scr", "com", "efi", "sys", "msi", "cpl", "mui", "dll", "ocx", "drv"),
            FileFormat.PE_LIBRARY to setOf("dll", "ocx", "cpl", "sys", "drv", "mui", "ax", "exe"),
            FileFormat.ELF to setOf("so", "elf", "bin", "o", "ko", "out", "run", "axf"),
            FileFormat.PDF to setOf("pdf"),
        )
        private val EXECUTABLE_FORMATS = setOf(FileFormat.PE_EXECUTABLE, FileFormat.PE_LIBRARY, FileFormat.ELF, FileFormat.APK, FileFormat.DEX, FileFormat.JAR)
        private val DISGUISE_EXTENSIONS = setOf(
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif",
            "mp3", "mp4", "avi", "mov", "csv", "html", "htm",
        )
    }
}
