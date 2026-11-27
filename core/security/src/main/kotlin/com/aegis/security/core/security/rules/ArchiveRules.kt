package com.aegis.security.core.security.rules

import com.aegis.security.core.security.zip.ZipFacts
import com.aegis.security.domain.analysis.CommonFacts
import com.aegis.security.domain.model.FileFormat
import com.aegis.security.domain.analysis.FindingCategory
import com.aegis.security.domain.analysis.Severity
import javax.inject.Inject

class ArchiveRules @Inject constructor() : RuleSet {
    private fun zip(bag: FactBag) = bag.get<ZipFacts>()

    override val rules = listOf(
        LocalRule(
            "AEGIS-ZIP-001", "Caminho que tenta escapar do diretório de extração", FindingCategory.ARCHIVE, Severity.HIGH,
            "Entradas com \"../\" ou caminhos absolutos podem sobrescrever arquivos fora da pasta de destino " +
                "ao serem extraídas (vulnerabilidade conhecida como Zip Slip).",
        ) { bag -> zip(bag)?.let { hitsFrom(it.traversalEntries + it.absolutePathEntries) }.orEmpty() },

        LocalRule(
            "AEGIS-ZIP-002", "Indícios de ZIP bomb", FindingCategory.ARCHIVE, Severity.HIGH,
            "Razões de compressão extremas, tamanhos declarados acima dos limites ou entradas sobrepostas " +
                "são usados para esgotar memória e armazenamento de quem extrai o arquivo.",
        ) { bag -> zip(bag)?.let { hitsFrom(it.bombIndicators + it.overlappingEntries.map { o -> "Entradas sobrepostas: $o" }) }.orEmpty() },

        LocalRule(
            "AEGIS-ZIP-003", "Executáveis dentro do arquivo compactado", FindingCategory.ARCHIVE, Severity.MEDIUM,
            "Arquivos compactados são um meio comum de distribuir executáveis e scripts. A presença não indica " +
                "malware por si só, mas o conteúdo deve ser verificado antes de ser aberto.",
        ) { bag ->
            val isApk = bag.get<CommonFacts>()?.format == FileFormat.APK
            // Em APKs, classes*.dex na raiz e lib/<abi>/*.so são a estrutura normal do app, não um indicador.
            val entries = zip(bag)?.executableEntries.orEmpty().filterNot { isApk && (APK_DEX.matches(it) || APK_NATIVE.matches(it)) }
            hitsFrom(entries)
        },

        LocalRule(
            "AEGIS-ZIP-004", "Entrada com extensão dupla", FindingCategory.ARCHIVE, Severity.HIGH,
            "Nomes como \"documento.pdf.exe\" fazem um executável parecer um documento.",
        ) { bag -> zip(bag)?.let { hitsFrom(it.doubleExtensionEntries) }.orEmpty() },

        LocalRule(
            "AEGIS-ZIP-005", "Entrada com nome enganoso (controle bidirecional)", FindingCategory.ARCHIVE, Severity.HIGH,
            "Caracteres de controle de direção (ex.: U+202E) invertem a exibição e escondem a extensão real.",
        ) { bag -> zip(bag)?.let { hitsFrom(it.misleadingNameEntries) }.orEmpty() },

        LocalRule(
            "AEGIS-ZIP-006", "Entradas duplicadas", FindingCategory.ARCHIVE, Severity.MEDIUM,
            "Ferramentas diferentes escolhem entradas diferentes quando um nome se repete, o que permite " +
                "mostrar um conteúdo a um verificador e entregar outro ao extrator (ex.: falhas \"Master Key\" do Android).",
        ) { bag -> zip(bag)?.let { hitsFrom(it.duplicateEntries) }.orEmpty() },

        LocalRule(
            "AEGIS-ZIP-007", "Limite de inspeção atingido", FindingCategory.ARCHIVE, Severity.MEDIUM,
            "O arquivo excede os limites configurados de entradas ou de profundidade; parte do conteúdo não foi inspecionada.",
        ) { bag ->
            val facts = zip(bag) ?: return@LocalRule emptyList()
            buildList {
                if (facts.entryLimitExceeded) add(RuleHit("mais de ${facts.entryCount} entradas (declaradas: ${facts.declaredEntryCount})"))
                if (facts.nestingLimitReached) add(RuleHit("arquivos compactados aninhados além da profundidade configurada"))
            }
        },

        LocalRule(
            "AEGIS-ZIP-008", "Entradas cifradas", FindingCategory.ARCHIVE, Severity.LOW,
            "Conteúdo protegido por senha não pode ser inspecionado; também é usado para driblar verificações.",
        ) { bag -> zip(bag)?.let { if (it.encryptedEntries.isEmpty()) emptyList() else listOf(RuleHit("${it.encryptedEntries.size} entrada(s) cifrada(s)")) }.orEmpty() },

        LocalRule(
            "AEGIS-ZIP-009", "Dados anexados antes do conteúdo compactado", FindingCategory.STRUCTURE, Severity.LOW,
            "Bytes antes do primeiro registro ZIP indicam arquivo autoextraível ou poliglota (válido em dois formatos).",
        ) { bag -> zip(bag)?.let { if (it.prependedBytes > 0) listOf(RuleHit("${it.prependedBytes} bytes antes do primeiro registro")) else emptyList() }.orEmpty() },
    )

    private companion object {
        val APK_DEX = Regex("^classes\\d*\\.dex$")
        val APK_NATIVE = Regex("^lib/[^/]+/[^/]+\\.so$")
    }
}
