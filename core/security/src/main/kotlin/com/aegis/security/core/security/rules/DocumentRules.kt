package com.aegis.security.core.security.rules

import com.aegis.security.core.security.pdf.PdfFacts
import com.aegis.security.domain.analysis.FindingCategory
import com.aegis.security.domain.analysis.Severity
import javax.inject.Inject

class DocumentRules @Inject constructor() : RuleSet {
    private fun pdf(bag: FactBag) = bag.get<PdfFacts>()

    override val rules = listOf(
        LocalRule(
            "AEGIS-PDF-001", "JavaScript embutido", FindingCategory.DOCUMENT, Severity.MEDIUM,
            "Leitores de PDF executam JavaScript embutido; é usado em formulários, mas também para explorar falhas do leitor. " +
                "Combinado com ação automática ao abrir, o risco é maior.",
        ) { bag ->
            val facts = pdf(bag) ?: return@LocalRule emptyList()
            val js = facts.count("JavaScript") + facts.count("JS")
            if (js == 0) return@LocalRule emptyList()
            val auto = facts.count("OpenAction") + facts.count("AA") > 0
            listOf(RuleHit("$js ocorrência(s)" + if (auto) " com ação automática" else "", if (auto) Severity.HIGH else null))
        },

        LocalRule(
            "AEGIS-PDF-002", "Ação para iniciar programas (/Launch)", FindingCategory.DOCUMENT, Severity.HIGH,
            "/Launch pede ao leitor que abra programas ou arquivos externos — recurso raramente legítimo e explorado " +
                "para executar comandos.",
        ) { bag -> pdf(bag)?.count("Launch")?.takeIf { it > 0 }?.let { listOf(RuleHit("$it ocorrência(s)")) }.orEmpty() },

        LocalRule(
            "AEGIS-PDF-003", "Arquivos embutidos", FindingCategory.DOCUMENT, Severity.MEDIUM,
            "PDFs podem carregar outros arquivos (inclusive executáveis) que o leitor oferece para abrir.",
        ) { bag ->
            val facts = pdf(bag) ?: return@LocalRule emptyList()
            val count = facts.count("EmbeddedFile") + facts.count("EmbeddedFiles")
            if (count > 0) listOf(RuleHit("$count referência(s)")) else emptyList()
        },

        LocalRule(
            "AEGIS-PDF-004", "Ação automática ao abrir", FindingCategory.DOCUMENT, Severity.LOW,
            "/OpenAction e /AA executam ações ao abrir o documento ou páginas (navegação, scripts, formulários).",
        ) { bag ->
            val facts = pdf(bag) ?: return@LocalRule emptyList()
            val count = facts.count("OpenAction") + facts.count("AA")
            if (count > 0) listOf(RuleHit("$count ocorrência(s)")) else emptyList()
        },

        LocalRule(
            "AEGIS-PDF-005", "Nomes ofuscados com escapes hexadecimais", FindingCategory.OBFUSCATION, Severity.HIGH,
            "Escrever /JavaScript como /J#61vaScript não muda o significado para o leitor, mas engana verificações " +
                "simples; não há motivo legítimo para ofuscar nomes de ações.",
        ) { bag -> pdf(bag)?.obfuscatedNames.orEmpty().map { RuleHit("/$it") } },

        LocalRule(
            "AEGIS-PDF-006", "Envio de dados ou referências externas", FindingCategory.DOCUMENT, Severity.LOW,
            "/SubmitForm, /ImportData, /GoToR e /GoToE enviam dados de formulário ou abrem documentos remotos.",
        ) { bag ->
            val facts = pdf(bag) ?: return@LocalRule emptyList()
            listOf("SubmitForm", "ImportData", "GoToR", "GoToE").filter { facts.count(it) > 0 }.map { RuleHit("/$it") }
        },

        LocalRule(
            "AEGIS-PDF-007", "Conteúdo ativo XFA ou multimídia", FindingCategory.DOCUMENT, Severity.LOW,
            "Formulários XFA e /RichMedia (Flash) ampliam a superfície de ataque do leitor de PDF.",
        ) { bag ->
            val facts = pdf(bag) ?: return@LocalRule emptyList()
            listOf("XFA", "RichMedia", "JBIG2Decode").filter { facts.count(it) > 0 }.map { RuleHit("/$it") }
        },

        LocalRule(
            "AEGIS-PDF-008", "Inspeção parcial do documento", FindingCategory.DOCUMENT, Severity.LOW,
            "Partes do documento estão cifradas, em fluxos não suportados ou além do limite de conteúdo e não puderam ser verificadas.",
        ) { bag ->
            val facts = pdf(bag) ?: return@LocalRule emptyList()
            buildList {
                if (facts.count("Encrypt") > 0) add(RuleHit("documento criptografado"))
                if (facts.objectStreamsSkipped > 0) add(RuleHit("${facts.objectStreamsSkipped} fluxo(s) de objetos não inspecionado(s)"))
                if (facts.truncatedScan) add(RuleHit("limite de conteúdo atingido"))
            }
        },

        LocalRule(
            "AEGIS-PDF-009", "Cabeçalho PDF deslocado", FindingCategory.STRUCTURE, Severity.LOW,
            "Leitores aceitam o cabeçalho nos primeiros 1024 bytes; conteúdo antes dele pode tornar o arquivo um poliglota.",
        ) { bag -> pdf(bag)?.headerOffset?.takeIf { it > 0 }?.let { listOf(RuleHit("cabeçalho no byte $it")) }.orEmpty() },
    )
}
