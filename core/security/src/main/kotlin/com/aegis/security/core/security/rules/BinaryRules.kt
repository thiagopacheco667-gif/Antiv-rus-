package com.aegis.security.core.security.rules

import com.aegis.security.core.security.elf.ElfEngine
import com.aegis.security.core.security.elf.ElfFacts
import com.aegis.security.core.security.pe.PeEngine
import com.aegis.security.core.security.pe.PeFacts
import com.aegis.security.domain.analysis.FindingCategory
import com.aegis.security.domain.analysis.Severity
import javax.inject.Inject

class BinaryRules @Inject constructor() : RuleSet {
    private fun pe(bag: FactBag) = bag.get<PeFacts>()
    private fun elf(bag: FactBag) = bag.get<ElfFacts>()

    override val rules = listOf(
        LocalRule(
            "AEGIS-PE-001", "Seção gravável e executável", FindingCategory.EXECUTABLE, Severity.MEDIUM,
            "Seções W+X permitem que o programa modifique o próprio código em execução, técnica típica de " +
                "empacotadores e código autodescompactável.",
        ) { bag -> pe(bag)?.sections.orEmpty().filter { it.writable && it.executable }.map { RuleHit("seção ${it.name}") } },

        LocalRule(
            "AEGIS-PE-002", "Seção com entropia muito alta", FindingCategory.OBFUSCATION, Severity.MEDIUM,
            "Entropia acima de 7,2 bits/byte em seções de código indica dados comprimidos ou cifrados (empacotamento). " +
                "Recursos como imagens também têm alta entropia.",
        ) { bag ->
            pe(bag)?.sections.orEmpty().filter { it.entropy > HIGH_ENTROPY && it.rawSize > 4096 && (it.executable || it.name != ".rsrc") }
                .map { RuleHit("seção ${it.name}: %.2f".format(it.entropy)) }
        },

        LocalRule(
            "AEGIS-PE-003", "Nome de seção de empacotador conhecido", FindingCategory.OBFUSCATION, Severity.MEDIUM,
            "Seções com nomes de empacotadores (UPX, ASPack, MPRESS, Themida, VMProtect...) indicam que o código real " +
                "está comprimido ou protegido.",
        ) { bag ->
            pe(bag)?.sections.orEmpty().filter { s -> PACKER_SECTIONS.any { s.name.equals(it, ignoreCase = true) } }.map { RuleHit(it.name) }
        },

        LocalRule(
            "AEGIS-PE-004", "Ponto de entrada incomum", FindingCategory.EXECUTABLE, Severity.MEDIUM,
            "Compiladores colocam o ponto de entrada na seção de código. Entrada fora das seções ou na última seção " +
                "é característica de executáveis empacotados ou infectados.",
        ) { bag ->
            val facts = pe(bag) ?: return@LocalRule emptyList()
            when {
                facts.isDll && facts.entryPointRva == 0L -> emptyList()
                facts.entrySection == null && facts.entryPointRva != 0L -> listOf(RuleHit("entrada fora de qualquer seção"))
                facts.entryInLastSection -> listOf(RuleHit("entrada na última seção (${facts.entrySection})"))
                else -> emptyList()
            }
        },

        LocalRule(
            "AEGIS-PE-005", "Importações associadas a injeção em outros processos", FindingCategory.EXECUTABLE, Severity.HIGH,
            "A combinação VirtualAllocEx + WriteProcessMemory + CreateRemoteThread (ou equivalentes) permite escrever " +
                "e executar código dentro de outro processo.",
        ) { bag ->
            val functions = pe(bag)?.imports?.values?.flatten()?.map { it.removeSuffix("A").removeSuffix("W") }?.toSet().orEmpty()
            val alloc = functions.any { it in setOf("VirtualAllocEx", "NtAllocateVirtualMemory") }
            val write = functions.any { it in setOf("WriteProcessMemory", "NtWriteVirtualMemory") }
            val exec = functions.any { it in setOf("CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "QueueUserAPC", "RtlCreateUserThread") }
            if (alloc && write && exec) listOf(RuleHit("alocação + escrita + execução remotas importadas")) else emptyList()
        },

        LocalRule(
            "AEGIS-PE-006", "Importações de captura de teclado", FindingCategory.EXECUTABLE, Severity.MEDIUM,
            "SetWindowsHookEx com GetAsyncKeyState/GetKeyboardState permite registrar teclas digitadas. " +
                "Também aparece em utilitários de atalhos e jogos.",
        ) { bag ->
            val functions = pe(bag)?.imports?.values?.flatten()?.map { it.removeSuffix("A").removeSuffix("W") }?.toSet().orEmpty()
            if ("SetWindowsHookEx" in functions && (functions.contains("GetAsyncKeyState") || functions.contains("GetKeyboardState"))) {
                listOf(RuleHit("SetWindowsHookEx + leitura de estado do teclado"))
            } else {
                emptyList()
            }
        },

        LocalRule(
            "AEGIS-PE-007", "Inconsistências estruturais no PE", FindingCategory.STRUCTURE, Severity.MEDIUM,
            "Cabeçalhos que apontam para fora do arquivo ou tabelas inválidas indicam corrupção ou manipulação " +
                "para confundir ferramentas de análise.",
        ) { bag -> pe(bag)?.let { hitsFrom(it.inconsistencies) }.orEmpty() },

        LocalRule(
            "AEGIS-PE-008", "Comandos associados a ransomware ou persistência", FindingCategory.EXECUTABLE, Severity.MEDIUM,
            "Strings de comandos que apagam backups, desativam a recuperação ou criam inicialização automática.",
        ) { bag ->
            val matches = pe(bag)?.contentMatches.orEmpty()
            matches.map { key ->
                val ransomware = key.contains("shadow") || key.contains("recoveryenabled") || key.contains("wbadmin")
                RuleHit(PeEngine.SUSPICIOUS_STRINGS[key] ?: key, if (ransomware) Severity.HIGH else null)
            }
        },

        LocalRule(
            "AEGIS-ELF-001", "ELF sem cabeçalhos de seção ou com estrutura inválida", FindingCategory.STRUCTURE, Severity.MEDIUM,
            "Compiladores sempre geram tabela de seções; sua ausência ou inconsistência é típica de binários empacotados " +
                "ou adulterados para dificultar análise.",
        ) { bag -> elf(bag)?.let { hitsFrom(it.inconsistencies) }.orEmpty() },

        LocalRule(
            "AEGIS-ELF-002", "Marcador do empacotador UPX", FindingCategory.OBFUSCATION, Severity.MEDIUM,
            "O UPX comprime o executável; é usado legitimamente, mas também para esconder código malicioso.",
        ) { bag -> if (elf(bag)?.upxMarker == true) listOf(RuleHit("assinatura \"UPX!\"")) else emptyList() },

        LocalRule(
            "AEGIS-ELF-003", "Pilha ou segmentos graváveis e executáveis", FindingCategory.EXECUTABLE, Severity.MEDIUM,
            "Pilha executável ou segmentos RWX desativam proteções de memória (NX) e facilitam execução de código injetado.",
        ) { bag ->
            val facts = elf(bag) ?: return@LocalRule emptyList()
            buildList {
                if (facts.executableStack) add(RuleHit("PT_GNU_STACK executável"))
                if (facts.rwxSegments > 0) add(RuleHit("${facts.rwxSegments} segmento(s) RWX"))
            }
        },

        LocalRule(
            "AEGIS-ELF-004", "Strings associadas a mineração, persistência ou shell reverso", FindingCategory.EXECUTABLE, Severity.MEDIUM,
            "Referências a protocolos de mineração, LD_PRELOAD, /dev/tcp ou crontab são comuns em malware para Linux e IoT.",
        ) { bag ->
            elf(bag)?.contentMatches.orEmpty().map { key ->
                RuleHit(ElfEngine.SUSPICIOUS_STRINGS[key] ?: key, if (key == "stratum+tcp://" || key == "/dev/tcp/") Severity.HIGH else null)
            }
        },
    )

    companion object {
        private const val HIGH_ENTROPY = 7.2
        val PACKER_SECTIONS = listOf(
            "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".MPRESS1", ".MPRESS2", ".petite", ".themida", ".winlice",
            ".vmp0", ".vmp1", ".vmp2", ".enigma1", ".enigma2", "PEC2", ".nsp0", ".nsp1", ".packed", ".perplex",
        )
    }
}
