package com.aegis.security.core.security.pe

import com.aegis.security.core.security.identify.DefaultFormatIdentifier
import com.aegis.security.core.security.util.BinaryFile
import com.aegis.security.core.security.util.ContentScanner
import com.aegis.security.core.security.util.MalformedFileException
import com.aegis.security.core.security.util.entropy
import com.aegis.security.core.security.util.hex32
import com.aegis.security.core.security.util.startsWith
import com.aegis.security.core.security.util.summarize
import com.aegis.security.domain.analysis.AnalysisEngine
import com.aegis.security.domain.analysis.AnalysisFact
import com.aegis.security.domain.analysis.AnalysisInput
import com.aegis.security.domain.analysis.DetailEntry
import com.aegis.security.domain.analysis.DetailKind
import com.aegis.security.domain.analysis.DetailSection
import com.aegis.security.domain.analysis.EngineDescriptor
import com.aegis.security.domain.analysis.EngineResult
import com.aegis.security.domain.model.FileFormat
import javax.inject.Inject

data class PeSection(
    val name: String,
    val virtualAddress: Long,
    val virtualSize: Long,
    val rawOffset: Long,
    val rawSize: Long,
    val characteristics: Long,
    val entropy: Double,
) {
    val executable get() = characteristics and EXECUTE != 0L
    val writable get() = characteristics and WRITE != 0L

    companion object {
        const val EXECUTE = 0x20000000L
        const val WRITE = 0x80000000L
    }
}

data class PeFacts(
    val machine: String,
    val is64Bit: Boolean,
    val isDll: Boolean,
    val subsystem: String,
    val timestampEpochSeconds: Long,
    val entryPointRva: Long,
    val entrySection: String?,
    val entryInLastSection: Boolean,
    val sections: List<PeSection>,
    val imports: Map<String, List<String>>,
    val hasAuthenticode: Boolean,
    val isDotNet: Boolean,
    val overlayBytes: Long,
    val inconsistencies: List<String>,
    val contentMatches: Set<String>,
    val urls: List<String>,
) : AnalysisFact

/** Análise estática de PE/COFF (EXE/DLL). Nenhum código Windows é executado. */
class PeEngine @Inject constructor() : AnalysisEngine {
    override val descriptor = EngineDescriptor(
        "pe",
        "Analisador de executáveis Windows (PE)",
        setOf(FileFormat.PE_EXECUTABLE, FileFormat.PE_LIBRARY),
    )

    override suspend fun analyze(input: AnalysisInput): EngineResult {
        val facts = try {
            BinaryFile(input.file).use { parse(it) }
        } catch (error: MalformedFileException) {
            return EngineResult.Failed("estrutura PE inválida: ${error.message}")
        }
        val scan = ContentScanner.scan(input.file, SUSPICIOUS_STRINGS.keys, input.limits.maxContentScanBytes)
        val complete = facts.copy(contentMatches = scan.matches.keys, urls = scan.urls)
        return EngineResult.Completed(details(complete, scan.truncated), listOf(complete))
    }

    internal fun parse(bin: BinaryFile): PeFacts {
        val inconsistencies = mutableListOf<String>()
        if (bin.length < 64) throw MalformedFileException("cabeçalho DOS truncado")
        val pe = bin.u32(0x3C)
        if (pe < 0x40 || !bin.contains(pe, 24)) throw MalformedFileException("e_lfanew aponta para fora do arquivo")
        if (!bin.bytes(pe, 4).startsWith(DefaultFormatIdentifier.PE_SIGNATURE)) throw MalformedFileException("assinatura PE ausente")

        val machine = bin.u16(pe + 4)
        val sectionCount = bin.u16(pe + 6)
        val timestamp = bin.u32(pe + 8)
        val optionalSize = bin.u16(pe + 20)
        val characteristics = bin.u16(pe + 22)
        val opt = pe + 24
        if (optionalSize < 96 || !bin.contains(opt, optionalSize.toLong())) throw MalformedFileException("cabeçalho opcional truncado")
        val magic = bin.u16(opt)
        val is64 = when (magic) {
            0x10B -> false
            0x20B -> true
            else -> throw MalformedFileException("magic do cabeçalho opcional desconhecido (${hex32(magic.toLong())})")
        }
        val entryRva = bin.u32(opt + 16)
        val subsystem = bin.u16(opt + 68)
        val directoriesOffset = opt + if (is64) 112 else 96
        val directoryCount = minOf(bin.u32(opt + if (is64) 108 else 92), 16L).toInt()
        fun directory(index: Int): Pair<Long, Long> {
            val at = directoriesOffset + index * 8L
            if (index >= directoryCount || at + 8 > opt + optionalSize) return 0L to 0L
            return bin.u32(at) to bin.u32(at + 4)
        }

        if (sectionCount == 0) inconsistencies += "nenhuma seção declarada"
        if (sectionCount > MAX_SECTIONS) inconsistencies += "$sectionCount seções (o carregador do Windows aceita até $MAX_SECTIONS)"
        val sectionTable = opt + optionalSize
        val sections = (0 until minOf(sectionCount, MAX_SECTIONS)).mapNotNull { index ->
            val at = sectionTable + index * 40L
            if (!bin.contains(at, 40)) {
                inconsistencies += "tabela de seções truncada"
                return@mapNotNull null
            }
            val name = String(bin.bytes(at, 8), Charsets.ISO_8859_1).trimEnd('\u0000')
            val rawSize = bin.u32(at + 16)
            val rawOffset = bin.u32(at + 20)
            if (rawSize > 0 && !bin.contains(rawOffset, rawSize)) inconsistencies += "seção '$name' aponta para dados fora do arquivo"
            PeSection(
                name = name,
                virtualAddress = bin.u32(at + 12),
                virtualSize = bin.u32(at + 8),
                rawOffset = rawOffset,
                rawSize = rawSize,
                characteristics = bin.u32(at + 36),
                entropy = if (rawSize > 0 && bin.contains(rawOffset, 1)) bin.entropy(rawOffset, rawSize) else 0.0,
            )
        }

        val entrySection = sections.firstOrNull { entryRva >= it.virtualAddress && entryRva < it.virtualAddress + maxOf(it.virtualSize, it.rawSize) }
        val isDll = characteristics and DefaultFormatIdentifier.IMAGE_FILE_DLL != 0
        if (entryRva != 0L && entrySection == null) inconsistencies += "ponto de entrada (${hex32(entryRva)}) fora de qualquer seção"

        val (importRva, _) = directory(1)
        val imports = if (importRva != 0L) readImports(bin, sections, importRva, is64, inconsistencies) else emptyMap()
        val (securityOffset, securitySize) = directory(4)
        val (clrRva, _) = directory(14)

        val endOfSections = sections.maxOfOrNull { it.rawOffset + it.rawSize } ?: 0L
        val overlay = if (endOfSections in 1 until bin.length) {
            val signatureBytes = if (securityOffset >= endOfSections) securitySize else 0L
            maxOf(bin.length - endOfSections - signatureBytes, 0L)
        } else {
            0L
        }

        return PeFacts(
            machine = MACHINES[machine] ?: "Desconhecida (${hex32(machine.toLong())})",
            is64Bit = is64,
            isDll = isDll,
            subsystem = SUBSYSTEMS[subsystem] ?: "Desconhecido ($subsystem)",
            timestampEpochSeconds = timestamp,
            entryPointRva = entryRva,
            entrySection = entrySection?.name,
            entryInLastSection = entrySection != null && sections.size > 1 && entrySection == sections.last(),
            sections = sections,
            imports = imports,
            hasAuthenticode = securityOffset > 0 && securitySize > 0 && bin.contains(securityOffset, securitySize),
            isDotNet = clrRva != 0L,
            overlayBytes = overlay,
            inconsistencies = inconsistencies.distinct(),
            contentMatches = emptySet(),
            urls = emptyList(),
        )
    }

    private fun rvaToOffset(sections: List<PeSection>, rva: Long): Long? {
        val section = sections.firstOrNull { rva >= it.virtualAddress && rva < it.virtualAddress + maxOf(it.virtualSize, it.rawSize) }
            ?: return null
        val delta = rva - section.virtualAddress
        return if (delta < section.rawSize) section.rawOffset + delta else null
    }

    private fun readImports(
        bin: BinaryFile,
        sections: List<PeSection>,
        importRva: Long,
        is64: Boolean,
        inconsistencies: MutableList<String>,
    ): Map<String, List<String>> {
        val result = linkedMapOf<String, List<String>>()
        var descriptor = rvaToOffset(sections, importRva) ?: run {
            inconsistencies += "tabela de importação fora das seções"
            return result
        }
        var totalFunctions = 0
        repeat(MAX_IMPORT_DLLS) {
            if (!bin.contains(descriptor, 20)) return result
            val originalThunk = bin.u32(descriptor)
            val nameRva = bin.u32(descriptor + 12)
            val firstThunk = bin.u32(descriptor + 16)
            if (originalThunk == 0L && nameRva == 0L && firstThunk == 0L) return result
            val dllName = rvaToOffset(sections, nameRva)?.let { bin.cString(it, 128) }?.lowercase()
            if (dllName.isNullOrBlank()) {
                inconsistencies += "importação com nome de DLL inválido"
                return result
            }
            val functions = mutableListOf<String>()
            var thunk = rvaToOffset(sections, if (originalThunk != 0L) originalThunk else firstThunk)
            val width = if (is64) 8 else 4
            while (thunk != null && bin.contains(thunk, width.toLong()) && totalFunctions < MAX_IMPORT_FUNCTIONS) {
                val raw = bin.bytes(thunk, width)
                var value = 0L
                for (i in width - 1 downTo 0) value = (value shl 8) or (raw[i].toLong() and 0xFF)
                if (value == 0L) break
                val ordinalFlag = if (is64) value < 0 else value and 0x80000000L != 0L
                if (ordinalFlag) {
                    functions += "#${value and 0xFFFF}"
                } else {
                    val nameOffset = rvaToOffset(sections, (value and 0x7FFFFFFF) + 2)
                    functions += nameOffset?.let { bin.cString(it, 128) } ?: "?"
                }
                totalFunctions++
                thunk += width
            }
            result[dllName] = functions
            descriptor += 20
        }
        return result
    }

    private fun details(facts: PeFacts, truncated: Boolean): List<DetailSection> {
        val metadata = DetailSection(
            DetailKind.METADATA,
            "Executável Windows",
            listOf(
                DetailEntry("Tipo", if (facts.isDll) "Biblioteca (DLL)" else "Executável (EXE)"),
                DetailEntry("Arquitetura", facts.machine + if (facts.is64Bit) " · PE32+" else " · PE32"),
                DetailEntry("Subsistema", facts.subsystem),
                DetailEntry("Carimbo de compilação", if (facts.timestampEpochSeconds == 0L) "Ausente" else "${facts.timestampEpochSeconds} (época Unix)"),
                DetailEntry(".NET", if (facts.isDotNet) "Sim" else "Não"),
                DetailEntry("Assinatura Authenticode", if (facts.hasAuthenticode) "Presente (não verificada)" else "Ausente"),
            ),
        )
        val structure = DetailSection(
            DetailKind.STRUCTURE,
            "Cabeçalhos e seções",
            buildList {
                add(DetailEntry("Ponto de entrada", "${hex32(facts.entryPointRva)} (${facts.entrySection ?: "fora das seções"})", monospace = true))
                facts.sections.forEach { s ->
                    val flags = buildString {
                        append(if (s.characteristics and 0x40000000L != 0L) "R" else "-")
                        append(if (s.writable) "W" else "-")
                        append(if (s.executable) "X" else "-")
                    }
                    add(DetailEntry("Seção ${s.name.ifBlank { "(sem nome)" }}", "$flags · ${s.rawSize} bytes · entropia %.2f".format(s.entropy), monospace = true))
                }
                if (facts.overlayBytes > 0) add(DetailEntry("Dados anexados (overlay)", "${facts.overlayBytes} bytes"))
                facts.imports.forEach { (dll, functions) -> add(DetailEntry("Importa $dll", functions.summarize(12), monospace = true)) }
                if (facts.urls.isNotEmpty()) add(DetailEntry("URLs encontradas", facts.urls.joinToString("\n"), monospace = true))
                if (truncated) add(DetailEntry("Varredura de strings", "Parcial (limite de conteúdo atingido)"))
                facts.inconsistencies.forEach { add(DetailEntry("Inconsistência", it)) }
            },
        )
        return listOf(metadata, structure)
    }

    companion object {
        private const val MAX_SECTIONS = 96
        private const val MAX_IMPORT_DLLS = 512
        private const val MAX_IMPORT_FUNCTIONS = 20_000

        val MACHINES = mapOf(
            0x14C to "x86 (i386)", 0x8664 to "x86-64 (AMD64)", 0x1C0 to "ARM", 0x1C4 to "ARM Thumb-2",
            0xAA64 to "ARM64", 0x200 to "Intel Itanium", 0xA641 to "ARM64EC",
        )
        val SUBSYSTEMS = mapOf(
            1 to "Nativo", 2 to "Interface gráfica (GUI)", 3 to "Console", 5 to "OS/2", 7 to "POSIX",
            9 to "Windows CE", 10 to "Aplicativo EFI", 11 to "Driver EFI de boot", 12 to "Driver EFI de runtime",
            14 to "Xbox", 16 to "Aplicativo de boot do Windows",
        )

        /** Strings associadas a comportamentos específicos; nome → descrição. */
        val SUSPICIOUS_STRINGS = mapOf(
            "vssadmin delete shadows" to "Exclusão de cópias de sombra (comportamento de ransomware)",
            "wmic shadowcopy delete" to "Exclusão de cópias de sombra via WMIC",
            "bcdedit /set {default} recoveryenabled no" to "Desativação da recuperação do Windows",
            "wbadmin delete catalog" to "Exclusão do catálogo de backup",
            "-encodedcommand" to "PowerShell com comando codificado",
            "powershell -enc" to "PowerShell com comando codificado",
            "\\currentversion\\run" to "Chave de inicialização automática do registro",
            "schtasks /create" to "Criação de tarefa agendada",
            "cmd.exe /c" to "Execução de comandos via cmd.exe",
            "stratum+tcp://" to "Protocolo de mineração de criptomoedas",
        )
    }
}
