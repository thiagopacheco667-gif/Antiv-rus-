package com.aegis.security.core.security.elf

import com.aegis.security.core.security.util.BinaryFile
import com.aegis.security.core.security.util.ContentScanner
import com.aegis.security.core.security.util.MalformedFileException
import com.aegis.security.core.security.util.hex32
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

data class ElfFacts(
    val is64Bit: Boolean,
    val bigEndian: Boolean,
    val type: String,
    val machine: String,
    val osAbi: Int,
    val entryPoint: Long,
    val programHeaders: Int,
    val sectionHeaders: Int,
    val sectionNames: List<String>,
    val interpreter: String?,
    val rwxSegments: Int,
    val executableStack: Boolean,
    val dynamic: Boolean,
    val stripped: Boolean,
    val upxMarker: Boolean,
    val inconsistencies: List<String>,
    val contentMatches: Set<String>,
    val urls: List<String>,
) : AnalysisFact

/** Análise estática de ELF (System V ABI). Nenhum código é executado. */
class ElfEngine @Inject constructor() : AnalysisEngine {
    override val descriptor = EngineDescriptor("elf", "Analisador de executáveis ELF", setOf(FileFormat.ELF))

    override suspend fun analyze(input: AnalysisInput): EngineResult {
        val parsed = try {
            BinaryFile(input.file).use { parse(it) }
        } catch (error: MalformedFileException) {
            return EngineResult.Failed("estrutura ELF inválida: ${error.message}")
        }
        val scan = ContentScanner.scan(input.file, SUSPICIOUS_STRINGS.keys + UPX_MARKER, input.limits.maxContentScanBytes)
        val facts = parsed.copy(
            upxMarker = UPX_MARKER in scan.matches,
            contentMatches = scan.matches.keys - UPX_MARKER,
            urls = scan.urls,
        )
        val incomplete = if (scan.truncated) listOf("varredura de strings limitada aos primeiros ${input.limits.maxContentScanMb} MB") else emptyList()
        return EngineResult.Completed(details(facts), listOf(facts), incomplete)
    }

    internal fun parse(bin: BinaryFile): ElfFacts {
        if (bin.length < 52) throw MalformedFileException("cabeçalho ELF truncado")
        val elfClass = bin.u8(4)
        val data = bin.u8(5)
        if (elfClass !in 1..2) throw MalformedFileException("classe ELF inválida ($elfClass)")
        if (data !in 1..2) throw MalformedFileException("codificação de dados ELF inválida ($data)")
        val is64 = elfClass == 2
        val be = data == 2
        if (is64 && bin.length < 64) throw MalformedFileException("cabeçalho ELF64 truncado")
        val inconsistencies = mutableListOf<String>()

        val type = bin.u16(16, be)
        val machine = bin.u16(18, be)
        val entry = if (is64) bin.u64(24, be) else bin.u32(24, be)
        val phoff = if (is64) bin.u64(32, be) else bin.u32(28, be)
        val shoff = if (is64) bin.u64(40, be) else bin.u32(32, be)
        val phentsize = bin.u16(if (is64) 54 else 42, be)
        val phnum = bin.u16(if (is64) 56 else 44, be)
        val shentsize = bin.u16(if (is64) 58 else 46, be)
        val shnum = bin.u16(if (is64) 60 else 48, be)
        val shstrndx = bin.u16(if (is64) 62 else 50, be)

        var interpreter: String? = null
        var rwx = 0
        var execStack = false
        var hasDynamic = false
        val expectedPh = if (is64) 56 else 32
        if (phnum > 0) {
            if (phentsize != expectedPh) inconsistencies += "tamanho de cabeçalho de programa inesperado ($phentsize)"
            if (!bin.contains(phoff, phnum.toLong() * phentsize)) {
                inconsistencies += "cabeçalhos de programa fora do arquivo"
            } else if (phentsize == expectedPh) {
                for (i in 0 until minOf(phnum, MAX_HEADERS)) {
                    val at = phoff + i.toLong() * phentsize
                    val pType = bin.u32(at, be)
                    val flags = if (is64) bin.u32(at + 4, be) else bin.u32(at + 24, be)
                    val pOffset = if (is64) bin.u64(at + 8, be) else bin.u32(at + 4, be)
                    val pFilesz = if (is64) bin.u64(at + 32, be) else bin.u32(at + 16, be)
                    when (pType) {
                        PT_INTERP -> if (bin.contains(pOffset, pFilesz)) interpreter = bin.cString(pOffset, minOf(pFilesz, 256).toInt())
                        PT_DYNAMIC -> hasDynamic = true
                        PT_GNU_STACK -> execStack = flags and PF_X != 0L
                    }
                    if (pType == PT_LOAD && flags and (PF_X or PF_W) == (PF_X or PF_W)) rwx++
                    if (pType == PT_LOAD && pFilesz > 0 && !bin.contains(pOffset, pFilesz)) inconsistencies += "segmento carregável aponta para fora do arquivo"
                }
            }
        }

        val sectionNames = mutableListOf<String>()
        val expectedSh = if (is64) 64 else 40
        if (shnum == 0) {
            inconsistencies += "nenhum cabeçalho de seção (comum em binários empacotados ou adulterados)"
        } else if (shentsize != expectedSh || !bin.contains(shoff, shnum.toLong() * shentsize)) {
            inconsistencies += "tabela de seções inválida ou fora do arquivo"
        } else if (shstrndx < shnum) {
            val strAt = shoff + shstrndx.toLong() * shentsize
            val strOffset = if (is64) bin.u64(strAt + 24, be) else bin.u32(strAt + 16, be)
            val strSize = if (is64) bin.u64(strAt + 32, be) else bin.u32(strAt + 20, be)
            if (bin.contains(strOffset, strSize)) {
                for (i in 0 until minOf(shnum, MAX_HEADERS)) {
                    val nameIndex = bin.u32(shoff + i.toLong() * shentsize, be)
                    if (nameIndex < strSize) sectionNames += bin.cString(strOffset + nameIndex, 64)
                }
            } else {
                inconsistencies += "tabela de nomes de seção fora do arquivo"
            }
        }

        return ElfFacts(
            is64Bit = is64,
            bigEndian = be,
            type = TYPES[type] ?: "Desconhecido ($type)",
            machine = MACHINES[machine] ?: "Desconhecida ($machine)",
            osAbi = bin.u8(7),
            entryPoint = entry,
            programHeaders = phnum,
            sectionHeaders = shnum,
            sectionNames = sectionNames.filter { it.isNotBlank() },
            interpreter = interpreter,
            rwxSegments = rwx,
            executableStack = execStack,
            dynamic = hasDynamic,
            stripped = sectionNames.isNotEmpty() && ".symtab" !in sectionNames,
            upxMarker = false,
            inconsistencies = inconsistencies.distinct(),
            contentMatches = emptySet(),
            urls = emptyList(),
        )
    }

    private fun details(facts: ElfFacts) = listOf(
        DetailSection(
            DetailKind.METADATA,
            "Executável ELF",
            listOf(
                DetailEntry("Tipo", facts.type),
                DetailEntry("Arquitetura", "${facts.machine} · ${if (facts.is64Bit) "64" else "32"} bits · ${if (facts.bigEndian) "big-endian" else "little-endian"}"),
                DetailEntry("Interpretador", facts.interpreter ?: "Nenhum (estático ou não executável)", monospace = facts.interpreter != null),
                DetailEntry("Ligação dinâmica", if (facts.dynamic) "Sim" else "Não"),
                DetailEntry("Símbolos", if (facts.stripped) "Removidos (stripped)" else "Presentes ou sem tabela de seções"),
            ),
        ),
        DetailSection(
            DetailKind.STRUCTURE,
            "Cabeçalhos e seções",
            buildList {
                add(DetailEntry("Ponto de entrada", hex32(facts.entryPoint), monospace = true))
                add(DetailEntry("Cabeçalhos de programa", facts.programHeaders.toString()))
                add(DetailEntry("Seções", "${facts.sectionHeaders}: ${facts.sectionNames.summarize(15)}", monospace = true))
                add(DetailEntry("Pilha executável", if (facts.executableStack) "Sim" else "Não"))
                add(DetailEntry("Segmentos graváveis e executáveis", facts.rwxSegments.toString()))
                if (facts.urls.isNotEmpty()) add(DetailEntry("URLs encontradas", facts.urls.joinToString("\n"), monospace = true))
                facts.inconsistencies.forEach { add(DetailEntry("Inconsistência", it)) }
            },
        ),
    )

    companion object {
        private const val MAX_HEADERS = 4096
        private const val PT_LOAD = 1L
        private const val PT_DYNAMIC = 2L
        private const val PT_INTERP = 3L
        private const val PT_GNU_STACK = 0x6474E551L
        private const val PF_X = 1L
        private const val PF_W = 2L
        const val UPX_MARKER = "UPX!"

        val TYPES = mapOf(1 to "Objeto relocável", 2 to "Executável", 3 to "Objeto compartilhado / PIE", 4 to "Core dump")
        val MACHINES = mapOf(
            3 to "x86", 0x3E to "x86-64", 0x28 to "ARM", 0xB7 to "AArch64", 8 to "MIPS",
            0x14 to "PowerPC", 0x15 to "PowerPC64", 0xF3 to "RISC-V", 0x2B to "SPARC V9", 0x16 to "S390",
        )
        val SUSPICIOUS_STRINGS = mapOf(
            "stratum+tcp://" to "Protocolo de mineração de criptomoedas",
            "/etc/ld.so.preload" to "Persistência via ld.so.preload",
            "ld_preload" to "Injeção via LD_PRELOAD",
            "/dev/tcp/" to "Conexão de shell reverso via /dev/tcp",
            "chmod 777" to "Alteração ampla de permissões",
            "/etc/shadow" to "Acesso ao arquivo de senhas do sistema",
            "crontab -" to "Alteração de tarefas agendadas (cron)",
        )
    }
}
