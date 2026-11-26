package com.aegis.security.core.security.rules

import com.aegis.security.core.security.apk.ApkFacts
import com.aegis.security.core.security.apk.ApkKnowledge
import com.aegis.security.core.security.dex.DexFacts
import com.aegis.security.domain.analysis.FindingCategory
import com.aegis.security.domain.analysis.Severity
import javax.inject.Inject

class ApkRules @Inject constructor() : RuleSet {
    private fun apk(bag: FactBag) = bag.get<ApkFacts>()

    override val rules = listOf(
        LocalRule(
            "AEGIS-APK-001", "Permissões sensíveis solicitadas", FindingCategory.PERMISSION, Severity.LOW,
            "Estas permissões dão acesso a dados pessoais ou ao controle do aparelho. Muitos apps legítimos " +
                "as usam; avalie se fazem sentido para a finalidade do app.",
        ) { bag ->
            apk(bag)?.manifest?.permissions.orEmpty()
                .filter { it in ApkKnowledge.SENSITIVE_PERMISSIONS }
                .map { RuleHit(it.removePrefix("android.permission.")) }
        },

        LocalRule(
            "AEGIS-APK-002", "Combinação de capacidades típica de trojans bancários", FindingCategory.PERMISSION, Severity.HIGH,
            "Serviço de acessibilidade combinado a sobreposição de tela, leitura de SMS ou instalação de pacotes " +
                "permite capturar senhas e códigos de verificação. É o padrão documentado de famílias de trojans " +
                "bancários Android, embora alguns utilitários legítimos combinem essas capacidades.",
        ) { bag ->
            val facts = apk(bag) ?: return@LocalRule emptyList()
            val permissions = facts.manifest.permissions.toSet()
            val accessibility = facts.manifest.components.any { it.permission == ApkKnowledge.BIND_ACCESSIBILITY }
            if (!accessibility) return@LocalRule emptyList()
            val companions = listOf(
                "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
                "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.QUERY_ALL_PACKAGES",
            ).filter { it in permissions }
            if (companions.size >= 2) {
                listOf(RuleHit("serviço de acessibilidade + " + companions.joinToString { it.removePrefix("android.permission.") }))
            } else {
                emptyList()
            }
        },

        LocalRule(
            "AEGIS-APK-003", "Administração do dispositivo ou leitura de notificações", FindingCategory.COMPONENT, Severity.MEDIUM,
            "Administradores de dispositivo podem bloquear a tela e dificultar a desinstalação; leitores de " +
                "notificação acessam mensagens e códigos recebidos.",
        ) { bag ->
            apk(bag)?.manifest?.components.orEmpty()
                .filter { it.permission == ApkKnowledge.BIND_DEVICE_ADMIN || it.permission == ApkKnowledge.BIND_NOTIFICATION_LISTENER }
                .map { RuleHit("${it.type.label} ${it.name} (${it.permission?.removePrefix("android.permission.")})") }
        },

        LocalRule(
            "AEGIS-APK-004", "Componentes exportados sem proteção", FindingCategory.COMPONENT, Severity.LOW,
            "Componentes exportados sem permissão podem ser acionados por qualquer outro app instalado. " +
                "A atividade inicial normalmente é exportada; demais casos merecem revisão.",
        ) { bag ->
            val exported = apk(bag)?.manifest?.components.orEmpty().filter { it.exported && it.permission == null }
            if (exported.size <= 1) emptyList() else exported.map { RuleHit("${it.type.label}: ${it.name}") }
        },

        LocalRule(
            "AEGIS-APK-005", "APK sem assinatura válida reconhecida", FindingCategory.SIGNATURE, Severity.HIGH,
            "O Android exige assinatura para instalar apps. APKs sem assinatura reconhecida pelo verificador do " +
                "sistema foram adulterados, corrompidos ou não são instaláveis.",
        ) { bag ->
            val facts = apk(bag) ?: return@LocalRule emptyList()
            buildList {
                if (!facts.v1Signed && !facts.v2PlusSigned) add(RuleHit("nenhum esquema de assinatura (v1, v2 ou v3) encontrado"))
                if (facts.certificates.isEmpty()) add(RuleHit("o verificador do sistema não retornou certificados"))
                if (facts.unparseableCertificates > 0) add(RuleHit("${facts.unparseableCertificates} certificado(s) ilegível(is)"))
            }
        },

        LocalRule(
            "AEGIS-APK-006", "Assinado com certificado de depuração", FindingCategory.SIGNATURE, Severity.LOW,
            "Certificados \"Android Debug\" são gerados automaticamente para desenvolvimento e não identificam um editor.",
        ) { bag -> apk(bag)?.certificates.orEmpty().filter { it.isDebugCertificate }.map { RuleHit(it.subject) } },

        LocalRule(
            "AEGIS-APK-007", "Certificado fora do período de validade", FindingCategory.SIGNATURE, Severity.LOW,
            "O Android ignora a validade do certificado na instalação, mas datas incoerentes indicam certificados improvisados.",
        ) { bag ->
            val facts = apk(bag) ?: return@LocalRule emptyList()
            facts.certificates.filter { facts.analyzedAtEpochMillis !in it.notBeforeEpochMillis..it.notAfterEpochMillis }
                .map { RuleHit(it.subject) }
        },

        LocalRule(
            "AEGIS-APK-008", "Código executável embutido fora dos locais padrão", FindingCategory.OBFUSCATION, Severity.MEDIUM,
            "DEX, JAR, APK ou bibliotecas guardados em assets/ ou res/ costumam ser carregados dinamicamente, " +
                "técnica usada para esconder código da análise estática.",
        ) { bag -> apk(bag)?.let { hitsFrom(it.embeddedPayloads) }.orEmpty() },

        LocalRule(
            "AEGIS-APK-009", "Biblioteca de empacotador/protetor conhecida", FindingCategory.OBFUSCATION, Severity.MEDIUM,
            "Empacotadores comerciais cifram o código original. Apps legítimos também os usam, mas eles impedem " +
                "a inspeção do código real.",
        ) { bag -> apk(bag)?.let { hitsFrom(it.knownPackerLibraries) }.orEmpty() },

        LocalRule(
            "AEGIS-APK-010", "App depurável", FindingCategory.STRUCTURE, Severity.LOW,
            "android:debuggable permite anexar depuradores e inspecionar a memória do app; não é usado em versões publicadas.",
        ) { bag -> if (apk(bag)?.manifest?.debuggable == true) listOf(RuleHit("android:debuggable=\"true\"")) else emptyList() },

        LocalRule(
            "AEGIS-DEX-001", "DEX com integridade inválida", FindingCategory.STRUCTURE, Severity.MEDIUM,
            "O checksum Adler-32 e a assinatura SHA-1 do cabeçalho DEX não correspondem ao conteúdo, indicando " +
                "modificação posterior à compilação.",
        ) { bag ->
            val dex = bag.get<DexFacts>() ?: return@LocalRule emptyList()
            buildList {
                if (!dex.checksumValid) add(RuleHit("checksum Adler-32 inválido"))
                if (!dex.signatureValid) add(RuleHit("assinatura SHA-1 inválida"))
                if (dex.declaredFileSize != dex.actualFileSize) add(RuleHit("tamanho declarado ${dex.declaredFileSize} ≠ real ${dex.actualFileSize}"))
                if (!dex.endianTagValid) add(RuleHit("marca de endianness inesperada"))
            }
        },

        LocalRule(
            "AEGIS-DEX-002", "Carregamento dinâmico de código ou execução de comandos", FindingCategory.OBFUSCATION, Severity.LOW,
            "Estas APIs permitem baixar e executar código não presente no pacote ou rodar comandos do sistema.",
        ) { bag -> bag.get<DexFacts>()?.apiReferences.orEmpty().map { RuleHit(it) } },
    )
}
