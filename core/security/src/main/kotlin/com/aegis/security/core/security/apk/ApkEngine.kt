package com.aegis.security.core.security.apk

import com.aegis.security.core.security.util.MalformedFileException
import com.aegis.security.core.security.util.hex
import com.aegis.security.core.security.util.summarize
import com.aegis.security.core.security.zip.ZipDirectoryParser
import com.aegis.security.domain.analysis.AnalysisEngine
import com.aegis.security.domain.analysis.AnalysisFact
import com.aegis.security.domain.analysis.AnalysisInput
import com.aegis.security.domain.analysis.DetailEntry
import com.aegis.security.domain.analysis.DetailKind
import com.aegis.security.domain.analysis.DetailSection
import com.aegis.security.domain.analysis.EngineDescriptor
import com.aegis.security.domain.analysis.EngineResult
import com.aegis.security.domain.model.FileFormat
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import javax.inject.Inject

data class CertificateFacts(
    val subject: String,
    val issuer: String,
    val serialNumber: String,
    val sha256Fingerprint: String,
    val signatureAlgorithm: String,
    val notBeforeEpochMillis: Long,
    val notAfterEpochMillis: Long,
    val isDebugCertificate: Boolean,
    val selfSigned: Boolean,
)

data class ApkFacts(
    val manifest: ApkManifest,
    val certificates: List<CertificateFacts>,
    val unparseableCertificates: Int,
    val v1Signed: Boolean,
    val v2PlusSigned: Boolean,
    val dexFiles: List<String>,
    val nativeAbis: List<String>,
    val nativeLibraries: List<String>,
    val embeddedPayloads: List<String>,
    val knownPackerLibraries: List<String>,
    val analyzedAtEpochMillis: Long,
) : AnalysisFact

/**
 * Inspeção de APK: manifesto (pacote, versão, permissões, componentes exportados), assinaturas,
 * certificados e arquivos internos relevantes. Permissões sensíveis sozinhas não tornam o app malicioso.
 */
class ApkEngine @Inject constructor(
    private val manifestReader: ApkManifestReader,
) : AnalysisEngine {
    override val descriptor = EngineDescriptor(
        id = "apk",
        displayName = "Analisador de APK",
        supportedFormats = setOf(FileFormat.APK),
    )

    override suspend fun analyze(input: AnalysisInput): EngineResult {
        val directory = try {
            ZipDirectoryParser.parse(input.file, input.limits.maxArchiveEntries)
        } catch (error: MalformedFileException) {
            return EngineResult.Failed("estrutura ZIP do APK inválida: ${error.message}")
        }
        val manifest = manifestReader.read(input.file)
            ?: return EngineResult.Failed("o sistema não conseguiu interpretar o manifesto ou a assinatura do APK")

        val names = directory.entries.map { it.name }
        val dexFiles = names.filter { ROOT_DEX.matches(it) }
        val nativeLibs = names.filter { it.startsWith("lib/") && it.endsWith(".so") }
        val abis = nativeLibs.mapNotNull { it.split('/').getOrNull(1) }.distinct().sorted()
        val embedded = names.filter { name ->
            !ROOT_DEX.matches(name) && !name.startsWith("lib/") &&
                PAYLOAD_EXTENSIONS.any { name.lowercase().endsWith(it) }
        }
        val packers = nativeLibs.map { it.substringAfterLast('/') }.filter { lib -> KNOWN_PACKER_LIBRARIES.any { lib.equals(it, ignoreCase = true) } }
        val v1 = names.any { V1_SIGNATURE.matches(it) } && names.any { it.startsWith("META-INF/") && it.endsWith(".SF") }

        var unparseable = 0
        val certificates = manifest.signerCertificates.mapNotNull { der ->
            parseCertificate(der).also { if (it == null) unparseable++ }
        }

        val facts = ApkFacts(
            manifest = manifest,
            certificates = certificates,
            unparseableCertificates = unparseable,
            v1Signed = v1,
            v2PlusSigned = directory.hasApkSigningBlock,
            dexFiles = dexFiles,
            nativeAbis = abis,
            nativeLibraries = nativeLibs,
            embeddedPayloads = embedded,
            knownPackerLibraries = packers.distinct(),
            analyzedAtEpochMillis = System.currentTimeMillis(),
        )
        return EngineResult.Completed(details = details(facts), facts = listOf(facts))
    }

    private fun details(facts: ApkFacts): List<DetailSection> {
        val m = facts.manifest
        val metadata = DetailSection(
            DetailKind.METADATA,
            "Aplicativo Android",
            listOfNotNull(
                DetailEntry("Pacote", m.packageName, monospace = true),
                DetailEntry("Versão", "${m.versionName ?: "—"} (código ${m.versionCode})"),
                m.minSdk?.let { DetailEntry("SDK mínimo", it.toString()) },
                m.targetSdk?.let { DetailEntry("SDK alvo", it.toString()) },
                DetailEntry("Depurável", yesNo(m.debuggable)),
                DetailEntry("Tráfego sem criptografia permitido", yesNo(m.usesCleartextTraffic)),
                DetailEntry("Backup permitido", yesNo(m.allowBackup)),
                DetailEntry("Arquivos DEX", facts.dexFiles.size.toString()),
                DetailEntry("Bibliotecas nativas", if (facts.nativeLibraries.isEmpty()) "Nenhuma" else "${facts.nativeLibraries.size} (${facts.nativeAbis.joinToString()})"),
                facts.embeddedPayloads.takeIf { it.isNotEmpty() }?.let { DetailEntry("Código embutido fora do padrão", it.summarize(8), monospace = true) },
            ),
        )
        val signature = DetailSection(
            DetailKind.SIGNATURE,
            "Assinatura digital",
            buildList {
                add(DetailEntry("Esquema v1 (JAR)", yesNo(facts.v1Signed)))
                add(DetailEntry("Esquema v2/v3 (bloco de assinatura APK)", yesNo(facts.v2PlusSigned)))
                add(DetailEntry("Rotação de chave registrada", yesNo(m.hasPastSigningCertificates)))
                if (facts.certificates.isEmpty()) add(DetailEntry("Certificados", "Nenhum certificado informado pelo verificador do sistema"))
                facts.certificates.forEachIndexed { index, cert ->
                    val prefix = if (facts.certificates.size > 1) "Certificado ${index + 1} — " else ""
                    add(DetailEntry("${prefix}Titular", cert.subject))
                    add(DetailEntry("${prefix}Emissor", cert.issuer))
                    add(DetailEntry("${prefix}Validade", "${date(cert.notBeforeEpochMillis)} a ${date(cert.notAfterEpochMillis)}"))
                    add(DetailEntry("${prefix}Algoritmo", cert.signatureAlgorithm))
                    add(DetailEntry("${prefix}SHA-256", cert.sha256Fingerprint, monospace = true))
                }
            },
        )
        val permissions = DetailSection(
            DetailKind.PERMISSIONS,
            "Permissões solicitadas (${m.permissions.size})",
            m.permissions.map { permission ->
                DetailEntry(
                    permission.removePrefix("android.permission."),
                    if (permission in ApkKnowledge.SENSITIVE_PERMISSIONS) "Sensível" else "Comum",
                    monospace = true,
                )
            },
        )
        val components = DetailSection(
            DetailKind.COMPONENTS,
            "Componentes (${m.components.size}, ${m.components.count { it.exported }} exportados)",
            m.components.sortedByDescending { it.exported }.take(150).map { c ->
                DetailEntry(
                    "${c.type.label}: ${c.name}",
                    buildString {
                        append(if (c.exported) "Exportado" else "Interno")
                        c.permission?.let { append(" · protegido por ").append(it.removePrefix("android.permission.")) }
                    },
                    monospace = false,
                )
            },
        )
        return listOf(metadata, signature, permissions, components)
    }

    private fun parseCertificate(der: ByteArray): CertificateFacts? = try {
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        val subject = cert.subjectX500Principal.name
        CertificateFacts(
            subject = subject,
            issuer = cert.issuerX500Principal.name,
            serialNumber = cert.serialNumber.toString(16),
            sha256Fingerprint = hex(MessageDigest.getInstance("SHA-256").digest(der)).chunked(2).joinToString(":").uppercase(),
            signatureAlgorithm = cert.sigAlgName,
            notBeforeEpochMillis = cert.notBefore.time,
            notAfterEpochMillis = cert.notAfter.time,
            isDebugCertificate = subject.contains("CN=Android Debug", ignoreCase = true),
            selfSigned = cert.subjectX500Principal == cert.issuerX500Principal,
        )
    } catch (error: CertificateException) {
        null
    } catch (error: ClassCastException) {
        null
    }

    private fun yesNo(value: Boolean) = if (value) "Sim" else "Não"

    private fun date(epochMillis: Long): String =
        SimpleDateFormat("dd/MM/yyyy", Locale.ROOT).apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date(epochMillis))

    companion object {
        private val ROOT_DEX = Regex("^classes\\d*\\.dex$")
        private val V1_SIGNATURE = Regex("^META-INF/[^/]+\\.(RSA|DSA|EC)$", RegexOption.IGNORE_CASE)
        private val PAYLOAD_EXTENSIONS = listOf(".dex", ".jar", ".apk", ".so", ".odex", ".vdex")

        /**
         * Bibliotecas de empacotadores/protetores comerciais conhecidos. São usadas também por apps
         * legítimos; a presença indica ofuscação, não malware.
         */
        val KNOWN_PACKER_LIBRARIES = listOf(
            "libjiagu.so", "libjiagu_x86.so", "libjiagu_a64.so", "libjiagu_x64.so",
            "libsecexe.so", "libsecmain.so", "libDexHelper.so", "libDexHelper-x86.so",
            "libprotectClass.so", "libnqshield.so", "libshell-super.2019.so", "libshella-2.10.3.0.so",
            "libmobisec.so", "libexec.so", "libexecmain.so", "libtup.so", "libbaiduprotect.so",
            "libnesec.so", "libAPKProtect.so", "libdexjni.so", "libitsec.so",
        )
    }
}

/** Conhecimento público sobre permissões Android (developer.android.com/reference/android/Manifest.permission). */
object ApkKnowledge {
    val SENSITIVE_PERMISSIONS = setOf(
        "android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
        "android.permission.RECEIVE_MMS", "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS", "android.permission.CALL_PHONE", "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS", "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_PHONE_STATE", "android.permission.READ_PHONE_NUMBERS",
        "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.REQUEST_DELETE_PACKAGES", "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_SETTINGS", "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.BODY_SENSORS", "android.permission.ACTIVITY_RECOGNITION",
        "android.permission.USE_FULL_SCREEN_INTENT", "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO", "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.GET_ACCOUNTS",
    )

    const val BIND_ACCESSIBILITY = "android.permission.BIND_ACCESSIBILITY_SERVICE"
    const val BIND_DEVICE_ADMIN = "android.permission.BIND_DEVICE_ADMIN"
    const val BIND_NOTIFICATION_LISTENER = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
}
