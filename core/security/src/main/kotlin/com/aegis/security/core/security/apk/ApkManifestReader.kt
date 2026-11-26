package com.aegis.security.core.security.apk

import java.io.File

data class ApkComponent(
    val type: Type,
    val name: String,
    val exported: Boolean,
    val permission: String?,
) {
    enum class Type(val label: String) { ACTIVITY("Atividade"), SERVICE("Serviço"), RECEIVER("Receptor"), PROVIDER("Provedor") }
}

/** Dados do AndroidManifest.xml e da assinatura, lidos sem instalar nem executar o APK. */
data class ApkManifest(
    val packageName: String,
    val versionName: String?,
    val versionCode: Long,
    val minSdk: Int?,
    val targetSdk: Int?,
    val permissions: List<String>,
    val debuggable: Boolean,
    val usesCleartextTraffic: Boolean,
    val allowBackup: Boolean,
    val components: List<ApkComponent>,
    /** Certificados X.509 codificados (DER) informados pelo verificador do sistema. */
    val signerCertificates: List<ByteArray>,
    val hasPastSigningCertificates: Boolean,
)

/**
 * Lê o manifesto binário e as assinaturas de um APK. A implementação Android usa o parser
 * do próprio sistema (PackageManager.getPackageArchiveInfo), que não instala nem executa código.
 */
interface ApkManifestReader {
    /** Retorna null quando o sistema não consegue interpretar o APK. */
    fun read(apk: File): ApkManifest?
}
