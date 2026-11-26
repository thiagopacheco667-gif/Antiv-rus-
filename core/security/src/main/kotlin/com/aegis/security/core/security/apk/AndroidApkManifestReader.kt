package com.aegis.security.core.security.apk

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.ComponentInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ProviderInfo
import android.os.Build
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import javax.inject.Inject

internal class AndroidApkManifestReader @Inject constructor(
    @ApplicationContext private val context: Context,
) : ApkManifestReader {

    override fun read(apk: File): ApkManifest? {
        val info = archiveInfo(apk) ?: return null
        val app: ApplicationInfo? = info.applicationInfo
        val components = buildList {
            info.activities?.forEach { add(component(ApkComponent.Type.ACTIVITY, it, it.permission)) }
            info.services?.forEach { add(component(ApkComponent.Type.SERVICE, it, it.permission)) }
            info.receivers?.forEach { add(component(ApkComponent.Type.RECEIVER, it, it.permission)) }
            info.providers?.forEach { add(component(ApkComponent.Type.PROVIDER, it, providerPermission(it))) }
        }
        val (signers, history) = certificates(info)
        return ApkManifest(
            packageName = info.packageName ?: "",
            versionName = info.versionName,
            versionCode = versionCode(info),
            minSdk = app?.minSdkVersion,
            targetSdk = app?.targetSdkVersion,
            permissions = info.requestedPermissions?.filterNotNull()?.sorted().orEmpty(),
            debuggable = app != null && app.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0,
            usesCleartextTraffic = app != null && app.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC != 0,
            allowBackup = app != null && app.flags and ApplicationInfo.FLAG_ALLOW_BACKUP != 0,
            components = components,
            signerCertificates = signers,
            hasPastSigningCertificates = history,
        )
    }

    private fun archiveInfo(apk: File): PackageInfo? {
        val pm = context.packageManager
        var flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES or
            PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS
        flags = flags or if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            legacySignaturesFlag()
        }
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageArchiveInfo(apk.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                legacyArchiveInfo(pm, apk, flags)
            }
        } catch (error: RuntimeException) {
            // O parser do sistema pode lançar exceções em APKs malformados.
            null
        }
    }

    private fun component(type: ApkComponent.Type, info: ComponentInfo, permission: String?) =
        ApkComponent(type, info.name ?: "?", info.exported, permission)

    private fun providerPermission(info: ProviderInfo): String? = info.readPermission ?: info.writePermission

    private fun certificates(info: PackageInfo): Pair<List<ByteArray>, Boolean> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signing = info.signingInfo
            when {
                signing == null -> emptyList<ByteArray>() to false
                signing.hasMultipleSigners() -> signing.apkContentsSigners.orEmpty().map { it.toByteArray() } to false
                else -> {
                    val history = signing.signingCertificateHistory.orEmpty()
                    listOfNotNull(history.lastOrNull()?.toByteArray()) to (history.size > 1)
                }
            }
        } else {
            legacySignatures(info).map { it.toByteArray() } to false
        }

    private fun versionCode(info: PackageInfo): Long =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode else legacyVersionCode(info)

    @Suppress("DEPRECATION")
    private fun legacySignaturesFlag() = PackageManager.GET_SIGNATURES

    @Suppress("DEPRECATION")
    private fun legacyArchiveInfo(pm: PackageManager, apk: File, flags: Int) = pm.getPackageArchiveInfo(apk.absolutePath, flags)

    @Suppress("DEPRECATION")
    private fun legacySignatures(info: PackageInfo) = info.signatures.orEmpty().filterNotNull()

    @Suppress("DEPRECATION")
    private fun legacyVersionCode(info: PackageInfo) = info.versionCode.toLong()
}
