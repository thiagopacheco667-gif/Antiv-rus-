package com.aegis.security.core.security

import com.aegis.security.core.security.apk.ApkComponent
import com.aegis.security.core.security.apk.ApkEngine
import com.aegis.security.core.security.apk.ApkFacts
import com.aegis.security.core.security.apk.ApkManifest
import com.aegis.security.core.security.apk.ApkManifestReader
import com.aegis.security.core.security.rules.ApkRules
import com.aegis.security.core.security.rules.DefaultRuleEngine
import com.aegis.security.core.security.testing.TestFiles
import com.aegis.security.core.security.testing.TestFiles.ZipSpec
import com.aegis.security.domain.analysis.EngineResult
import com.aegis.security.domain.analysis.Severity
import com.aegis.security.domain.model.FileFormat
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * O manifesto binário é lido pelo PackageManager no aparelho; aqui ele é substituído por um leitor
 * falso para testar a lógica de fatos e regras na JVM.
 */
class ApkEngineTest {
    @get:Rule
    val temp = TemporaryFolder()
    private val rules = DefaultRuleEngine(setOf(ApkRules()))

    private fun manifest(permissions: List<String>, components: List<ApkComponent> = emptyList()) = ApkManifest(
        packageName = "com.exemplo.teste",
        versionName = "1.0",
        versionCode = 1,
        minSdk = 26,
        targetSdk = 34,
        permissions = permissions,
        debuggable = false,
        usesCleartextTraffic = false,
        allowBackup = true,
        components = components,
        signerCertificates = emptyList(),
        hasPastSigningCertificates = false,
    )

    private fun apkFile(vararg extra: ZipSpec): File = temp.newFile("app.apk").apply {
        writeBytes(TestFiles.zip(listOf(ZipSpec("AndroidManifest.xml", ByteArray(8)), ZipSpec("classes.dex", ByteArray(8))) + extra))
    }

    private suspend fun analyze(file: File, manifest: ApkManifest?) =
        ApkEngine(object : ApkManifestReader { override fun read(apk: File) = manifest }).analyze(TestFiles.input(file, FileFormat.APK))

    @Test
    fun sensitivePermissionsAlone_areLowSeverity_notThreat() = runTest {
        val result = analyze(apkFile(), manifest(listOf("android.permission.CAMERA", "android.permission.RECORD_AUDIO"))) as EngineResult.Completed
        val findings = rules.evaluate(result.facts)
        val permissionFinding = findings.single { it.ruleId == "AEGIS-APK-001" }
        assertEquals(Severity.LOW, permissionFinding.severity)
        assertTrue(findings.none { it.confirmsThreat })
    }

    @Test
    fun bankingTrojanCapabilityCombination_isHigh() = runTest {
        val accessibility = ApkComponent(ApkComponent.Type.SERVICE, "com.x.Svc", exported = true, permission = "android.permission.BIND_ACCESSIBILITY_SERVICE")
        val result = analyze(
            apkFile(),
            manifest(listOf("android.permission.SYSTEM_ALERT_WINDOW", "android.permission.READ_SMS"), listOf(accessibility)),
        ) as EngineResult.Completed
        assertTrue(rules.evaluate(result.facts).any { it.ruleId == "AEGIS-APK-002" && it.severity == Severity.HIGH })
    }

    @Test
    fun unsignedApk_andHiddenPayloads_areFlagged() = runTest {
        val result = analyze(
            apkFile(ZipSpec("assets/payload.dex", ByteArray(8)), ZipSpec("lib/arm64-v8a/libjiagu.so", ByteArray(8))),
            manifest(emptyList()),
        ) as EngineResult.Completed
        val facts = result.facts.single() as ApkFacts
        assertEquals(listOf("assets/payload.dex"), facts.embeddedPayloads)
        val ids = rules.evaluate(result.facts).map { it.ruleId }
        assertTrue("AEGIS-APK-005" in ids)
        assertTrue("AEGIS-APK-008" in ids)
        assertTrue("AEGIS-APK-009" in ids)
    }

    @Test
    fun unreadableManifest_isEngineFailure() = runTest {
        assertTrue(analyze(apkFile(), null) is EngineResult.Failed)
    }
}
