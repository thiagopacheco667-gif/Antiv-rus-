package com.aegis.security.core.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.HelpOutline
import androidx.compose.material.icons.outlined.Android
import androidx.compose.material.icons.outlined.Code
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.FolderZip
import androidx.compose.material.icons.outlined.GppBad
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material.icons.outlined.PictureAsPdf
import androidx.compose.material.icons.outlined.ReportProblem
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import com.aegis.security.core.designsystem.theme.StatusTone
import com.aegis.security.domain.analysis.Severity
import com.aegis.security.domain.model.AnalysisOrigin
import com.aegis.security.domain.model.FileFormat
import com.aegis.security.domain.model.Verdict

// Mapeamento único entre modelos de domínio e apresentação, compartilhado pelas features.

@Composable
fun Verdict.label(): String = stringResource(
    when (this) {
        Verdict.SAFE_BY_CHECKS -> R.string.core_ui_verdict_safe_by_checks
        Verdict.SUSPICIOUS -> R.string.core_ui_verdict_suspicious
        Verdict.THREAT_DETECTED -> R.string.core_ui_verdict_threat_detected
        Verdict.INCONCLUSIVE -> R.string.core_ui_verdict_inconclusive
        Verdict.ANALYSIS_ERROR -> R.string.core_ui_verdict_analysis_error
    },
)

val Verdict.tone: StatusTone
    get() = when (this) {
        Verdict.SAFE_BY_CHECKS -> StatusTone.SAFE
        Verdict.SUSPICIOUS -> StatusTone.SUSPICIOUS
        Verdict.THREAT_DETECTED -> StatusTone.THREAT
        Verdict.INCONCLUSIVE -> StatusTone.INCONCLUSIVE
        Verdict.ANALYSIS_ERROR -> StatusTone.ERROR
    }

val Verdict.icon: ImageVector
    get() = when (this) {
        Verdict.SAFE_BY_CHECKS -> Icons.Outlined.VerifiedUser
        Verdict.SUSPICIOUS -> Icons.Outlined.ReportProblem
        Verdict.THREAT_DETECTED -> Icons.Outlined.GppBad
        Verdict.INCONCLUSIVE -> Icons.AutoMirrored.Outlined.HelpOutline
        Verdict.ANALYSIS_ERROR -> Icons.Outlined.ErrorOutline
    }

@Composable
fun FileFormat.label(): String = stringResource(
    when (this) {
        FileFormat.APK -> R.string.core_ui_format_apk
        FileFormat.ZIP -> R.string.core_ui_format_zip
        FileFormat.JAR -> R.string.core_ui_format_jar
        FileFormat.DEX -> R.string.core_ui_format_dex
        FileFormat.PE_EXECUTABLE -> R.string.core_ui_format_exe
        FileFormat.PE_LIBRARY -> R.string.core_ui_format_dll
        FileFormat.ELF -> R.string.core_ui_format_elf
        FileFormat.PDF -> R.string.core_ui_format_pdf
        FileFormat.UNKNOWN -> R.string.core_ui_format_unknown
    },
)

val FileFormat.icon: ImageVector
    get() = when (this) {
        FileFormat.APK -> Icons.Outlined.Android
        FileFormat.ZIP, FileFormat.JAR -> Icons.Outlined.FolderZip
        FileFormat.DEX -> Icons.Outlined.Code
        FileFormat.PE_EXECUTABLE, FileFormat.PE_LIBRARY -> Icons.Outlined.Memory
        FileFormat.ELF -> Icons.Outlined.Terminal
        FileFormat.PDF -> Icons.Outlined.PictureAsPdf
        FileFormat.UNKNOWN -> Icons.Outlined.Description
    }

@Composable
fun AnalysisOrigin.label(): String = stringResource(
    when (this) {
        AnalysisOrigin.LOCAL -> R.string.core_ui_origin_local
        AnalysisOrigin.LOCAL_AND_VIRUSTOTAL -> R.string.core_ui_origin_local_and_virustotal
        AnalysisOrigin.UNKNOWN -> R.string.core_ui_origin_unknown
    },
)

@Composable
fun Severity.label(): String = stringResource(
    when (this) {
        Severity.INFO -> R.string.core_ui_severity_info
        Severity.LOW -> R.string.core_ui_severity_low
        Severity.MEDIUM -> R.string.core_ui_severity_medium
        Severity.HIGH -> R.string.core_ui_severity_high
        Severity.CRITICAL -> R.string.core_ui_severity_critical
    },
)

val Severity.tone: StatusTone
    get() = when (this) {
        Severity.INFO, Severity.LOW -> StatusTone.INFO
        Severity.MEDIUM -> StatusTone.SUSPICIOUS
        Severity.HIGH, Severity.CRITICAL -> StatusTone.THREAT
    }
