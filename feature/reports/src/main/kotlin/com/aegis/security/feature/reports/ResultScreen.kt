package com.aegis.security.feature.reports

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Public
import androidx.compose.material.icons.outlined.Cloud
import androidx.compose.material.icons.outlined.CloudUpload
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Build
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aegis.security.core.designsystem.component.AegisCard
import com.aegis.security.core.designsystem.component.AegisPrimaryButton
import com.aegis.security.core.designsystem.component.AegisTopBar
import com.aegis.security.core.designsystem.component.EmptyState
import com.aegis.security.core.designsystem.component.SectionHeader
import com.aegis.security.core.designsystem.component.StatusBadge
import com.aegis.security.core.designsystem.component.StatusOrb
import com.aegis.security.core.designsystem.theme.AegisMonospace
import com.aegis.security.core.designsystem.theme.AegisTheme
import com.aegis.security.core.designsystem.theme.StatusTone
import com.aegis.security.core.ui.AegisFormatters
import com.aegis.security.core.ui.icon
import com.aegis.security.core.ui.label
import com.aegis.security.core.ui.tone
import com.aegis.security.domain.analysis.Finding
import com.aegis.security.domain.model.AnalysisReport
import com.aegis.security.domain.model.EngineStatus
import com.aegis.security.domain.model.FileFormat
import com.aegis.security.domain.model.OnlineReputation
import com.aegis.security.domain.model.ScanRecord

@Composable
internal fun ResultRoute(
    onNavigateBack: () -> Unit,
    onOpenDetails: (Long) -> Unit,
    viewModel: ResultViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val action by viewModel.action.collectAsStateWithLifecycle()
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        viewModel.onFileReselected(uri?.toString())
    }
    if (action == OnlineAction.NeedsFileSelection) {
        ReselectDialog(onConfirm = { picker.launch(arrayOf("*/*")) }, onDismiss = viewModel::dismiss)
    }
    ResultScreen(
        uiState = uiState,
        action = action,
        onNavigateBack = onNavigateBack,
        onOpenDetails = { onOpenDetails(viewModel.recordId) },
        onRequestLookup = viewModel::requestLookup,
        onConfirmLookup = viewModel::confirmLookup,
        onRequestUpload = viewModel::requestUpload,
        onConfirmUpload = viewModel::confirmUpload,
        onCancelOnline = viewModel::cancelOnline,
        onDismiss = viewModel::dismiss,
    )
}

@Composable
internal fun ResultScreen(
    uiState: ResultUiState,
    action: OnlineAction,
    onNavigateBack: () -> Unit,
    onOpenDetails: () -> Unit,
    onRequestLookup: () -> Unit,
    onConfirmLookup: () -> Unit,
    onRequestUpload: () -> Unit,
    onConfirmUpload: () -> Unit,
    onCancelOnline: () -> Unit,
    onDismiss: () -> Unit,
) {
    Scaffold(
        containerColor = Color.Transparent,
        topBar = { AegisTopBar(title = stringResource(R.string.feature_reports_title), onNavigateBack = onNavigateBack) },
    ) { innerPadding ->
        Box(Modifier.fillMaxSize().padding(innerPadding)) {
            when (uiState) {
                ResultUiState.Loading -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                ResultUiState.NotFound -> EmptyState(
                    icon = Icons.Outlined.ErrorOutline,
                    title = stringResource(R.string.feature_reports_not_found_title),
                    message = stringResource(R.string.feature_reports_not_found_message),
                    modifier = Modifier.align(Alignment.Center),
                )
                is ResultUiState.Ready -> {
                    val report = uiState.record.report
                    if (report == null) {
                        EmptyState(
                            icon = Icons.Outlined.ErrorOutline,
                            title = stringResource(R.string.feature_reports_legacy_title),
                            message = stringResource(R.string.feature_reports_legacy_message),
                            modifier = Modifier.align(Alignment.Center),
                        )
                    } else {
                        ResultContent(uiState.record, report, uiState.onlineConfigured, action, onOpenDetails, onRequestLookup, onRequestUpload, onCancelOnline)
                    }
                }
            }
        }
    }
    val ready = uiState as? ResultUiState.Ready
    when (action) {
        OnlineAction.ConfirmLookup -> LookupConsentDialog(onConfirmLookup, onDismiss)
        OnlineAction.ConfirmUpload -> UploadConsentDialog(
            isDocument = ready?.record?.format == FileFormat.PDF || ready?.record?.format == FileFormat.UNKNOWN || ready?.record?.format == FileFormat.ZIP,
            onConfirm = onConfirmUpload,
            onDismiss = onDismiss,
        )
        else -> Unit
    }
}

@Composable
private fun ResultContent(
    record: ScanRecord,
    report: AnalysisReport,
    onlineConfigured: Boolean,
    action: OnlineAction,
    onOpenDetails: () -> Unit,
    onRequestLookup: () -> Unit,
    onRequestUpload: () -> Unit,
    onCancelOnline: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item(key = "verdict") { VerdictCard(record, report) }
        item(key = "file_header") { SectionHeader(stringResource(R.string.feature_reports_file_section)) }
        item(key = "file") { FileCard(report) }
        item(key = "findings_header") { SectionHeader(stringResource(R.string.feature_reports_findings_section, report.findings.size)) }
        item(key = "findings") {
            AegisCard(Modifier.fillMaxWidth()) {
                if (report.findings.isEmpty()) {
                    Text(stringResource(R.string.feature_reports_no_findings), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    report.findings.forEachIndexed { index, finding ->
                        if (index > 0) HorizontalDivider(Modifier.padding(vertical = 12.dp), color = MaterialTheme.colorScheme.outlineVariant)
                        FindingItem(finding)
                    }
                }
            }
        }
        item(key = "local_header") { SectionHeader(stringResource(R.string.feature_reports_local_section)) }
        item(key = "local") { LocalCard(report) }
        item(key = "online_header") { SectionHeader(stringResource(R.string.feature_reports_online_section)) }
        item(key = "online") { OnlineCard(report, onlineConfigured, action, onRequestLookup, onRequestUpload, onCancelOnline) }
        item(key = "details") {
            OutlinedButton(onClick = onOpenDetails, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) {
                Icon(Icons.Outlined.Build, contentDescription = null)
                Spacer(Modifier.size(8.dp))
                Text(stringResource(R.string.feature_reports_open_details))
            }
        }
        item(key = "bottom") { Spacer(Modifier.height(8.dp)) }
    }
}

@Composable
private fun VerdictCard(record: ScanRecord, report: AnalysisReport) {
    val tone = report.verdict.tone
    AegisCard(Modifier.fillMaxWidth().semantics(mergeDescendants = true) {}) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            StatusOrb(tone = tone, icon = report.verdict.icon, size = 64.dp)
            Spacer(Modifier.size(16.dp))
            Column(Modifier.weight(1f)) {
                Text(report.verdict.label(), style = MaterialTheme.typography.titleLarge, color = AegisTheme.statusColors.forTone(tone).content)
                Text(record.fileName, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2)
            }
        }
        Spacer(Modifier.height(14.dp))
        Text(stringResource(R.string.feature_reports_explanation), style = MaterialTheme.typography.labelLarge)
        Spacer(Modifier.height(6.dp))
        report.explanation.forEach { reason ->
            Row(Modifier.padding(vertical = 2.dp)) {
                Text("•", color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(end = 8.dp))
                Text(reason, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun FileCard(report: AnalysisReport) {
    val clipboard = LocalClipboardManager.current
    AegisCard(Modifier.fillMaxWidth()) {
        InfoRow(stringResource(R.string.feature_reports_name), report.metadata.fileName)
        InfoRow(stringResource(R.string.feature_reports_format), report.format.label() + (report.metadata.declaredExtension?.let { " (.$it)" } ?: ""))
        InfoRow(stringResource(R.string.feature_reports_size), report.metadata.sizeBytes?.let { AegisFormatters.fileSize(it) + " ($it bytes)" } ?: "—")
        InfoRow(stringResource(R.string.feature_reports_date), AegisFormatters.dateTime(report.analyzedAtEpochMillis))
        InfoRow(stringResource(R.string.feature_reports_duration), "${report.durationMillis} ms")
        val sha256 = report.hashes?.sha256
        Spacer(Modifier.height(10.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("SHA-256", style = MaterialTheme.typography.labelLarge, modifier = Modifier.weight(1f))
            if (sha256 != null) {
                IconButton(onClick = { clipboard.setText(AnnotatedString(sha256)) }) {
                    Icon(Icons.Outlined.ContentCopy, contentDescription = stringResource(R.string.feature_reports_copy_hash))
                }
            }
        }
        SelectionContainer {
            Text(sha256 ?: stringResource(R.string.feature_reports_no_hash), style = AegisMonospace, color = MaterialTheme.colorScheme.onSurface)
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp).semantics(mergeDescendants = true) {}) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(0.4f))
        Text(value, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(0.6f))
    }
}

@Composable
private fun FindingItem(finding: Finding) {
    var expanded by rememberSaveable(finding.ruleId) { mutableStateOf(false) }
    Column(
        Modifier
            .fillMaxWidth()
            .toggleable(value = expanded, role = Role.Button, onValueChange = { expanded = it })
            .semantics(mergeDescendants = true) {},
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StatusBadge(label = finding.severity.label(), tone = finding.severity.tone)
            Text(finding.ruleId, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(finding.description, style = MaterialTheme.typography.titleSmall)
        Text(stringResource(R.string.feature_reports_evidence, finding.evidence), style = MaterialTheme.typography.bodySmall)
        if (expanded) {
            Text(finding.rationale, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            Text(stringResource(R.string.feature_reports_show_rationale), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        }
    }
}

@Composable
private fun LocalCard(report: AnalysisReport) {
    AegisCard(Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(stringResource(R.string.feature_reports_local_verdict), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            StatusBadge(label = report.localVerdict.label(), tone = report.localVerdict.tone, icon = report.localVerdict.icon)
        }
        Spacer(Modifier.height(10.dp))
        val applicable = report.engines.filter { it.status != EngineStatus.NOT_APPLICABLE }
        applicable.forEach { engine ->
            val (text, tone) = when (engine.status) {
                EngineStatus.COMPLETED -> stringResource(R.string.feature_reports_engine_completed) to StatusTone.SAFE
                EngineStatus.FAILED -> stringResource(R.string.feature_reports_engine_failed, engine.failureReason ?: "?") to StatusTone.ERROR
                EngineStatus.NOT_APPLICABLE -> "" to StatusTone.INCONCLUSIVE
            }
            Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(engine.engineName, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                Text(text, style = MaterialTheme.typography.labelMedium, color = AegisTheme.statusColors.forTone(tone).content)
            }
        }
        report.failure?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = AegisTheme.statusColors.error.content)
        }
        if (applicable.isEmpty() && report.failure == null) {
            Text(stringResource(R.string.feature_reports_no_engines), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun OnlineCard(
    report: AnalysisReport,
    configured: Boolean,
    action: OnlineAction,
    onRequestLookup: () -> Unit,
    onRequestUpload: () -> Unit,
    onCancelOnline: () -> Unit,
) {
    val uriHandler = LocalUriHandler.current
    AegisCard(Modifier.fillMaxWidth()) {
        when (val online = report.online) {
            OnlineReputation.NotRequested -> Text(stringResource(R.string.feature_reports_online_not_requested), style = MaterialTheme.typography.bodyMedium)
            is OnlineReputation.NotFound -> Text(stringResource(R.string.feature_reports_online_not_found), style = MaterialTheme.typography.bodyMedium)
            is OnlineReputation.Failed -> Text(
                stringResource(R.string.feature_reports_online_failed, online.message),
                style = MaterialTheme.typography.bodyMedium,
                color = AegisTheme.statusColors.error.content,
            )
            is OnlineReputation.Found -> {
                val stats = online.stats
                StatRow(stringResource(R.string.feature_reports_vt_malicious), stats.malicious, StatusTone.THREAT)
                StatRow(stringResource(R.string.feature_reports_vt_suspicious), stats.suspicious, StatusTone.SUSPICIOUS)
                StatRow(stringResource(R.string.feature_reports_vt_clean), stats.notDetected, StatusTone.SAFE)
                StatRow(stringResource(R.string.feature_reports_vt_inconclusive), stats.inconclusive, StatusTone.INCONCLUSIVE)
                online.analysisDateEpochSeconds?.let {
                    Text(stringResource(R.string.feature_reports_vt_date, AegisFormatters.dateTime(it * 1000)), style = MaterialTheme.typography.bodySmall)
                }
                val positives = online.detections.filter { it.category == "malicious" || it.category == "suspicious" }
                if (positives.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text(stringResource(R.string.feature_reports_vt_names), style = MaterialTheme.typography.labelLarge)
                    positives.take(25).forEach { detection ->
                        Text("${detection.engine}: ${detection.result ?: detection.category}", style = AegisMonospace)
                    }
                }
                Text(stringResource(R.string.feature_reports_vt_disclaimer), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                online.permalink?.let { link ->
                    TextButton(onClick = { uriHandler.openUri(link) }) {
                        Icon(Icons.Outlined.Public, contentDescription = null)
                        Spacer(Modifier.size(6.dp))
                        Text(stringResource(R.string.feature_reports_vt_open))
                    }
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        when (action) {
            OnlineAction.LookingUp -> ProgressLine(stringResource(R.string.feature_reports_looking_up), null, onCancelOnline)
            is OnlineAction.Uploading -> ProgressLine(stringResource(R.string.feature_reports_uploading, (action.progress * 100).toInt()), action.progress, onCancelOnline)
            is OnlineAction.WaitingAnalysis -> ProgressLine(stringResource(R.string.feature_reports_waiting, action.status), null, onCancelOnline)
            else -> {
                if (action is OnlineAction.Error) {
                    Text(action.message, style = MaterialTheme.typography.bodySmall, color = AegisTheme.statusColors.error.content)
                    Spacer(Modifier.height(8.dp))
                }
                if (!configured) {
                    Text(stringResource(R.string.feature_reports_online_not_configured), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else if (report.hashes != null) {
                    AegisPrimaryButton(
                        text = stringResource(R.string.feature_reports_lookup_button),
                        onClick = onRequestLookup,
                        icon = Icons.Outlined.Cloud,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    if (report.online is OnlineReputation.NotFound || report.online is OnlineReputation.Found) {
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(onClick = onRequestUpload, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) {
                            Icon(Icons.Outlined.CloudUpload, contentDescription = null)
                            Spacer(Modifier.size(8.dp))
                            Text(stringResource(R.string.feature_reports_upload_button))
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun StatRow(label: String, value: Int, tone: StatusTone) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp).semantics(mergeDescendants = true) {}, verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(10.dp).background(AegisTheme.statusColors.forTone(tone).content, MaterialTheme.shapes.extraSmall))
        Spacer(Modifier.size(10.dp))
        Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Text(value.toString(), style = MaterialTheme.typography.titleMedium)
    }
}

@Composable
private fun ProgressLine(text: String, progress: Float?, onCancel: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(text, style = MaterialTheme.typography.bodyMedium)
        if (progress != null) LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
        else LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        TextButton(onClick = onCancel) { Text(stringResource(R.string.feature_reports_cancel)) }
    }
}

@Composable
private fun LookupConsentDialog(onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Outlined.Cloud, contentDescription = null) },
        title = { Text(stringResource(R.string.feature_reports_lookup_dialog_title)) },
        text = { Text(stringResource(R.string.feature_reports_lookup_dialog_message)) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(stringResource(R.string.feature_reports_lookup_dialog_confirm)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.feature_reports_cancel)) } },
    )
}

@Composable
private fun UploadConsentDialog(isDocument: Boolean, onConfirm: () -> Unit, onDismiss: () -> Unit) {
    var acknowledged by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Outlined.CloudUpload, contentDescription = null, tint = AegisTheme.statusColors.suspicious.content) },
        title = { Text(stringResource(R.string.feature_reports_upload_dialog_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.feature_reports_upload_dialog_message))
                if (isDocument) {
                    Text(stringResource(R.string.feature_reports_upload_dialog_personal), color = AegisTheme.statusColors.suspicious.content)
                }
                Row(
                    Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .toggleable(value = acknowledged, role = Role.Checkbox, onValueChange = { acknowledged = it }),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(checked = acknowledged, onCheckedChange = null)
                    Spacer(Modifier.size(8.dp))
                    Text(stringResource(R.string.feature_reports_upload_dialog_ack), style = MaterialTheme.typography.bodyMedium)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm, enabled = acknowledged) { Text(stringResource(R.string.feature_reports_upload_dialog_confirm)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.feature_reports_cancel)) } },
    )
}

@Composable
private fun ReselectDialog(onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.feature_reports_reselect_title)) },
        text = { Text(stringResource(R.string.feature_reports_reselect_message)) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(stringResource(R.string.feature_reports_reselect_confirm)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.feature_reports_cancel)) } },
    )
}
