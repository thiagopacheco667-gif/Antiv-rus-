package com.aegis.security.feature.dashboard

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.GppBad
import androidx.compose.material.icons.outlined.GppMaybe
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Inbox
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.UploadFile
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aegis.security.core.designsystem.component.AegisCard
import com.aegis.security.core.designsystem.component.AegisPrimaryButton
import com.aegis.security.core.designsystem.component.AegisTopBar
import com.aegis.security.core.designsystem.component.AegisWordmark
import com.aegis.security.core.designsystem.component.EmptyState
import com.aegis.security.core.designsystem.component.SectionHeader
import com.aegis.security.core.designsystem.component.StatusOrb
import com.aegis.security.core.designsystem.theme.AegisTheme
import com.aegis.security.core.designsystem.theme.StatusTone
import com.aegis.security.core.ui.ScanRecordRow
import com.aegis.security.core.ui.label
import com.aegis.security.domain.analysis.ScannerStatus
import com.aegis.security.domain.model.DashboardSummary
import com.aegis.security.domain.model.FileFormat

@Composable
internal fun DashboardRoute(
    onAnalyzeFile: () -> Unit,
    onOpenHistory: () -> Unit,
    onOpenSettings: () -> Unit,
    viewModel: DashboardViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    DashboardScreen(
        uiState = uiState,
        onAnalyzeFile = onAnalyzeFile,
        onOpenHistory = onOpenHistory,
        onOpenSettings = onOpenSettings,
    )
}

@Composable
internal fun DashboardScreen(
    uiState: DashboardUiState,
    onAnalyzeFile: () -> Unit,
    onOpenHistory: () -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier,
        containerColor = Color.Transparent,
        topBar = {
            AegisTopBar(
                title = { AegisWordmark(symbolSize = 34.dp) },
                actions = {
                    IconButton(onClick = onOpenSettings) {
                        Icon(
                            imageVector = Icons.Outlined.Settings,
                            contentDescription = stringResource(R.string.feature_dashboard_open_settings),
                        )
                    }
                },
            )
        },
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
        ) {
            when (uiState) {
                DashboardUiState.Loading -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                DashboardUiState.Error -> EmptyState(
                    icon = Icons.Outlined.ErrorOutline,
                    title = stringResource(R.string.feature_dashboard_error_title),
                    message = stringResource(R.string.feature_dashboard_error_message),
                    modifier = Modifier.align(Alignment.Center),
                )
                is DashboardUiState.Ready -> DashboardContent(
                    scanner = uiState.scanner,
                    summary = uiState.summary,
                    onAnalyzeFile = onAnalyzeFile,
                    onOpenHistory = onOpenHistory,
                    onOpenSettings = onOpenSettings,
                )
            }
        }
    }
}

@Composable
private fun DashboardContent(
    scanner: ScannerStatus,
    summary: DashboardSummary,
    onAnalyzeFile: () -> Unit,
    onOpenHistory: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item(key = "scanner") { ScannerStatusCard(scanner) }

        item(key = "analyze") {
            AegisPrimaryButton(
                text = stringResource(R.string.feature_dashboard_analyze_file),
                onClick = onAnalyzeFile,
                icon = Icons.Outlined.UploadFile,
                modifier = Modifier.fillMaxWidth(),
            )
        }

        item(key = "stats") {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                StatCard(
                    label = stringResource(R.string.feature_dashboard_files_analyzed),
                    value = summary.totalScans.toString(),
                    icon = Icons.Outlined.Description,
                    tone = StatusTone.INFO,
                    modifier = Modifier.weight(1f),
                )
                StatCard(
                    label = stringResource(R.string.feature_dashboard_threats_detected),
                    value = summary.threatsDetected.toString(),
                    icon = Icons.Outlined.GppBad,
                    tone = if (summary.threatsDetected > 0) StatusTone.THREAT else StatusTone.INCONCLUSIVE,
                    modifier = Modifier.weight(1f),
                )
            }
        }

        item(key = "last_header") {
            SectionHeader(title = stringResource(R.string.feature_dashboard_last_analysis))
        }
        item(key = "last") {
            val last = summary.lastScan
            AegisCard(modifier = Modifier.fillMaxWidth()) {
                if (last != null) {
                    ScanRecordRow(record = last)
                } else {
                    EmptyState(
                        icon = Icons.Outlined.Inbox,
                        title = stringResource(R.string.feature_dashboard_empty_title),
                        message = stringResource(R.string.feature_dashboard_empty_message),
                    )
                }
            }
        }

        val older = summary.recentScans.drop(1)
        if (older.isNotEmpty()) {
            item(key = "recent_header") {
                SectionHeader(
                    title = stringResource(R.string.feature_dashboard_recent_activity),
                    actionLabel = stringResource(R.string.feature_dashboard_see_history),
                    onAction = onOpenHistory,
                )
            }
            item(key = "recent") {
                AegisCard(modifier = Modifier.fillMaxWidth(), contentPadding = PaddingValues(horizontal = 20.dp, vertical = 8.dp)) {
                    older.forEachIndexed { index, record ->
                        if (index > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                        ScanRecordRow(record = record, modifier = Modifier.padding(vertical = 12.dp))
                    }
                }
            }
        }

        item(key = "shortcuts_header") {
            SectionHeader(title = stringResource(R.string.feature_dashboard_shortcuts))
        }
        item(key = "shortcuts") {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                ShortcutCard(
                    label = stringResource(R.string.feature_dashboard_shortcut_history),
                    icon = Icons.Outlined.History,
                    onClick = onOpenHistory,
                    modifier = Modifier.weight(1f),
                )
                ShortcutCard(
                    label = stringResource(R.string.feature_dashboard_shortcut_settings),
                    icon = Icons.Outlined.Settings,
                    onClick = onOpenSettings,
                    modifier = Modifier.weight(1f),
                )
            }
        }
        item(key = "bottom_space") { Spacer(Modifier.height(8.dp)) }
    }
}

/** Estado do scanner calculado a partir dos mecanismos realmente registrados. */
@Composable
private fun ScannerStatusCard(status: ScannerStatus) {
    val tone = if (status.isOperational) StatusTone.SAFE else StatusTone.SUSPICIOUS
    AegisCard(modifier = Modifier.fillMaxWidth().semantics(mergeDescendants = true) {}) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            StatusOrb(
                tone = tone,
                icon = if (status.isOperational) Icons.Outlined.Shield else Icons.Outlined.GppMaybe,
                pulsing = status.isOperational,
            )
            Spacer(Modifier.size(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.feature_dashboard_scanner_label),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = stringResource(
                        if (status.isOperational) {
                            R.string.feature_dashboard_scanner_ready
                        } else {
                            R.string.feature_dashboard_scanner_unavailable
                        },
                    ),
                    style = MaterialTheme.typography.titleMedium,
                    color = AegisTheme.statusColors.forTone(tone).content,
                )
            }
        }
        Spacer(Modifier.height(14.dp))
        if (status.isOperational) {
            val formats = FileFormat.prioritized
                .filter { it in status.supportedFormats }
                .map { it.label() }
                .joinToString(", ")
            Text(
                text = stringResource(R.string.feature_dashboard_scanner_engines, status.engines.size),
                style = MaterialTheme.typography.bodyMedium,
            )
            if (formats.isNotEmpty()) {
                Text(
                    text = stringResource(R.string.feature_dashboard_scanner_formats, formats),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            Text(
                text = stringResource(R.string.feature_dashboard_scanner_unavailable_detail),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun StatCard(
    label: String,
    value: String,
    icon: ImageVector,
    tone: StatusTone,
    modifier: Modifier = Modifier,
) {
    AegisCard(modifier = modifier.semantics(mergeDescendants = true) {}) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = AegisTheme.statusColors.forTone(tone).content,
            modifier = Modifier.size(22.dp),
        )
        Spacer(Modifier.height(12.dp))
        Text(text = value, style = MaterialTheme.typography.headlineMedium)
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun ShortcutCard(
    label: String,
    icon: ImageVector,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    AegisCard(
        modifier = modifier,
        onClick = onClick,
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 18.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(imageVector = icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.size(12.dp))
            Text(text = label, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
            Icon(
                imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
