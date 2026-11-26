package com.aegis.security.feature.scanner

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Cloud
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.PhoneAndroid
import androidx.compose.material.icons.outlined.PrivacyTip
import androidx.compose.material.icons.outlined.UploadFile
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aegis.security.core.designsystem.component.AegisCard
import com.aegis.security.core.designsystem.component.AegisPrimaryButton
import com.aegis.security.core.designsystem.component.AegisTopBar
import com.aegis.security.core.designsystem.component.SectionHeader
import com.aegis.security.core.designsystem.component.StatusBadge
import com.aegis.security.core.designsystem.theme.AegisTheme
import com.aegis.security.core.designsystem.theme.StatusTone
import com.aegis.security.core.ui.icon
import com.aegis.security.core.ui.label
import com.aegis.security.domain.model.FileFormat

@Composable
internal fun ScannerRoute(
    onNavigateBack: () -> Unit,
    onFileSelected: (String) -> Unit,
    viewModel: ScannerViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    // Storage Access Framework: o usuário escolhe um arquivo; nenhuma permissão de armazenamento é pedida.
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) onFileSelected(uri.toString())
    }
    ScannerScreen(
        uiState = uiState,
        onNavigateBack = onNavigateBack,
        onSelectFile = { picker.launch(arrayOf("*/*")) },
    )
}

@Composable
internal fun ScannerScreen(
    uiState: ScannerUiState,
    onNavigateBack: () -> Unit,
    onSelectFile: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val status = uiState.status
    Scaffold(
        modifier = modifier,
        containerColor = Color.Transparent,
        topBar = { AegisTopBar(title = stringResource(R.string.feature_scanner_title), onNavigateBack = onNavigateBack) },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            SelectionArea(enabled = status.isOperational, maxFileMb = uiState.limits.maxFileSizeMb, onSelectFile = onSelectFile)
            AegisPrimaryButton(
                text = stringResource(R.string.feature_scanner_select_file_button),
                onClick = onSelectFile,
                enabled = status.isOperational,
                icon = Icons.Outlined.FolderOpen,
                modifier = Modifier.fillMaxWidth(),
            )

            SectionHeader(title = stringResource(R.string.feature_scanner_formats_title))
            AegisCard(modifier = Modifier.fillMaxWidth()) {
                SupportedFormats(supported = status.supportedFormats)
                Spacer(Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.feature_scanner_formats_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            SectionHeader(title = stringResource(R.string.feature_scanner_modes_title))
            AnalysisModeCard(
                icon = Icons.Outlined.PhoneAndroid,
                title = stringResource(R.string.feature_scanner_local_title),
                description = stringResource(R.string.feature_scanner_local_description),
                badge = stringResource(if (status.isOperational) R.string.feature_scanner_available else R.string.feature_scanner_unavailable),
                tone = if (status.isOperational) StatusTone.SAFE else StatusTone.SUSPICIOUS,
            )
            AnalysisModeCard(
                icon = Icons.Outlined.Cloud,
                title = stringResource(R.string.feature_scanner_online_title),
                description = stringResource(R.string.feature_scanner_online_description),
                badge = stringResource(if (uiState.online.isConfigured) R.string.feature_scanner_configured else R.string.feature_scanner_not_configured),
                tone = if (uiState.online.isConfigured) StatusTone.INFO else StatusTone.INCONCLUSIVE,
            )
            PrivacyNotice()
            Spacer(Modifier.height(8.dp))
        }
    }
}

@Composable
private fun SelectionArea(enabled: Boolean, maxFileMb: Int, onSelectFile: () -> Unit) {
    val outline = MaterialTheme.colorScheme.outline
    val label = stringResource(R.string.feature_scanner_select_file)
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .background(MaterialTheme.colorScheme.surfaceContainerLow)
            .clickable(enabled = enabled, onClickLabel = label, role = Role.Button, onClick = onSelectFile)
            .drawBehind {
                drawRoundRect(
                    color = outline,
                    style = Stroke(width = 1.5.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(10.dp.toPx(), 8.dp.toPx()))),
                    cornerRadius = CornerRadius(16.dp.toPx()),
                )
            }
            .padding(horizontal = 24.dp, vertical = 32.dp)
            .semantics(mergeDescendants = true) {},
        contentAlignment = Alignment.Center,
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Icon(Icons.Outlined.UploadFile, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(40.dp))
            Text(text = label, style = MaterialTheme.typography.titleMedium)
            Text(
                text = stringResource(R.string.feature_scanner_select_hint, maxFileMb),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun SupportedFormats(supported: Set<FileFormat>) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        FileFormat.prioritized.forEach { format -> FormatChip(format, format in supported) }
    }
}

@Composable
private fun FormatChip(format: FileFormat, available: Boolean) {
    val colors = AegisTheme.statusColors.forTone(if (available) StatusTone.SAFE else StatusTone.INCONCLUSIVE)
    val state = stringResource(if (available) R.string.feature_scanner_format_available else R.string.feature_scanner_format_unavailable)
    Row(
        modifier = Modifier
            .clip(MaterialTheme.shapes.small)
            .background(MaterialTheme.colorScheme.surfaceContainerHigh)
            .padding(horizontal = 12.dp, vertical = 8.dp)
            .semantics(mergeDescendants = true) {},
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Icon(format.icon, contentDescription = null, tint = colors.content, modifier = Modifier.size(18.dp))
        Text(text = format.label(), style = MaterialTheme.typography.labelLarge)
        Text(text = state, style = MaterialTheme.typography.labelSmall, color = colors.content)
    }
}

@Composable
private fun AnalysisModeCard(icon: ImageVector, title: String, description: String, badge: String, tone: StatusTone) {
    AegisCard(modifier = Modifier.fillMaxWidth().semantics(mergeDescendants = true) {}) {
        Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(text = title, style = MaterialTheme.typography.titleSmall)
                Text(text = description, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                StatusBadge(label = badge, tone = tone)
            }
        }
    }
}

@Composable
private fun PrivacyNotice() {
    val info = AegisTheme.statusColors.info
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .background(info.container)
            .padding(16.dp)
            .semantics(mergeDescendants = true) {},
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(Icons.Outlined.PrivacyTip, contentDescription = null, tint = info.content)
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(text = stringResource(R.string.feature_scanner_privacy_title), style = MaterialTheme.typography.titleSmall, color = info.content)
            Text(text = stringResource(R.string.feature_scanner_privacy_body), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface)
        }
    }
}
