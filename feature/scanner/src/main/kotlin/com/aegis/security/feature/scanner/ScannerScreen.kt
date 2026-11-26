package com.aegis.security.feature.scanner

import androidx.compose.foundation.background
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
import androidx.compose.material.icons.outlined.PhoneAndroid
import androidx.compose.material.icons.outlined.PrivacyTip
import androidx.compose.material.icons.outlined.UploadFile
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.aegis.security.core.designsystem.component.AegisCard
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
    viewModel: ScannerViewModel = hiltViewModel(),
) {
    ScannerScreen(uiState = viewModel.uiState, onNavigateBack = onNavigateBack)
}

@Composable
internal fun ScannerScreen(
    uiState: ScannerUiState,
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val status = uiState.status
    Scaffold(
        modifier = modifier,
        containerColor = Color.Transparent,
        topBar = {
            AegisTopBar(title = stringResource(R.string.feature_scanner_title), onNavigateBack = onNavigateBack)
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            SelectionArea(operational = status.isOperational)

            SectionHeader(title = stringResource(R.string.feature_scanner_formats_title))
            AegisCard(modifier = Modifier.fillMaxWidth()) {
                SupportedFormats(supported = status.supportedFormats)
                if (status.supportedFormats.isEmpty()) {
                    Spacer(Modifier.height(12.dp))
                    Text(
                        text = stringResource(R.string.feature_scanner_formats_none),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            SectionHeader(title = stringResource(R.string.feature_scanner_modes_title))
            AnalysisModeCard(
                icon = Icons.Outlined.PhoneAndroid,
                title = stringResource(R.string.feature_scanner_local_title),
                description = stringResource(R.string.feature_scanner_local_description),
                available = status.isOperational,
            )
            AnalysisModeCard(
                icon = Icons.Outlined.Cloud,
                title = stringResource(R.string.feature_scanner_online_title),
                description = stringResource(R.string.feature_scanner_online_description),
                // A integração VirusTotal (via backend) só existe a partir da Etapa 7.
                available = false,
            )

            PrivacyNotice()
            Spacer(Modifier.height(8.dp))
        }
    }
}

@Composable
private fun SelectionArea(operational: Boolean) {
    val outline = MaterialTheme.colorScheme.outline
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .background(MaterialTheme.colorScheme.surfaceContainerLow)
            .drawBehind {
                drawRoundRect(
                    color = outline,
                    style = Stroke(
                        width = 1.5.dp.toPx(),
                        pathEffect = PathEffect.dashPathEffect(floatArrayOf(10.dp.toPx(), 8.dp.toPx())),
                    ),
                    cornerRadius = CornerRadius(16.dp.toPx()),
                )
            }
            .padding(horizontal = 24.dp, vertical = 32.dp)
            .semantics(mergeDescendants = true) {},
        contentAlignment = Alignment.Center,
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Icon(
                imageVector = Icons.Outlined.UploadFile,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(40.dp),
            )
            Text(
                text = stringResource(R.string.feature_scanner_select_file),
                style = MaterialTheme.typography.titleMedium,
            )
            if (!operational) {
                Text(
                    text = stringResource(R.string.feature_scanner_select_unavailable),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
                StatusBadge(
                    label = stringResource(R.string.feature_scanner_unavailable),
                    tone = StatusTone.SUSPICIOUS,
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun SupportedFormats(supported: Set<FileFormat>) {
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        FileFormat.prioritized.forEach { format ->
            FormatChip(format = format, available = format in supported)
        }
    }
}

@Composable
private fun FormatChip(format: FileFormat, available: Boolean) {
    val tone = if (available) StatusTone.SAFE else StatusTone.INCONCLUSIVE
    val colors = AegisTheme.statusColors.forTone(tone)
    val stateLabel = stringResource(
        if (available) R.string.feature_scanner_format_available else R.string.feature_scanner_format_unavailable,
    )
    val formatLabel = format.label()
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
        Text(text = formatLabel, style = MaterialTheme.typography.labelLarge)
        Text(text = stateLabel, style = MaterialTheme.typography.labelSmall, color = colors.content)
    }
}

@Composable
private fun AnalysisModeCard(
    icon: ImageVector,
    title: String,
    description: String,
    available: Boolean,
) {
    AegisCard(modifier = Modifier.fillMaxWidth().semantics(mergeDescendants = true) {}) {
        Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(text = title, style = MaterialTheme.typography.titleSmall)
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                StatusBadge(
                    label = stringResource(
                        if (available) R.string.feature_scanner_available else R.string.feature_scanner_unavailable,
                    ),
                    tone = if (available) StatusTone.SAFE else StatusTone.SUSPICIOUS,
                )
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
            Text(
                text = stringResource(R.string.feature_scanner_privacy_title),
                style = MaterialTheme.typography.titleSmall,
                color = info.content,
            )
            Text(
                text = stringResource(R.string.feature_scanner_privacy_body),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}
