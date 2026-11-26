package com.aegis.security.feature.scanner

import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.RemoveCircleOutline
import androidx.compose.material.icons.outlined.RadioButtonUnchecked
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aegis.security.core.designsystem.component.AegisCard
import com.aegis.security.core.designsystem.component.AegisLogo
import com.aegis.security.core.designsystem.component.AegisTopBar
import com.aegis.security.core.designsystem.component.EmptyState
import com.aegis.security.core.designsystem.theme.AegisTheme
import com.aegis.security.domain.analysis.ScanStep
import androidx.compose.material.icons.outlined.ErrorOutline

@Composable
internal fun AnalyzingRoute(
    onCompleted: (recordId: Long, sourceUri: String) -> Unit,
    onCancelled: () -> Unit,
    viewModel: AnalyzingViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(state.completedRecordId) {
        state.completedRecordId?.let { onCompleted(it, viewModel.sourceUri) }
    }
    LaunchedEffect(state.cancelled) {
        if (state.cancelled) onCancelled()
    }
    BackHandler(enabled = state.completedRecordId == null) { viewModel.cancel() }
    AnalyzingScreen(state = state, onCancel = viewModel::cancel)
}

@Composable
internal fun AnalyzingScreen(state: AnalyzingUiState, onCancel: () -> Unit) {
    val progress by animateFloatAsState(targetValue = state.progress, animationSpec = tween(300), label = "progress")
    Scaffold(
        containerColor = Color.Transparent,
        topBar = { AegisTopBar(title = stringResource(R.string.feature_scanner_analyzing_title)) },
    ) { innerPadding ->
        if (state.unexpectedError != null) {
            Box(Modifier.fillMaxSize().padding(innerPadding), contentAlignment = Alignment.Center) {
                EmptyState(
                    icon = Icons.Outlined.ErrorOutline,
                    title = stringResource(R.string.feature_scanner_analyzing_error_title),
                    message = stringResource(R.string.feature_scanner_analyzing_error_message, state.unexpectedError),
                    action = { OutlinedButton(onClick = onCancel) { Text(stringResource(R.string.feature_scanner_back)) } },
                )
            }
            return@Scaffold
        }
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            ProgressRing(progress)
            AegisCard(modifier = Modifier.fillMaxWidth()) {
                ScanStep.entries.forEachIndexed { index, step ->
                    StepRow(index + 1, step, state.steps[step] ?: StepState.PENDING, if (state.steps[step] == StepState.RUNNING) state.currentFraction else null)
                }
            }
            Text(
                text = stringResource(R.string.feature_scanner_analyzing_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(
                onClick = onCancel,
                enabled = state.completedRecordId == null,
                modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp),
            ) { Text(stringResource(R.string.feature_scanner_cancel)) }
        }
    }
}

@Composable
private fun ProgressRing(progress: Float) {
    val track = MaterialTheme.colorScheme.surfaceContainerHighest
    val brushStart = MaterialTheme.colorScheme.primary
    val brushEnd = MaterialTheme.colorScheme.secondary
    val percent = (progress * 100).toInt()
    val description = stringResource(R.string.feature_scanner_progress_description, percent)
    Box(
        modifier = Modifier
            .size(180.dp)
            .semantics {
                progressBarRangeInfo = ProgressBarRangeInfo(progress, 0f..1f)
                liveRegion = LiveRegionMode.Polite
                contentDescription = description
            },
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.fillMaxSize()) {
            val stroke = 10.dp.toPx()
            val arcSize = Size(size.width - stroke, size.height - stroke)
            val topLeft = Offset(stroke / 2, stroke / 2)
            drawArc(track, 0f, 360f, false, topLeft, arcSize, style = Stroke(stroke))
            drawArc(
                brush = androidx.compose.ui.graphics.Brush.sweepGradient(listOf(brushStart, brushEnd, brushStart)),
                startAngle = -90f,
                sweepAngle = 360f * progress,
                useCenter = false,
                topLeft = topLeft,
                size = arcSize,
                style = Stroke(stroke, cap = StrokeCap.Round),
            )
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            AegisLogo(size = 44.dp, contentDescription = null)
            Spacer(Modifier.height(6.dp))
            Text(text = "$percent%", style = MaterialTheme.typography.headlineSmall)
        }
    }
}

@Composable
private fun StepRow(number: Int, step: ScanStep, state: StepState, fraction: Float?) {
    val colors = AegisTheme.statusColors
    Row(
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).semantics(mergeDescendants = true) {},
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Box(Modifier.size(24.dp), contentAlignment = Alignment.Center) {
            when (state) {
                StepState.RUNNING -> CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                StepState.DONE -> Icon(Icons.Outlined.CheckCircle, contentDescription = null, tint = colors.safe.content)
                StepState.SKIPPED -> Icon(Icons.Outlined.RemoveCircleOutline, contentDescription = null, tint = colors.inconclusive.content)
                StepState.PENDING -> Icon(Icons.Outlined.RadioButtonUnchecked, contentDescription = null, tint = MaterialTheme.colorScheme.outline)
            }
        }
        Column(Modifier.weight(1f)) {
            Text(
                text = "$number. ${stringResource(step.labelRes())}",
                style = MaterialTheme.typography.bodyLarge,
                color = if (state == StepState.PENDING) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface,
            )
            val stateText = when (state) {
                StepState.PENDING -> R.string.feature_scanner_step_pending
                StepState.RUNNING -> R.string.feature_scanner_step_running
                StepState.DONE -> R.string.feature_scanner_step_done
                StepState.SKIPPED -> R.string.feature_scanner_step_skipped
            }
            Text(
                text = stringResource(stateText) + (fraction?.let { " · ${(it * 100).toInt()}%" } ?: ""),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

private fun ScanStep.labelRes(): Int = when (this) {
    ScanStep.IDENTIFYING -> R.string.feature_scanner_step_identifying
    ScanStep.HASHING -> R.string.feature_scanner_step_hashing
    ScanStep.INSPECTING -> R.string.feature_scanner_step_inspecting
    ScanStep.CHECKING_INDICATORS -> R.string.feature_scanner_step_indicators
    ScanStep.ONLINE_REPUTATION -> R.string.feature_scanner_step_online
    ScanStep.FINALIZING -> R.string.feature_scanner_step_finalizing
}
