package com.aegis.security.feature.filedetails

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.ExpandLess
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.compose.composable
import androidx.navigation.toRoute
import com.aegis.security.core.designsystem.component.AegisCard
import com.aegis.security.core.designsystem.component.AegisTopBar
import com.aegis.security.core.designsystem.component.EmptyState
import com.aegis.security.core.designsystem.theme.AegisMonospace
import com.aegis.security.core.ui.AegisFormatters
import com.aegis.security.core.ui.label
import com.aegis.security.domain.analysis.DetailEntry
import com.aegis.security.domain.analysis.DetailKind
import com.aegis.security.domain.analysis.DetailSection
import com.aegis.security.domain.model.AnalysisReport
import com.aegis.security.domain.model.OnlineReputation
import com.aegis.security.domain.model.ScanRecord
import com.aegis.security.domain.usecase.ObserveScanRecordUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.serialization.Serializable
import javax.inject.Inject

@Serializable
data class DetailsDestination(val recordId: Long)

fun NavController.navigateToDetails(recordId: Long) = navigate(DetailsDestination(recordId)) { launchSingleTop = true }

fun NavGraphBuilder.detailsScreen(onNavigateBack: () -> Unit) {
    composable<DetailsDestination> { DetailsRoute(onNavigateBack) }
}

sealed interface DetailsUiState {
    data object Loading : DetailsUiState
    data object Missing : DetailsUiState
    data class Ready(val record: ScanRecord, val report: AnalysisReport) : DetailsUiState
}

@HiltViewModel
class DetailsViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    observeRecord: ObserveScanRecordUseCase,
) : ViewModel() {
    private val id = savedStateHandle.toRoute<DetailsDestination>().recordId

    val uiState: StateFlow<DetailsUiState> = observeRecord(id)
        .map { record -> record?.report?.let { DetailsUiState.Ready(record, it) } ?: DetailsUiState.Missing }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), DetailsUiState.Loading)
}

@Composable
internal fun DetailsRoute(onNavigateBack: () -> Unit, viewModel: DetailsViewModel = hiltViewModel()) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    Scaffold(
        containerColor = Color.Transparent,
        topBar = { AegisTopBar(title = stringResource(R.string.feature_filedetails_title), onNavigateBack = onNavigateBack) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val s = state) {
                DetailsUiState.Loading -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                DetailsUiState.Missing -> EmptyState(
                    icon = Icons.Outlined.ErrorOutline,
                    title = stringResource(R.string.feature_filedetails_missing_title),
                    message = stringResource(R.string.feature_filedetails_missing_message),
                    modifier = Modifier.align(Alignment.Center),
                )
                is DetailsUiState.Ready -> DetailsContent(buildSections(s.report))
            }
        }
    }
}

/** Seções na ordem da especificação. Tipos sem dados para o formato aparecem como "não aplicável". */
@Composable
private fun buildSections(report: AnalysisReport): List<Pair<DetailKind, List<DetailSection>>> {
    val engineSections = report.engines.flatMap { it.details }
    val metadata = DetailSection(
        DetailKind.METADATA,
        stringResource(R.string.feature_filedetails_file_metadata),
        listOfNotNull(
            DetailEntry(stringResource(R.string.feature_filedetails_name), report.metadata.fileName),
            DetailEntry(stringResource(R.string.feature_filedetails_real_format), report.format.label()),
            report.metadata.declaredExtension?.let { DetailEntry(stringResource(R.string.feature_filedetails_extension), ".$it") },
            report.metadata.sizeBytes?.let { DetailEntry(stringResource(R.string.feature_filedetails_size), "${AegisFormatters.fileSize(it)} ($it bytes)") },
            report.metadata.mimeType?.let { DetailEntry(stringResource(R.string.feature_filedetails_mime), it) },
            report.metadata.lastModifiedEpochMillis?.let { DetailEntry(stringResource(R.string.feature_filedetails_modified), AegisFormatters.dateTime(it)) },
            report.metadata.provider?.let { DetailEntry(stringResource(R.string.feature_filedetails_provider), it) },
        ),
    )
    val hashes = report.hashes?.let {
        DetailSection(
            DetailKind.HASHES,
            stringResource(R.string.feature_filedetails_hashes),
            listOf(DetailEntry("SHA-256", it.sha256, true), DetailEntry("SHA-1", it.sha1, true), DetailEntry("MD5", it.md5, true)),
        )
    }
    val indicators = DetailSection(
        DetailKind.INDICATORS,
        stringResource(R.string.feature_filedetails_indicators),
        report.findings.map { DetailEntry("${it.ruleId} · ${it.severity.label()}", "${it.description}\n${it.evidence}\n${it.rationale}") },
    )
    val external = when (val online = report.online) {
        is OnlineReputation.Found -> DetailSection(
            DetailKind.EXTERNAL,
            stringResource(R.string.feature_filedetails_external),
            listOf(
                DetailEntry("malicious / suspicious / undetected / harmless", "${online.stats.malicious} / ${online.stats.suspicious} / ${online.stats.undetected} / ${online.stats.harmless}", true),
                DetailEntry("timeout / failure / type-unsupported", "${online.stats.timeout} / ${online.stats.failure} / ${online.stats.typeUnsupported}", true),
            ) + online.detections.map { DetailEntry(it.engine, "${it.category}${it.result?.let { r -> " · $r" } ?: ""}", true) },
        )
        is OnlineReputation.NotFound -> DetailSection(DetailKind.EXTERNAL, stringResource(R.string.feature_filedetails_external), listOf(DetailEntry("VirusTotal", stringResource(R.string.feature_filedetails_vt_unknown))))
        is OnlineReputation.Failed -> DetailSection(DetailKind.EXTERNAL, stringResource(R.string.feature_filedetails_external), listOf(DetailEntry("VirusTotal", online.message)))
        OnlineReputation.NotRequested -> null
    }
    val all = listOfNotNull(metadata, hashes) + engineSections + listOfNotNull(indicators.takeIf { it.entries.isNotEmpty() }, external)
    return DetailKind.entries.map { kind -> kind to all.filter { it.kind == kind } }
}

@Composable
private fun DetailsContent(sections: List<Pair<DetailKind, List<DetailSection>>>) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(sections, key = { it.first.name }) { (kind, content) -> ExpandableSection(kind, content) }
    }
}

@Composable
private fun ExpandableSection(kind: DetailKind, sections: List<DetailSection>) {
    var expanded by rememberSaveable(kind) { mutableStateOf(kind == DetailKind.METADATA) }
    AegisCard(Modifier.fillMaxWidth(), contentPadding = PaddingValues(0.dp)) {
        Row(
            Modifier
                .fillMaxWidth()
                .heightIn(min = 56.dp)
                .toggleable(value = expanded, role = Role.Button, onValueChange = { expanded = it })
                .padding(horizontal = 20.dp)
                .semantics { heading() },
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(stringResource(kind.titleRes()), style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
            if (sections.isEmpty()) {
                Text(stringResource(R.string.feature_filedetails_not_applicable), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.size(8.dp))
            }
            Icon(if (expanded) Icons.Outlined.ExpandLess else Icons.Outlined.ExpandMore, contentDescription = null)
        }
        AnimatedVisibility(visible = expanded, enter = expandVertically() + fadeIn(), exit = shrinkVertically() + fadeOut()) {
            Column(Modifier.padding(start = 20.dp, end = 20.dp, bottom = 16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                if (sections.isEmpty()) {
                    Text(stringResource(R.string.feature_filedetails_not_applicable_detail), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                sections.forEachIndexed { index, section ->
                    if (index > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    Text(section.title, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                    if (section.entries.isEmpty()) {
                        Text(stringResource(R.string.feature_filedetails_empty), style = MaterialTheme.typography.bodySmall)
                    }
                    section.entries.forEach { entry -> EntryRow(entry) }
                }
            }
        }
    }
}

@Composable
private fun EntryRow(entry: DetailEntry) {
    Column(Modifier.fillMaxWidth().semantics(mergeDescendants = true) {}) {
        Text(entry.label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        SelectionContainer {
            Text(entry.value, style = if (entry.monospace) AegisMonospace else MaterialTheme.typography.bodyMedium)
        }
    }
}

private fun DetailKind.titleRes(): Int = when (this) {
    DetailKind.METADATA -> R.string.feature_filedetails_kind_metadata
    DetailKind.HASHES -> R.string.feature_filedetails_kind_hashes
    DetailKind.SIGNATURE -> R.string.feature_filedetails_kind_signature
    DetailKind.PERMISSIONS -> R.string.feature_filedetails_kind_permissions
    DetailKind.COMPONENTS -> R.string.feature_filedetails_kind_components
    DetailKind.STRUCTURE -> R.string.feature_filedetails_kind_structure
    DetailKind.INDICATORS -> R.string.feature_filedetails_kind_indicators
    DetailKind.EXTERNAL -> R.string.feature_filedetails_kind_external
}
