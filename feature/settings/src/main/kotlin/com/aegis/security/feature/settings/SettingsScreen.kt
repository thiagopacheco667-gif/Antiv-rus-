package com.aegis.security.feature.settings

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Cloud
import androidx.compose.material.icons.outlined.DeleteSweep
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Speed
import androidx.compose.material.icons.outlined.Tune
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aegis.security.core.designsystem.component.AegisCard
import com.aegis.security.core.designsystem.component.AegisLogo
import com.aegis.security.core.designsystem.component.AegisTopBar
import com.aegis.security.core.designsystem.component.EmptyState
import com.aegis.security.core.designsystem.component.SectionHeader
import com.aegis.security.core.designsystem.component.StatusBadge
import com.aegis.security.core.designsystem.theme.StatusTone
import com.aegis.security.domain.model.ThemePreference

@Composable
internal fun SettingsRoute(
    onNavigateBack: () -> Unit,
    viewModel: SettingsViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val clearDialogVisible by viewModel.clearDialogVisible.collectAsStateWithLifecycle()
    val message by viewModel.message.collectAsStateWithLifecycle()

    SettingsScreen(
        uiState = uiState,
        clearDialogVisible = clearDialogVisible,
        message = message,
        onNavigateBack = onNavigateBack,
        onThemeSelected = viewModel::onThemeSelected,
        onRequestClearHistory = viewModel::requestClearHistory,
        onConfirmClearHistory = viewModel::confirmClearHistory,
        onDismissClearHistory = viewModel::dismissClearHistory,
        onMessageShown = viewModel::onMessageShown,
    )
}

@Composable
internal fun SettingsScreen(
    uiState: SettingsUiState,
    clearDialogVisible: Boolean,
    message: SettingsMessage?,
    onNavigateBack: () -> Unit,
    onThemeSelected: (ThemePreference) -> Unit,
    onRequestClearHistory: () -> Unit,
    onConfirmClearHistory: () -> Unit,
    onDismissClearHistory: () -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    val clearedText = stringResource(R.string.feature_settings_history_cleared)
    val failedText = stringResource(R.string.feature_settings_operation_failed)
    LaunchedEffect(message) {
        val text = when (message) {
            SettingsMessage.HistoryCleared -> clearedText
            SettingsMessage.OperationFailed -> failedText
            null -> return@LaunchedEffect
        }
        snackbarHostState.showSnackbar(text)
        onMessageShown()
    }

    Scaffold(
        modifier = modifier,
        containerColor = Color.Transparent,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = { AegisTopBar(title = stringResource(R.string.feature_settings_title), onNavigateBack = onNavigateBack) },
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
        ) {
            when (uiState) {
                SettingsUiState.Loading -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                SettingsUiState.Error -> EmptyState(
                    icon = Icons.Outlined.ErrorOutline,
                    title = stringResource(R.string.feature_settings_error_title),
                    message = stringResource(R.string.feature_settings_error_message),
                    modifier = Modifier.align(Alignment.Center),
                )
                is SettingsUiState.Ready -> SettingsContent(
                    state = uiState,
                    onThemeSelected = onThemeSelected,
                    onRequestClearHistory = onRequestClearHistory,
                )
            }
        }
    }

    if (clearDialogVisible) {
        AlertDialog(
            onDismissRequest = onDismissClearHistory,
            title = { Text(stringResource(R.string.feature_settings_clear_dialog_title)) },
            text = { Text(stringResource(R.string.feature_settings_clear_dialog_message)) },
            confirmButton = {
                TextButton(onClick = onConfirmClearHistory) {
                    Text(stringResource(R.string.feature_settings_clear_confirm), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = onDismissClearHistory) { Text(stringResource(R.string.feature_settings_cancel)) }
            },
        )
    }
}

@Composable
private fun SettingsContent(
    state: SettingsUiState.Ready,
    onThemeSelected: (ThemePreference) -> Unit,
    onRequestClearHistory: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SectionHeader(title = stringResource(R.string.feature_settings_section_appearance))
        AegisCard(modifier = Modifier.fillMaxWidth(), contentPadding = PaddingValues(vertical = 8.dp)) {
            ThemeSelector(selected = state.theme, onSelected = onThemeSelected)
        }

        SectionHeader(title = stringResource(R.string.feature_settings_section_analysis))
        AegisCard(modifier = Modifier.fillMaxWidth(), contentPadding = PaddingValues(vertical = 4.dp)) {
            UnavailableRow(
                icon = Icons.Outlined.Tune,
                title = stringResource(R.string.feature_settings_analysis_preferences),
                detail = stringResource(R.string.feature_settings_requires_engines),
            )
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            UnavailableRow(
                icon = Icons.Outlined.Speed,
                title = stringResource(R.string.feature_settings_analysis_limits),
                detail = stringResource(R.string.feature_settings_requires_engines),
            )
        }

        SectionHeader(title = stringResource(R.string.feature_settings_section_online))
        AegisCard(modifier = Modifier.fillMaxWidth(), contentPadding = PaddingValues(vertical = 4.dp)) {
            UnavailableRow(
                icon = Icons.Outlined.Cloud,
                title = stringResource(R.string.feature_settings_virustotal),
                detail = stringResource(R.string.feature_settings_virustotal_unavailable),
            )
        }

        SectionHeader(title = stringResource(R.string.feature_settings_section_privacy))
        AegisCard(modifier = Modifier.fillMaxWidth()) {
            PrivacyFacts()
        }

        SectionHeader(title = stringResource(R.string.feature_settings_section_data))
        AegisCard(
            modifier = Modifier.fillMaxWidth(),
            onClick = if (state.storedRecords > 0) onRequestClearHistory else null,
            contentPadding = PaddingValues(horizontal = 20.dp, vertical = 16.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Outlined.DeleteSweep,
                    contentDescription = null,
                    tint = if (state.storedRecords > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.size(16.dp))
                Column {
                    Text(text = stringResource(R.string.feature_settings_clear_history), style = MaterialTheme.typography.titleSmall)
                    Text(
                        text = if (state.storedRecords > 0) {
                            stringResource(R.string.feature_settings_records_stored, state.storedRecords)
                        } else {
                            stringResource(R.string.feature_settings_no_records)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        SectionHeader(title = stringResource(R.string.feature_settings_section_about))
        AboutCard()
        Spacer(Modifier.height(8.dp))
    }
}

@Composable
private fun ThemeSelector(
    selected: ThemePreference,
    onSelected: (ThemePreference) -> Unit,
) {
    val options = listOf(
        ThemePreference.DARK to stringResource(R.string.feature_settings_theme_dark),
        ThemePreference.LIGHT to stringResource(R.string.feature_settings_theme_light),
        ThemePreference.SYSTEM to stringResource(R.string.feature_settings_theme_system),
    )
    Column(modifier = Modifier.selectableGroup()) {
        options.forEach { (preference, label) ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 52.dp)
                    .selectable(
                        selected = preference == selected,
                        onClick = { onSelected(preference) },
                        role = Role.RadioButton,
                    )
                    .padding(horizontal = 20.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = preference == selected, onClick = null)
                Spacer(Modifier.size(16.dp))
                Text(text = label, style = MaterialTheme.typography.bodyLarge)
            }
        }
    }
}

/** Opção que ainda não existe: apresentada explicitamente como indisponível, sem ação. */
@Composable
private fun UnavailableRow(icon: ImageVector, title: String, detail: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 14.dp)
            .semantics(mergeDescendants = true) {},
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.size(16.dp))
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(text = title, style = MaterialTheme.typography.titleSmall)
            Text(text = detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.size(12.dp))
        StatusBadge(label = stringResource(R.string.feature_settings_unavailable), tone = StatusTone.INCONCLUSIVE)
    }
}

@Composable
private fun PrivacyFacts() {
    val facts = listOf(
        R.string.feature_settings_privacy_local_default,
        R.string.feature_settings_privacy_consent,
        R.string.feature_settings_privacy_no_internet,
        R.string.feature_settings_privacy_metadata_only,
        R.string.feature_settings_privacy_no_backup,
    )
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        facts.forEach { fact ->
            Row {
                Text(text = "•", color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(end = 10.dp))
                Text(text = stringResource(fact), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun AboutCard() {
    val context = LocalContext.current
    val version = remember(context) { context.appVersionName() }
    AegisCard(modifier = Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            AegisLogo(size = 44.dp, contentDescription = null)
            Spacer(Modifier.size(14.dp))
            Column {
                Text(text = stringResource(R.string.feature_settings_about_name), style = MaterialTheme.typography.titleMedium)
                Text(
                    text = stringResource(R.string.feature_settings_about_version, version),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Spacer(Modifier.height(14.dp))
        Text(
            text = stringResource(R.string.feature_settings_about_disclaimer),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

private fun Context.appVersionName(): String = try {
    val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
    } else {
        legacyPackageInfo()
    }
    info.versionName ?: "—"
} catch (error: PackageManager.NameNotFoundException) {
    "—"
}

@Suppress("DEPRECATION")
private fun Context.legacyPackageInfo() = packageManager.getPackageInfo(packageName, 0)
