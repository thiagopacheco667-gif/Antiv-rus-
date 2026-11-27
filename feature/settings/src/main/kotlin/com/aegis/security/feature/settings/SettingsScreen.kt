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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.DeleteSweep
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Remove
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aegis.security.core.designsystem.component.AegisCard
import com.aegis.security.core.designsystem.component.AegisLogo
import com.aegis.security.core.designsystem.component.AegisTopBar
import com.aegis.security.core.designsystem.component.EmptyState
import com.aegis.security.core.designsystem.component.SectionHeader
import com.aegis.security.core.designsystem.component.StatusBadge
import com.aegis.security.core.designsystem.theme.AegisTheme
import com.aegis.security.core.designsystem.theme.StatusTone
import com.aegis.security.domain.model.AnalysisLimits
import com.aegis.security.domain.model.OnlineMode
import com.aegis.security.domain.model.OnlineServiceConfig
import com.aegis.security.domain.model.ThemePreference

@Composable
internal fun SettingsRoute(
    onNavigateBack: () -> Unit,
    viewModel: SettingsViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val clearDialogVisible by viewModel.clearDialogVisible.collectAsStateWithLifecycle()
    val message by viewModel.message.collectAsStateWithLifecycle()
    val connection by viewModel.connection.collectAsStateWithLifecycle()

    val snackbarHostState = remember { SnackbarHostState() }
    val texts = mapOf(
        SettingsMessage.HistoryCleared to stringResource(R.string.feature_settings_history_cleared),
        SettingsMessage.OperationFailed to stringResource(R.string.feature_settings_operation_failed),
        SettingsMessage.OnlineSaved to stringResource(R.string.feature_settings_online_saved),
        SettingsMessage.OnlineRemoved to stringResource(R.string.feature_settings_online_removed),
        SettingsMessage.InvalidUrl to stringResource(R.string.feature_settings_online_invalid_url),
        SettingsMessage.InvalidApiKey to stringResource(R.string.feature_settings_api_key_invalid),
    )
    LaunchedEffect(message) {
        val current = message ?: return@LaunchedEffect
        snackbarHostState.showSnackbar(texts.getValue(current))
        viewModel.onMessageShown()
    }

    Scaffold(
        containerColor = Color.Transparent,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = { AegisTopBar(title = stringResource(R.string.feature_settings_title), onNavigateBack = onNavigateBack) },
    ) { innerPadding ->
        Box(Modifier.fillMaxSize().padding(innerPadding)) {
            when (val state = uiState) {
                SettingsUiState.Loading -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                SettingsUiState.Error -> EmptyState(
                    icon = Icons.Outlined.ErrorOutline,
                    title = stringResource(R.string.feature_settings_error_title),
                    message = stringResource(R.string.feature_settings_error_message),
                    modifier = Modifier.align(Alignment.Center),
                )
                is SettingsUiState.Ready -> SettingsContent(
                    state = state,
                    connection = connection,
                    engineNames = viewModel.engineNames,
                    ruleCount = viewModel.ruleCount,
                    yaraIntegrated = viewModel.yaraIntegrated,
                    onThemeSelected = viewModel::onThemeSelected,
                    onLimitsChanged = viewModel::onLimitsChanged,
                    onSaveOnline = viewModel::saveOnlineConfig,
                    onRemoveOnline = viewModel::removeOnlineConfig,
                    onTestConnection = viewModel::testConnection,
                    onRequestClearHistory = viewModel::requestClearHistory,
                )
            }
        }
    }

    if (clearDialogVisible) {
        AlertDialog(
            onDismissRequest = viewModel::dismissClearHistory,
            title = { Text(stringResource(R.string.feature_settings_clear_dialog_title)) },
            text = { Text(stringResource(R.string.feature_settings_clear_dialog_message)) },
            confirmButton = {
                TextButton(onClick = viewModel::confirmClearHistory) {
                    Text(stringResource(R.string.feature_settings_clear_confirm), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = viewModel::dismissClearHistory) { Text(stringResource(R.string.feature_settings_cancel)) } },
        )
    }
}

@Composable
private fun SettingsContent(
    state: SettingsUiState.Ready,
    connection: ConnectionTest,
    engineNames: List<String>,
    ruleCount: Int,
    yaraIntegrated: Boolean,
    onThemeSelected: (ThemePreference) -> Unit,
    onLimitsChanged: (AnalysisLimits) -> Unit,
    onSaveOnline: (OnlineMode, String, String) -> Unit,
    onRemoveOnline: (OnlineMode) -> Unit,
    onTestConnection: () -> Unit,
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
        AegisCard(Modifier.fillMaxWidth(), contentPadding = PaddingValues(vertical = 8.dp)) {
            ThemeSelector(selected = state.theme, onSelected = onThemeSelected)
        }

        SectionHeader(title = stringResource(R.string.feature_settings_section_analysis))
        AegisCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.feature_settings_engines, engineNames.size, ruleCount), style = MaterialTheme.typography.bodyMedium)
            Text(engineNames.joinToString(" · "), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(10.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.feature_settings_yara), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                StatusBadge(
                    label = stringResource(if (yaraIntegrated) R.string.feature_settings_integrated else R.string.feature_settings_not_integrated),
                    tone = if (yaraIntegrated) StatusTone.SAFE else StatusTone.INCONCLUSIVE,
                )
            }
        }

        SectionHeader(title = stringResource(R.string.feature_settings_section_limits))
        AegisCard(Modifier.fillMaxWidth(), contentPadding = PaddingValues(vertical = 4.dp)) {
            LimitsEditor(state.limits, onLimitsChanged)
        }

        SectionHeader(title = stringResource(R.string.feature_settings_section_online))
        AegisCard(Modifier.fillMaxWidth()) {
            OnlineEditor(state.online, connection, onSaveOnline, onRemoveOnline, onTestConnection)
        }

        SectionHeader(title = stringResource(R.string.feature_settings_section_privacy))
        AegisCard(Modifier.fillMaxWidth()) { PrivacyFacts() }

        SectionHeader(title = stringResource(R.string.feature_settings_section_data))
        AegisCard(
            modifier = Modifier.fillMaxWidth(),
            onClick = if (state.storedRecords > 0) onRequestClearHistory else null,
            contentPadding = PaddingValues(horizontal = 20.dp, vertical = 16.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Outlined.DeleteSweep,
                    contentDescription = null,
                    tint = if (state.storedRecords > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.size(16.dp))
                Column {
                    Text(stringResource(R.string.feature_settings_clear_history), style = MaterialTheme.typography.titleSmall)
                    Text(
                        if (state.storedRecords > 0) stringResource(R.string.feature_settings_records_stored, state.storedRecords) else stringResource(R.string.feature_settings_no_records),
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
private fun ThemeSelector(selected: ThemePreference, onSelected: (ThemePreference) -> Unit) {
    val options = listOf(
        ThemePreference.DARK to stringResource(R.string.feature_settings_theme_dark),
        ThemePreference.LIGHT to stringResource(R.string.feature_settings_theme_light),
        ThemePreference.SYSTEM to stringResource(R.string.feature_settings_theme_system),
    )
    Column(Modifier.selectableGroup()) {
        options.forEach { (preference, label) ->
            Row(
                Modifier
                    .fillMaxWidth()
                    .heightIn(min = 52.dp)
                    .selectable(selected = preference == selected, onClick = { onSelected(preference) }, role = Role.RadioButton)
                    .padding(horizontal = 20.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = preference == selected, onClick = null)
                Spacer(Modifier.size(16.dp))
                Text(label, style = MaterialTheme.typography.bodyLarge)
            }
        }
    }
}

@Composable
private fun LimitsEditor(limits: AnalysisLimits, onChanged: (AnalysisLimits) -> Unit) {
    LimitStepper(stringResource(R.string.feature_settings_limit_file_size), limits.maxFileSizeMb, AnalysisLimits.FileSizeOptionsMb, "MB") { onChanged(limits.copy(maxFileSizeMb = it)) }
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
    LimitStepper(stringResource(R.string.feature_settings_limit_entries), limits.maxArchiveEntries, AnalysisLimits.ArchiveEntryOptions, "") { onChanged(limits.copy(maxArchiveEntries = it)) }
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
    LimitStepper(stringResource(R.string.feature_settings_limit_uncompressed), limits.maxTotalUncompressedMb, AnalysisLimits.TotalUncompressedOptionsMb, "MB") { onChanged(limits.copy(maxTotalUncompressedMb = it)) }
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
    LimitStepper(stringResource(R.string.feature_settings_limit_ratio), limits.maxCompressionRatio, AnalysisLimits.CompressionRatioOptions, ":1") { onChanged(limits.copy(maxCompressionRatio = it)) }
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
    LimitStepper(stringResource(R.string.feature_settings_limit_depth), limits.maxNestingDepth, AnalysisLimits.NestingDepthOptions, "") { onChanged(limits.copy(maxNestingDepth = it)) }
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
    LimitStepper(stringResource(R.string.feature_settings_limit_scan), limits.maxContentScanMb, AnalysisLimits.ContentScanOptionsMb, "MB") { onChanged(limits.copy(maxContentScanMb = it)) }
}

/** Escolha entre valores pré-definidos e seguros (evita limites inválidos). */
@Composable
private fun LimitStepper(label: String, value: Int, options: List<Int>, unit: String, onChanged: (Int) -> Unit) {
    val index = options.indexOf(value).takeIf { it >= 0 } ?: options.indexOfFirst { it >= value }.coerceAtLeast(0)
    val decrease = stringResource(R.string.feature_settings_decrease, label)
    val increase = stringResource(R.string.feature_settings_increase, label)
    Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f).padding(start = 8.dp))
        IconButton(onClick = { onChanged(options[index - 1]) }, enabled = index > 0) { Icon(Icons.Outlined.Remove, contentDescription = decrease) }
        Text("$value$unit".replace("MB", " MB"), style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics(mergeDescendants = true) {})
        IconButton(onClick = { onChanged(options[index + 1]) }, enabled = index < options.lastIndex) { Icon(Icons.Outlined.Add, contentDescription = increase) }
    }
}

@Composable
private fun OnlineEditor(
    config: OnlineServiceConfig,
    connection: ConnectionTest,
    onSave: (OnlineMode, String, String) -> Unit,
    onRemove: (OnlineMode) -> Unit,
    onTest: () -> Unit,
) {
    var mode by rememberSaveable(config.mode) { mutableStateOf(config.mode) }
    var url by rememberSaveable(config.baseUrl) { mutableStateOf(config.baseUrl) }
    var secret by remember { mutableStateOf("") }
    val hasSecret = if (mode == OnlineMode.DIRECT) config.hasApiKey else config.hasBackendToken
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Column(Modifier.selectableGroup()) {
            listOf(
                OnlineMode.DIRECT to R.string.feature_settings_mode_direct,
                OnlineMode.BACKEND to R.string.feature_settings_mode_backend,
            ).forEach { (option, label) ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .selectable(selected = mode == option, onClick = { mode = option; secret = "" }, role = Role.RadioButton),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = mode == option, onClick = null)
                    Spacer(Modifier.size(12.dp))
                    Text(stringResource(label), style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
        Text(
            stringResource(if (mode == OnlineMode.DIRECT) R.string.feature_settings_direct_intro else R.string.feature_settings_online_intro),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (mode == OnlineMode.BACKEND) {
            OutlinedTextField(
                value = url,
                onValueChange = { url = it.trim() },
                label = { Text(stringResource(R.string.feature_settings_online_url)) },
                placeholder = { Text("https://aegis.exemplo.com") },
                singleLine = true,
                isError = url.isNotBlank() && !OnlineServiceConfig.isValidBaseUrl(url),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.fillMaxWidth(),
            )
        }
        val secretLabel = when {
            mode == OnlineMode.DIRECT && hasSecret -> R.string.feature_settings_api_key_keep
            mode == OnlineMode.DIRECT -> R.string.feature_settings_api_key
            hasSecret -> R.string.feature_settings_online_token_keep
            else -> R.string.feature_settings_online_token
        }
        OutlinedTextField(
            value = secret,
            onValueChange = { secret = it.trim() },
            label = { Text(stringResource(secretLabel)) },
            singleLine = true,
            isError = mode == OnlineMode.DIRECT && secret.isNotBlank() && !OnlineServiceConfig.isValidApiKey(secret),
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )
        val activeAndConfigured = config.mode == mode && config.isConfigured
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { onSave(mode, url, secret); secret = "" }, modifier = Modifier.weight(1f).heightIn(min = 48.dp)) {
                Text(stringResource(R.string.feature_settings_online_save))
            }
            OutlinedButton(onClick = onTest, enabled = activeAndConfigured && connection != ConnectionTest.Running, modifier = Modifier.weight(1f).heightIn(min = 48.dp)) {
                Icon(Icons.Outlined.Search, contentDescription = null)
                Spacer(Modifier.size(6.dp))
                Text(stringResource(R.string.feature_settings_online_test))
            }
        }
        when (connection) {
            ConnectionTest.Idle -> Unit
            ConnectionTest.Running -> Text(stringResource(R.string.feature_settings_online_testing), style = MaterialTheme.typography.bodySmall)
            is ConnectionTest.Success -> Text(
                stringResource(
                    R.string.feature_settings_online_ok,
                    connection.status.mode,
                    stringResource(if (connection.status.uploadsEnabled) R.string.feature_settings_yes else R.string.feature_settings_no),
                    connection.status.dailyQuotaRemaining?.toString() ?: "—",
                ),
                style = MaterialTheme.typography.bodySmall,
                color = AegisTheme.statusColors.safe.content,
            )
            is ConnectionTest.Failure -> Text(
                stringResource(R.string.feature_settings_online_fail, connection.message),
                style = MaterialTheme.typography.bodySmall,
                color = AegisTheme.statusColors.error.content,
            )
        }
        if (hasSecret || (mode == OnlineMode.BACKEND && config.baseUrl.isNotBlank())) {
            TextButton(onClick = { onRemove(mode) }) { Text(stringResource(R.string.feature_settings_online_remove), color = MaterialTheme.colorScheme.error) }
        }
        Text(stringResource(R.string.feature_settings_online_terms), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun PrivacyFacts() {
    val facts = listOf(
        R.string.feature_settings_privacy_local_default,
        R.string.feature_settings_privacy_consent,
        R.string.feature_settings_privacy_internet,
        R.string.feature_settings_privacy_metadata_only,
        R.string.feature_settings_privacy_token,
        R.string.feature_settings_privacy_no_backup,
    )
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        facts.forEach { fact ->
            Row {
                Text("•", color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(end = 10.dp))
                Text(stringResource(fact), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun AboutCard() {
    val context = LocalContext.current
    val version = remember(context) { context.appVersionName() }
    AegisCard(Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            AegisLogo(size = 44.dp, contentDescription = null)
            Spacer(Modifier.size(14.dp))
            Column {
                Text(stringResource(R.string.feature_settings_about_name), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.feature_settings_about_version, version), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Spacer(Modifier.height(14.dp))
        Text(stringResource(R.string.feature_settings_about_disclaimer), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
