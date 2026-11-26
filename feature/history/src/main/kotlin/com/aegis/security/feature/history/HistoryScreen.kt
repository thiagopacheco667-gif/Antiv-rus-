package com.aegis.security.feature.history

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.DeleteSweep
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.History
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aegis.security.core.designsystem.component.AegisCard
import com.aegis.security.core.designsystem.component.AegisTopBar
import com.aegis.security.core.designsystem.component.EmptyState
import com.aegis.security.core.ui.ScanRecordRow
import com.aegis.security.core.ui.label
import com.aegis.security.domain.model.ScanRecord

@Composable
internal fun HistoryRoute(
    onNavigateBack: () -> Unit,
    viewModel: HistoryViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val confirmation by viewModel.pendingConfirmation.collectAsStateWithLifecycle()
    val operationFailed by viewModel.operationFailed.collectAsStateWithLifecycle()

    HistoryScreen(
        uiState = uiState,
        confirmation = confirmation,
        operationFailed = operationFailed,
        onNavigateBack = onNavigateBack,
        onRequestDelete = viewModel::requestDelete,
        onRequestClearAll = viewModel::requestClearAll,
        onConfirm = viewModel::confirm,
        onDismissConfirmation = viewModel::dismissConfirmation,
        onOperationErrorShown = viewModel::onOperationErrorShown,
    )
}

@Composable
internal fun HistoryScreen(
    uiState: HistoryUiState,
    confirmation: HistoryConfirmation?,
    operationFailed: Boolean,
    onNavigateBack: () -> Unit,
    onRequestDelete: (ScanRecord) -> Unit,
    onRequestClearAll: () -> Unit,
    onConfirm: () -> Unit,
    onDismissConfirmation: () -> Unit,
    onOperationErrorShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    val errorMessage = stringResource(R.string.feature_history_operation_failed)
    LaunchedEffect(operationFailed) {
        if (operationFailed) {
            snackbarHostState.showSnackbar(errorMessage)
            onOperationErrorShown()
        }
    }

    val hasRecords = (uiState as? HistoryUiState.Ready)?.records?.isNotEmpty() == true

    Scaffold(
        modifier = modifier,
        containerColor = Color.Transparent,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            AegisTopBar(
                title = stringResource(R.string.feature_history_title),
                onNavigateBack = onNavigateBack,
                actions = {
                    if (hasRecords) {
                        IconButton(onClick = onRequestClearAll) {
                            Icon(
                                imageVector = Icons.Outlined.DeleteSweep,
                                contentDescription = stringResource(R.string.feature_history_clear_all),
                            )
                        }
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
                HistoryUiState.Loading -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                HistoryUiState.Error -> EmptyState(
                    icon = Icons.Outlined.ErrorOutline,
                    title = stringResource(R.string.feature_history_error_title),
                    message = stringResource(R.string.feature_history_error_message),
                    modifier = Modifier.align(Alignment.Center),
                )
                is HistoryUiState.Ready -> if (uiState.records.isEmpty()) {
                    EmptyState(
                        icon = Icons.Outlined.History,
                        title = stringResource(R.string.feature_history_empty_title),
                        message = stringResource(R.string.feature_history_empty_message),
                        modifier = Modifier.align(Alignment.Center),
                    )
                } else {
                    HistoryList(records = uiState.records, onRequestDelete = onRequestDelete)
                }
            }
        }
    }

    if (confirmation != null) {
        ConfirmationDialog(confirmation = confirmation, onConfirm = onConfirm, onDismiss = onDismissConfirmation)
    }
}

@Composable
private fun HistoryList(
    records: List<ScanRecord>,
    onRequestDelete: (ScanRecord) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(items = records, key = { it.id }) { record ->
            AegisCard(
                modifier = Modifier.fillMaxWidth(),
                contentPadding = PaddingValues(start = 16.dp, end = 4.dp, top = 14.dp, bottom = 14.dp),
            ) {
                ScanRecordRow(
                    record = record,
                    trailing = {
                        IconButton(onClick = { onRequestDelete(record) }) {
                            Icon(
                                imageVector = Icons.Outlined.Delete,
                                contentDescription = stringResource(
                                    R.string.feature_history_delete_record,
                                    record.fileName,
                                ),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    },
                )
                val evidence = record.evidenceSummary
                Text(
                    text = if (evidence.isBlank()) record.origin.label() else "${record.origin.label()} · $evidence",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 10.dp, end = 12.dp),
                )
            }
        }
    }
}

@Composable
private fun ConfirmationDialog(
    confirmation: HistoryConfirmation,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    val (title, message) = when (confirmation) {
        is HistoryConfirmation.DeleteOne ->
            stringResource(R.string.feature_history_delete_title) to
                stringResource(R.string.feature_history_delete_message, confirmation.fileName)
        HistoryConfirmation.ClearAll ->
            stringResource(R.string.feature_history_clear_title) to
                stringResource(R.string.feature_history_clear_message)
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(message) },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.feature_history_confirm_delete), color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.feature_history_cancel)) }
        },
    )
}
