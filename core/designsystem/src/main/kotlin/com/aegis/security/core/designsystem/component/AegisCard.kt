package com.aegis.security.core.designsystem.component

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Card AEGIS: superfície carvão com borda fina — profundidade discreta, sem sombras pesadas.
 * Quando [onClick] é nulo o card não é clicável (nenhuma affordance falsa).
 */
@Composable
fun AegisCard(
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    contentPadding: PaddingValues = PaddingValues(20.dp),
    content: @Composable ColumnScope.() -> Unit,
) {
    val shape = MaterialTheme.shapes.large
    val colors = CardDefaults.outlinedCardColors(
        containerColor = MaterialTheme.colorScheme.surfaceContainer,
        contentColor = MaterialTheme.colorScheme.onSurface,
    )
    val border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)

    if (onClick != null) {
        OutlinedCard(onClick = onClick, modifier = modifier, shape = shape, colors = colors, border = border) {
            Column(modifier = Modifier.padding(contentPadding), content = content)
        }
    } else {
        OutlinedCard(modifier = modifier, shape = shape, colors = colors, border = border) {
            Column(modifier = Modifier.padding(contentPadding), content = content)
        }
    }
}
