package com.aegis.security.core.designsystem.component

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegis.security.core.designsystem.R
import com.aegis.security.core.designsystem.theme.AegisTheme

/**
 * Símbolo AEGIS: escudo com contorno em gradiente violeta→azul e marca "A" esmeralda.
 * Desenhado em vetor (Canvas) para nitidez em qualquer densidade.
 */
@Composable
fun AegisLogo(
    modifier: Modifier = Modifier,
    size: Dp = 40.dp,
    contentDescription: String? = stringResource(R.string.core_designsystem_logo_description),
) {
    val start = MaterialTheme.colorScheme.primary
    val end = MaterialTheme.colorScheme.secondary
    val fill = MaterialTheme.colorScheme.surfaceContainerHigh
    val mark = AegisTheme.statusColors.safe.content

    val semanticsModifier = if (contentDescription != null) {
        Modifier.semantics { this.contentDescription = contentDescription }
    } else {
        Modifier.clearAndSetSemantics { }
    }

    Canvas(modifier = modifier.size(size).then(semanticsModifier)) {
        val w = this.size.width
        val h = this.size.height

        val shield = Path().apply {
            moveTo(w * 0.50f, h * 0.07f)
            lineTo(w * 0.88f, h * 0.20f)
            lineTo(w * 0.88f, h * 0.46f)
            cubicTo(w * 0.88f, h * 0.70f, w * 0.72f, h * 0.87f, w * 0.50f, h * 0.95f)
            cubicTo(w * 0.28f, h * 0.87f, w * 0.12f, h * 0.70f, w * 0.12f, h * 0.46f)
            lineTo(w * 0.12f, h * 0.20f)
            close()
        }
        drawPath(path = shield, color = fill)
        drawPath(
            path = shield,
            brush = Brush.linearGradient(listOf(start, end), start = Offset.Zero, end = Offset(w, h)),
            style = Stroke(width = w * 0.065f, join = StrokeJoin.Round),
        )

        val monogram = Path().apply {
            moveTo(w * 0.50f, h * 0.28f)
            lineTo(w * 0.69f, h * 0.70f)
            lineTo(w * 0.60f, h * 0.70f)
            lineTo(w * 0.50f, h * 0.48f)
            lineTo(w * 0.40f, h * 0.70f)
            lineTo(w * 0.31f, h * 0.70f)
            close()
        }
        drawPath(path = monogram, color = mark)
    }
}

/** Logotipo completo: símbolo + "AEGIS SECURITY". */
@Composable
fun AegisWordmark(
    modifier: Modifier = Modifier,
    symbolSize: Dp = 36.dp,
) {
    val name = stringResource(R.string.core_designsystem_brand_name)
    val tagline = stringResource(R.string.core_designsystem_brand_tagline)
    Row(
        modifier = modifier.clearAndSetSemantics { contentDescription = "$name $tagline" },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        AegisLogo(size = symbolSize, contentDescription = null)
        Column {
            Text(
                text = name,
                style = MaterialTheme.typography.titleLarge.copy(letterSpacing = 4.sp),
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = tagline,
                style = MaterialTheme.typography.labelSmall.copy(letterSpacing = 3.sp),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
