package com.aegis.security.core.designsystem.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.unit.dp

private val AegisDarkColorScheme = darkColorScheme(
    primary = AegisPalette.Violet,
    onPrimary = AegisPalette.VioletInk,
    primaryContainer = AegisPalette.VioletContainerDark,
    onPrimaryContainer = AegisPalette.VioletOnContainerDark,
    secondary = AegisPalette.ElectricBlue,
    onSecondary = AegisPalette.ElectricBlueInk,
    secondaryContainer = AegisPalette.ElectricBlueContainerDark,
    onSecondaryContainer = AegisPalette.ElectricBlueOnContainerDark,
    tertiary = AegisPalette.ElectricBlue,
    onTertiary = AegisPalette.ElectricBlueInk,
    background = AegisPalette.Graphite,
    onBackground = AegisPalette.TextHighDark,
    surface = AegisPalette.Graphite,
    onSurface = AegisPalette.TextHighDark,
    surfaceVariant = AegisPalette.Charcoal800,
    onSurfaceVariant = AegisPalette.TextMediumDark,
    surfaceContainerLowest = AegisPalette.Charcoal950,
    surfaceContainerLow = AegisPalette.Charcoal900,
    surfaceContainer = AegisPalette.Charcoal850,
    surfaceContainerHigh = AegisPalette.Charcoal800,
    surfaceContainerHighest = AegisPalette.Charcoal700,
    surfaceBright = AegisPalette.Charcoal600,
    surfaceDim = AegisPalette.Graphite,
    outline = AegisPalette.OutlineDark,
    outlineVariant = AegisPalette.OutlineVariantDark,
    error = AegisPalette.ErrorDark,
    errorContainer = AegisPalette.ErrorContainerDark,
)

private val AegisLightColorScheme = lightColorScheme(
    primary = AegisPalette.VioletStrong,
    onPrimary = AegisPalette.White,
    primaryContainer = AegisPalette.VioletContainerLight,
    onPrimaryContainer = AegisPalette.VioletOnContainerLight,
    secondary = AegisPalette.ElectricBlueStrong,
    onSecondary = AegisPalette.White,
    secondaryContainer = AegisPalette.ElectricBlueContainerLight,
    onSecondaryContainer = AegisPalette.ElectricBlueOnContainerLight,
    tertiary = AegisPalette.ElectricBlueStrong,
    onTertiary = AegisPalette.White,
    background = AegisPalette.Mist,
    onBackground = AegisPalette.TextHighLight,
    surface = AegisPalette.Mist,
    onSurface = AegisPalette.TextHighLight,
    surfaceVariant = AegisPalette.Cloud100,
    onSurfaceVariant = AegisPalette.TextMediumLight,
    surfaceContainerLowest = AegisPalette.White,
    surfaceContainerLow = AegisPalette.Cloud50,
    surfaceContainer = AegisPalette.White,
    surfaceContainerHigh = AegisPalette.Cloud100,
    surfaceContainerHighest = AegisPalette.Cloud200,
    surfaceBright = AegisPalette.White,
    surfaceDim = AegisPalette.Cloud200,
    outline = AegisPalette.OutlineLight,
    outlineVariant = AegisPalette.OutlineVariantLight,
    error = AegisPalette.ErrorLight,
    errorContainer = AegisPalette.ErrorContainerLight,
)

/** Bordas arredondadas contidas, sem exagero. */
internal val AegisShapes = Shapes(
    extraSmall = RoundedCornerShape(6.dp),
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(12.dp),
    large = RoundedCornerShape(16.dp),
    extraLarge = RoundedCornerShape(24.dp),
)

/**
 * Tema AEGIS. Cores dinâmicas (Material You) ficam desligadas para preservar a identidade.
 */
@Composable
fun AegisTheme(
    darkTheme: Boolean = true,
    content: @Composable () -> Unit,
) {
    val colorScheme = if (darkTheme) AegisDarkColorScheme else AegisLightColorScheme
    val statusColors = if (darkTheme) DarkStatusColors else LightStatusColors

    CompositionLocalProvider(LocalAegisStatusColors provides statusColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = AegisTypography,
            shapes = AegisShapes,
            content = content,
        )
    }
}

object AegisTheme {
    val statusColors: AegisStatusColors
        @Composable
        @ReadOnlyComposable
        get() = LocalAegisStatusColors.current

    /** Gradiente de marca: violeta → azul elétrico. */
    val accentBrush: Brush
        @Composable
        @ReadOnlyComposable
        get() = Brush.linearGradient(
            listOf(MaterialTheme.colorScheme.primary, MaterialTheme.colorScheme.secondary),
        )
}
