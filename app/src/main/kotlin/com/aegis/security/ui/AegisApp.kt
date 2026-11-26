package com.aegis.security.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import com.aegis.security.navigation.AegisNavHost

/** Raiz da interface: fundo grafite com um brilho violeta sutil e o grafo de navegação. */
@Composable
fun AegisApp(modifier: Modifier = Modifier) {
    val background = MaterialTheme.colorScheme.background
    val glow = MaterialTheme.colorScheme.primary.copy(alpha = 0.09f)

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(background)
            .drawBehind {
                drawCircle(
                    brush = Brush.radialGradient(
                        colors = listOf(glow, Color.Transparent),
                        center = Offset(size.width * 0.85f, 0f),
                        radius = size.width * 0.9f,
                    ),
                    radius = size.width * 0.9f,
                    center = Offset(size.width * 0.85f, 0f),
                )
            },
    ) {
        AegisNavHost()
    }
}
