package com.aegis.security.core.designsystem.theme

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/**
 * Tons semânticos usados para comunicar estados reais (vereditos, disponibilidade).
 * A UI nunca deve usar [SAFE] para algo que não foi efetivamente verificado.
 */
enum class StatusTone { SAFE, SUSPICIOUS, THREAT, INCONCLUSIVE, ERROR, INFO }

@Immutable
data class ToneColors(val content: Color, val container: Color)

@Immutable
data class AegisStatusColors(
    val safe: ToneColors,
    val suspicious: ToneColors,
    val threat: ToneColors,
    val inconclusive: ToneColors,
    val error: ToneColors,
    val info: ToneColors,
) {
    fun forTone(tone: StatusTone): ToneColors = when (tone) {
        StatusTone.SAFE -> safe
        StatusTone.SUSPICIOUS -> suspicious
        StatusTone.THREAT -> threat
        StatusTone.INCONCLUSIVE -> inconclusive
        StatusTone.ERROR -> error
        StatusTone.INFO -> info
    }
}

internal val DarkStatusColors = AegisStatusColors(
    safe = ToneColors(content = Color(0xFF34D399), container = Color(0xFF0E2A21)),
    suspicious = ToneColors(content = Color(0xFFF2B84B), container = Color(0xFF2E2411)),
    threat = ToneColors(content = Color(0xFFEF6B6F), container = Color(0xFF301518)),
    inconclusive = ToneColors(content = Color(0xFFA7B0C0), container = Color(0xFF1F242C)),
    error = ToneColors(content = Color(0xFFBBA8E6), container = Color(0xFF241F31)),
    info = ToneColors(content = Color(0xFF8B7CFF), container = Color(0xFF1E1A3D)),
)

internal val LightStatusColors = AegisStatusColors(
    safe = ToneColors(content = Color(0xFF0B8A5E), container = Color(0xFFDCF4E9)),
    suspicious = ToneColors(content = Color(0xFF9A6200), container = Color(0xFFFCEFD5)),
    threat = ToneColors(content = Color(0xFFBF2F36), container = Color(0xFFFBE3E4)),
    inconclusive = ToneColors(content = Color(0xFF545D6C), container = Color(0xFFEAEDF1)),
    error = ToneColors(content = Color(0xFF654AA3), container = Color(0xFFEEE8F8)),
    info = ToneColors(content = Color(0xFF5848D8), container = Color(0xFFE9E6FF)),
)

internal val LocalAegisStatusColors = staticCompositionLocalOf { DarkStatusColors }
