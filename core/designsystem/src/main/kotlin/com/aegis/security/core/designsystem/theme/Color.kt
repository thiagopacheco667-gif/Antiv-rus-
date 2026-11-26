package com.aegis.security.core.designsystem.theme

import androidx.compose.ui.graphics.Color

/** Paleta base AEGIS. Use sempre via [androidx.compose.material3.MaterialTheme] ou [AegisTheme]. */
internal object AegisPalette {
    // Escuro — grafite e carvão
    val Graphite = Color(0xFF0B0D10)
    val Charcoal950 = Color(0xFF0F1115)
    val Charcoal900 = Color(0xFF12151A)
    val Charcoal850 = Color(0xFF161A20)
    val Charcoal800 = Color(0xFF1B2027)
    val Charcoal700 = Color(0xFF222831)
    val Charcoal600 = Color(0xFF2A313C)
    val OutlineDark = Color(0xFF3A4250)
    val OutlineVariantDark = Color(0xFF252B35)
    val TextHighDark = Color(0xFFE8EAEF)
    val TextMediumDark = Color(0xFF9BA4B3)

    // Claro
    val Mist = Color(0xFFF4F5F8)
    val White = Color(0xFFFFFFFF)
    val Cloud50 = Color(0xFFF9FAFB)
    val Cloud100 = Color(0xFFEEF0F4)
    val Cloud200 = Color(0xFFE5E8ED)
    val OutlineLight = Color(0xFFC1C7D1)
    val OutlineVariantLight = Color(0xFFE0E3E9)
    val TextHighLight = Color(0xFF13161B)
    val TextMediumLight = Color(0xFF576070)

    // Acentos — violeta e azul elétrico
    val Violet = Color(0xFF8B7CFF)
    val VioletInk = Color(0xFF120D33)
    val VioletContainerDark = Color(0xFF2A2361)
    val VioletOnContainerDark = Color(0xFFDDD8FF)
    val VioletStrong = Color(0xFF5848D8)
    val VioletContainerLight = Color(0xFFE7E3FF)
    val VioletOnContainerLight = Color(0xFF1C1460)

    val ElectricBlue = Color(0xFF4DA3FF)
    val ElectricBlueInk = Color(0xFF00213F)
    val ElectricBlueContainerDark = Color(0xFF0D3A66)
    val ElectricBlueOnContainerDark = Color(0xFFD3E6FF)
    val ElectricBlueStrong = Color(0xFF1C6CCF)
    val ElectricBlueContainerLight = Color(0xFFD9E9FF)
    val ElectricBlueOnContainerLight = Color(0xFF052B55)

    // Erro de interface (Material) — distinto de "ameaça detectada"
    val ErrorDark = Color(0xFFF2777B)
    val ErrorContainerDark = Color(0xFF3B1517)
    val ErrorLight = Color(0xFFC0303A)
    val ErrorContainerLight = Color(0xFFFBE2E3)
}
