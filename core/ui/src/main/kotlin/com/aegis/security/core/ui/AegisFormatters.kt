package com.aegis.security.core.ui

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale

object AegisFormatters {
    private val dateTimeFormatter: DateTimeFormatter =
        DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT)

    fun dateTime(
        epochMillis: Long,
        zone: ZoneId = ZoneId.systemDefault(),
        locale: Locale = Locale.getDefault(),
    ): String = dateTimeFormatter.withLocale(locale).format(Instant.ofEpochMilli(epochMillis).atZone(zone))

    /** Tamanho em unidades binárias (1 KB = 1024 bytes). */
    fun fileSize(bytes: Long, locale: Locale = Locale.getDefault()): String {
        require(bytes >= 0) { "Tamanho negativo: $bytes" }
        if (bytes < 1024) return "$bytes B"
        val units = listOf("KB", "MB", "GB", "TB")
        var value = bytes / 1024.0
        var unitIndex = 0
        while (value >= 1024 && unitIndex < units.lastIndex) {
            value /= 1024
            unitIndex++
        }
        return String.format(locale, "%.1f %s", value, units[unitIndex])
    }

    /** Forma abreviada de um hash para listas; o relatório sempre mostra o hash completo. */
    fun shortHash(hash: String): String =
        if (hash.length > 20) "${hash.take(8)}…${hash.takeLast(8)}" else hash
}
