package com.aegis.security.domain.model

/** Configuração do backend AEGIS que intermedeia o VirusTotal. A chave da API nunca fica no app. */
data class OnlineServiceConfig(
    val baseUrl: String,
    val hasAccessToken: Boolean,
) {
    val isConfigured: Boolean get() = baseUrl.isNotBlank() && hasAccessToken

    companion object {
        val Empty = OnlineServiceConfig(baseUrl = "", hasAccessToken = false)

        /** HTTPS é obrigatório. */
        fun isValidBaseUrl(url: String): Boolean {
            val trimmed = url.trim()
            if (!trimmed.startsWith("https://", ignoreCase = true)) return false
            val host = trimmed.substring(8).substringBefore('/').substringBefore('?')
            return host.isNotBlank() && !host.contains(' ') && !host.contains('@')
        }
    }
}

/** Informações públicas do backend obtidas em /v1/health. */
data class BackendStatus(val mode: String, val uploadsEnabled: Boolean, val dailyQuotaRemaining: Int?)
