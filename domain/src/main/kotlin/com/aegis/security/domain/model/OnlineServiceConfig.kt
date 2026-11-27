package com.aegis.security.domain.model

/** Como o app fala com o VirusTotal. */
enum class OnlineMode {
    /** Chave pessoal do VirusTotal informada pelo usuário, cifrada no aparelho. Nunca embutida no APK. */
    DIRECT,

    /** Servidor AEGIS próprio (pasta backend/): a chave fica só no servidor. */
    BACKEND,
}

data class OnlineServiceConfig(
    val mode: OnlineMode,
    val baseUrl: String,
    val hasBackendToken: Boolean,
    val hasApiKey: Boolean,
) {
    val isConfigured: Boolean
        get() = when (mode) {
            OnlineMode.DIRECT -> hasApiKey
            OnlineMode.BACKEND -> isValidBaseUrl(baseUrl) && hasBackendToken
        }

    companion object {
        val Empty = OnlineServiceConfig(OnlineMode.DIRECT, baseUrl = "", hasBackendToken = false, hasApiKey = false)

        /** HTTPS é obrigatório. */
        fun isValidBaseUrl(url: String): Boolean {
            val trimmed = url.trim()
            if (!trimmed.startsWith("https://", ignoreCase = true)) return false
            val host = trimmed.substring(8).substringBefore('/').substringBefore('?')
            return host.isNotBlank() && !host.contains(' ') && !host.contains('@')
        }

        /** Chaves da API v3 do VirusTotal têm 64 caracteres hexadecimais. */
        fun isValidApiKey(key: String): Boolean = Regex("^[0-9a-fA-F]{64}$").matches(key.trim())
    }
}

/** Informações do serviço obtidas no teste de conexão. */
data class BackendStatus(val mode: String, val uploadsEnabled: Boolean, val dailyQuotaRemaining: Int?)
