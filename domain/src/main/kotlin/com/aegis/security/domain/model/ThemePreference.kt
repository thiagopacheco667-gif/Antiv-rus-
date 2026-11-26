package com.aegis.security.domain.model

/** Nomes persistidos no DataStore: não renomear. */
enum class ThemePreference {
    DARK,
    LIGHT,
    SYSTEM,
    ;

    companion object {
        /** A identidade AEGIS usa o tema escuro como padrão. */
        val Default = DARK
    }
}
