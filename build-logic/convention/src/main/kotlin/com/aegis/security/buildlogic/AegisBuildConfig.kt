package com.aegis.security.buildlogic

/**
 * Configuração de SDK compartilhada por todos os módulos Android.
 *
 * TARGET_SDK/COMPILE_SDK acompanham a versão mais recente suportada oficialmente pelo AGP
 * do catálogo. Ao atualizar o AGP (Upgrade Assistant do Android Studio), ajuste aqui.
 */
object AegisBuildConfig {
    const val MIN_SDK = 26
    const val COMPILE_SDK = 35
    const val TARGET_SDK = 35
}
