# kotlinx.serialization: rotas de navegação e relatório persistido (JSON).
# As bibliotecas já trazem regras para @Serializable; estas cobrem os modelos do AEGIS
# usados por nome em sealed classes (OnlineReputation) e rotas tipadas.
-keepattributes *Annotation*, InnerClasses
-keep,includedescriptorclasses class com.aegis.security.**$$serializer { *; }
-keepclassmembers class com.aegis.security.** {
    *** Companion;
}
-keepclasseswithmembers class com.aegis.security.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# OkHttp (regras oficiais já incluídas); evita avisos de plataformas opcionais.
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
