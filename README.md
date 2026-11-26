# AEGIS SECURITY

Analisador de segurança de arquivos para Android nativo (Kotlin, Jetpack Compose, Material 3).

**Estado atual: Etapa 1** — estrutura multimódulo, Gradle, arquitetura, navegação, design system,
splash, dashboard, histórico (Room) e configurações (DataStore).
Nenhum mecanismo de análise está instalado ainda; o app informa isso de forma explícita e não
simula resultados. Detalhes em [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Requisitos

- Android Studio Ladybug (2024.2) ou mais recente, com JDK 17+ (o JBR embutido serve).
- Android SDK Platform 35.

## Compilar e validar

```bash
./gradlew assembleDebug              # gera app/build/outputs/apk/debug/app-debug.apk
./gradlew testDebugUnitTest :domain:test   # testes unitários
./gradlew connectedDebugAndroidTest  # testes instrumentados (emulador/aparelho conectado)
./gradlew lintDebug
```

## Estrutura

```
app/                    Application, MainActivity, splash, navegação
build-logic/convention/ convention plugins (aegis.android.*, aegis.jvm.library)
core/common             dispatchers e escopos
core/database           Room
core/designsystem       tema, cores, tipografia, logo, componentes
core/security           registro dos mecanismos de análise
core/ui                 apresentação de modelos de domínio
domain/                 model, repository, usecase, analysis (Kotlin puro)
data/                   local (DataStore), repository (Room), mapper
feature/dashboard | scanner | history | settings
```

## Roteiro

| Etapa | Escopo |
|---|---|
| 1 ✅ | Estrutura, Gradle, arquitetura, navegação, tema, dashboard |
| 2 | Seleção via Storage Access Framework, identificação por assinatura, SHA-256 em blocos |
| 3 | APK Analyzer e permissões |
| 4 | ZIP Analyzer com proteção contra ZIP bombs |
| 5 | EXE/DLL/ELF e PDF |
| 6 | Motor local de regras e classificação |
| 7 | Backend seguro e VirusTotal API v3 |
| 8 | Relatórios, histórico completo e detalhes técnicos |
| 9 | Testes, correções e desempenho |
| 10 | Identidade final, acessibilidade, APK de release |
