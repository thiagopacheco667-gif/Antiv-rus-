# AEGIS SECURITY — Arquitetura (Etapa 1)

## 1. Visão geral

Clean Architecture + MVVM, com fluxo unidirecional de dados:

```
UI (Compose) ──eventos──▶ ViewModel ──▶ UseCase ──▶ Repository (interface, :domain)
     ▲                       │                           │
     └──── StateFlow<UiState>┘          implementação em :data ──▶ Room / DataStore
```

- **:domain** é Kotlin puro (sem Android). Contém modelos, contratos de repositório,
  casos de uso e os **contratos dos mecanismos de análise** (`AnalysisEngine`).
- **:data** implementa os repositórios (Room para histórico, DataStore para preferências).
- **Features** dependem só de `:domain`, `:core:designsystem` e `:core:ui`. Nunca de outra feature.
- **:app** monta o grafo Hilt e a navegação.

## 2. Módulos

| Módulo | Tipo | Responsabilidade | Estado |
|---|---|---|---|
| `:app` | Android app | `Application`, `MainActivity`, splash, NavHost | ✅ |
| `:core:common` | Android lib | Dispatchers e escopo de aplicação injetáveis | ✅ |
| `:core:database` | Android lib | Room: `AegisDatabase`, `ScanRecordDao`, entidade | ✅ |
| `:core:designsystem` | Android lib | Tema, cores semânticas, tipografia, logo, componentes | ✅ |
| `:core:ui` | Android lib | Apresentação de modelos de domínio (veredito, formato), formatadores | ✅ |
| `:core:security` | Android lib | Registro dos mecanismos de análise (multibinding) | ✅ registro vazio |
| `:core:network` | Android lib | OkHttp + cliente do backend AEGIS | Etapa 7 |
| `:domain` | JVM lib | `model/`, `repository/`, `usecase/`, `analysis/` | ✅ |
| `:data` | Android lib | `local/` (DataStore), `repository/` (Room), `mapper/` | ✅ (`remote/` na Etapa 7) |
| `:feature:dashboard` | feature | Painel inicial | ✅ |
| `:feature:scanner` | feature | Seleção de arquivos e informações de análise | ✅ informativo; SAF na Etapa 2 |
| `:feature:history` | feature | Histórico com exclusão individual e limpeza | ✅ |
| `:feature:settings` | feature | Tema, privacidade, limpeza de histórico, sobre | ✅ parcial (itens futuros marcados indisponíveis) |
| `:feature:filedetails` | feature | Detalhes técnicos | Etapa 8 |
| `:feature:reports` | feature | Resultado / relatório | Etapa 8 |

Módulos só são criados quando passam a ter conteúdo real — nenhum módulo vazio "de fachada".

Grafo de dependências:

```
:app ─▶ :feature:* ─▶ :core:ui ─▶ :core:designsystem
  │          └──────▶ :domain ◀── :core:ui
  ├──▶ :data ─▶ :core:database, :core:common, :domain
  └──▶ :core:security ─▶ :domain
```

## 3. Mecanismos de análise extensíveis

`AnalysisEngine` (em `:domain`) é o contrato único:

```kotlin
interface AnalysisEngine {
    val descriptor: EngineDescriptor          // id, nome, formatos suportados
    suspend fun analyze(input: AnalysisInput): EngineResult  // Completed | Failed | NotApplicable
}
```

Cada mecanismo novo é registrado em `:core:security` com `@Binds @IntoSet`, sem tocar no resto
do app. `GetScannerStatusUseCase` lê o conjunto real: **com zero mecanismos, o dashboard e o
scanner informam que a análise está indisponível**, em vez de simular qualquer resultado.

`Finding` já traz os campos exigidos para o motor de regras (Etapa 6): identificador, descrição,
categoria, severidade, evidência e justificativa técnica.

## 4. Decisões arquiteturais

1. **Convention plugins (`build-logic/`)**: SDKs, Java 17, Compose, Hilt e Room configurados
   uma vez; cada módulo tem um `build.gradle.kts` de poucas linhas.
2. **Version catalog** (`gradle/libs.versions.toml`): fonte única de versões.
3. **Navegação tipada** (Navigation Compose 2.8 + kotlinx.serialization): rotas são objetos
   `@Serializable` expostos pelas features via `NavGraphBuilder.xxxScreen()`.
4. **Enums persistidos por nome**: valores ilegíveis vindos do banco viram `INCONCLUSIVE`
   (veredito) ou `UNKNOWN` — **nunca** "seguro". Coberto por teste.
5. **Erros de leitura não viram zero**: se o histórico falhar, o dashboard mostra erro em vez
   de "0 ameaças".
6. **Privacidade por construção nesta etapa**: a permissão `INTERNET` é removida explicitamente
   do manifesto; `allowBackup=false` e `data_extraction_rules.xml` excluem os dados de backup em
   nuvem e de transferência entre aparelhos. A tela de configurações afirma isso porque é verdade
   no build.
7. **Tema escuro padrão, cores dinâmicas desligadas** para preservar a identidade AEGIS.
8. **Cores semânticas próprias** (`AegisStatusColors`): esmeralda (seguro segundo as verificações),
   âmbar (suspeito), vermelho discreto (ameaça), ardósia (inconclusivo), lavanda (erro de análise),
   violeta (informação). Cor nunca é o único portador de significado — sempre há texto.
9. **R8 desligado no release** até a Etapa 10, onde será habilitado e validado com testes.

## 5. Dependências

| Biblioteca | Versão | Uso |
|---|---|---|
| Android Gradle Plugin | 8.7.3 | Build Android (compileSdk/targetSdk 35) |
| Gradle (wrapper) | 8.11.1 | Exigido ≥ 8.9 pelo AGP 8.7 |
| Kotlin + Compose compiler plugin | 2.1.0 | Linguagem e compilador Compose |
| KSP | 2.1.0-1.0.29 | Processamento de anotações (Hilt, Room) |
| Hilt (Dagger) | 2.54 | Injeção de dependências |
| hilt-navigation-compose | 1.2.0 | `hiltViewModel()` |
| Compose BOM | 2024.12.01 | UI, Material 3, ícones |
| Navigation Compose | 2.8.5 | Navegação tipada |
| Lifecycle | 2.8.7 | ViewModel, `collectAsStateWithLifecycle` |
| Activity Compose | 1.9.3 | `setContent`, edge-to-edge |
| Core KTX / SplashScreen | 1.15.0 / 1.0.1 | Utilidades, splash compatível com API 26+ |
| Room | 2.6.1 | Histórico |
| DataStore Preferences | 1.1.1 | Preferências |
| Coroutines | 1.9.0 | Assincronia e Flow |
| kotlinx.serialization | 1.7.3 | Rotas de navegação; JSON na Etapa 7 |
| OkHttp | 4.12.0 | **Declarada, ainda não usada** (Etapa 7) |
| WorkManager | 2.10.0 | **Declarada, ainda não usada** (Etapa 7) |
| JUnit 4 / AndroidX Test | 4.13.2 / 1.6.x | Testes |

Todas são mantidas por Google, JetBrains ou Square. Para subir `targetSdk` além de 35, atualize o
AGP com o Upgrade Assistant do Android Studio e ajuste `AegisBuildConfig`.

## 6. Design system

- **Cores**: grafite `#0B0D10`, carvão `#12151A…#2A313C`, violeta `#8B7CFF`, azul elétrico `#4DA3FF`.
- **Formas**: cantos de 6 a 24dp (cards 16dp).
- **Tipografia**: sans-serif do sistema com pesos ajustados; `AegisMonospace` para hashes.
- **Componentes**: `AegisLogo`, `AegisWordmark`, `AegisCard`, `AegisPrimaryButton` (gradiente),
  `StatusBadge`, `StatusOrb` (pulsa só quando há mecanismos ativos), `AegisTopBar`,
  `SectionHeader`, `EmptyState`.
- **Ícone e splash**: vetor original (escudo com monograma "A"), adaptativo e monocromático.

## 7. Testes da Etapa 1

| Teste | Tipo | Verifica |
|---|---|---|
| `ObserveDashboardSummaryUseCaseTest` | unitário | Resumo vazio sem dados inventados; contagem só de ameaças confirmadas; ordem; limite |
| `GetScannerStatusUseCaseTest` | unitário | Zero mecanismos ⇒ não operacional; formatos; ids duplicados rejeitados |
| `ScanRecordMapperTest` | unitário | Ida e volta; veredito corrompido **nunca** vira seguro |
| `AegisFormattersTest` | unitário | Tamanhos binários, hash abreviado |
| `ScanRecordDaoTest` | instrumentado | Ordenação, limite, contagem por veredito, exclusão |
