# AEGIS SECURITY — Arquitetura

## 1. Visão geral

Clean Architecture + MVVM com fluxo unidirecional:

```
UI (Compose) ─eventos─▶ ViewModel ─▶ UseCase (:domain) ─▶ Repository / AnalysisEngine (interfaces)
     ▲                     │                                   │
     └── StateFlow<UiState>┘          :data (SAF, Room, DataStore, Keystore, backend) · :core:security (motores)
```

## 2. Módulos

| Módulo | Responsabilidade |
|---|---|
| `:app` | Hilt, splash, NavHost, manifesto, `network_security_config` |
| `:domain` | Modelos (`AnalysisReport`, `Verdict`...), contratos (`AnalysisEngine`, `FormatIdentifier`, `RuleEngine`, `PatternScanner`, `FileStager`, `ReputationRepository`), `RiskClassifier`, casos de uso (`AnalyzeFileUseCase`...) |
| `:core:security` | Identificação por assinatura, analisadores APK/ZIP/DEX/PE/ELF/PDF/EICAR, motor e conjuntos de regras, registro Hilt |
| `:core:network` | `AegisBackendClient` (OkHttp, só HTTPS, limites de resposta, validação de contrato) |
| `:core:database` | Room v2 (`report_json`), migração 1→2 |
| `:data` | `SafFileStager`, `DataStoreUserPreferencesRepository`, `KeystoreTokenCipher`, `BackendReputationRepository`, `RoomScanHistoryRepository` |
| `:core:designsystem` / `:core:ui` | Tema, componentes, apresentação de vereditos e severidades |
| `:feature:*` | dashboard, scanner (seleção + Analisando), reports (Resultado + VirusTotal), filedetails, history, settings |
| `backend/` | Node.js sem dependências: guarda a chave, autentica, limita e traduz a VirusTotal API v3 |

## 3. Fluxo de análise

1. **Identificando arquivo** — metadados do provedor SAF e cabeçalho (8 KB) → formato real.
2. **Calculando hash** — cópia para `cacheDir/scan` com SHA-256/SHA-1/MD5 em blocos; progresso por bytes lidos.
3. **Inspecionando estrutura** — refinamento (ZIP→APK/JAR, PE→DLL) e cada `AnalysisEngine` aplicável.
4. **Verificando indicadores locais** — `RuleEngine` sobre os fatos extraídos.
5. **Reputação online** — marcada como não autorizada; oferecida depois no Resultado, com consentimento.
6. **Finalizando relatório** — classificação, gravação no histórico, cópia temporária apagada.

O fluxo é cancelável (cancelamento cooperativo); cancelado, nada é salvo e a cópia é removida.

## 4. Classificação (RiskClassifier)

| Situação | Veredito |
|---|---|
| Assinatura verificável (EICAR) | Ameaça detectada |
| Indicador de severidade alta/crítica | Suspeito |
| Arquivo vazio, formato sem inspeção estrutural, mecanismo com falha ou **inspeção parcial** | Inconclusivo |
| Arquivo ilegível ou erro de leitura | Erro na análise |
| Inspeção completa sem indicadores elevados | Seguro segundo as verificações (sempre com o aviso de que não há garantia) |
| VirusTotal: ≥ 3 mecanismos "malicious" | Ameaça detectada |
| VirusTotal: 1–2 "malicious" ou qualquer "suspicious" | No mínimo Suspeito |
| VirusTotal sem detecção, hash desconhecido ou falha | Mantém o resultado local |

Não há porcentagens; o limiar de 3 mecanismos independentes evita tratar falsos positivos isolados como ameaça.

## 5. Privacidade e segurança

- Análise local como padrão; nenhuma execução; nenhuma exclusão ou modificação de arquivos.
- Consentimento para compartilhar o hash; **confirmação separada com caixa de reconhecimento** para upload.
- Upload exige o mesmo SHA-256 da análise (o arquivo é reverificado); o URI do SAF não é persistido.
- Token do backend cifrado com AES-256-GCM (Android Keystore); chave do VirusTotal só no servidor.
- HTTPS obrigatório (interceptor + `cleartextTrafficPermitted=false`, apenas CAs do sistema).
- Respostas validadas (tamanho máximo, esquema, hash correspondente, contagens não negativas).
- Limites configuráveis: tamanho do arquivo, entradas, total descompactado, razão de compressão,
  profundidade, conteúdo varrido; total de arquivos aninhados limitado a 100.
- Dados fora de backups; histórico só com metadados e evidências.

## 6. Testes

| Módulo | Cobertura |
|---|---|
| `:domain` | Orquestração (arquivo inacessível, inexistente, vazio, muito grande, sem extensão, mecanismo que falha, cancelamento, ordem das etapas), classificador, dashboard |
| `:core:security` | Identificação (extensão falsa, sem extensão, vazio), ZIP válido/malformado/suspeito/bomba/aninhado/limites, PE válido/W+X/entrada inválida/truncado, ELF, PDF (metadados, JS ofuscado, ObjStm), EICAR, APK (permissões, combinações, assinatura ausente, payloads) |
| `:data` | Repositório de reputação: sem configuração, sem conexão, 429, 401/403, hash desconhecido, resposta inválida, upload de arquivo diferente, polling, upload cancelado; mapeamento do histórico |
| `:core:database` (instrumentado) | DAO e migração 1→2 |
| `backend/` | 13 testes com VirusTotal simulado |

Todos os arquivos de teste são sintéticos e inofensivos; nenhum malware real é usado.

## 7. Dependências

AGP 8.7.3 · Gradle 8.11.1 · Kotlin 2.1.0 · KSP 2.1.0-1.0.29 · Hilt 2.54 · Compose BOM 2024.12.01 ·
Navigation 2.8.5 · Lifecycle 2.8.7 · Room 2.6.1 · DataStore 1.1.1 · OkHttp 4.12.0 ·
kotlinx.serialization 1.7.3 · Coroutines 1.9.0. compileSdk/targetSdk 35, minSdk 26.
Todas mantidas por Google, JetBrains ou Square. YARA: interface `PatternScanner` preparada, sem
implementação registrada — a UI mostra "não integrado".
