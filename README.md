# AEGIS SECURITY

Analisador de segurança de arquivos para Android nativo (Kotlin, Jetpack Compose, Material 3).
Análise estática local, sem executar nada, e reputação opcional via VirusTotal API v3 por meio de
um backend próprio — a chave da API nunca fica no app.

**Estado: Etapas 1 a 10 concluídas.** Detalhes em [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## O que o app faz

- Seleção pelo **Storage Access Framework** (sem permissão de armazenamento).
- Identificação do **formato real pelo conteúdo**: APK, ZIP, JAR, DEX, EXE, DLL, ELF, PDF.
- **SHA-256, SHA-1 e MD5** calculados em blocos de 64 KB durante a cópia para o cache privado.
- Analisadores: **APK** (manifesto, permissões, componentes exportados, assinaturas v1/v2+, certificados,
  empacotadores, código embutido), **ZIP** (Zip Slip, extensões duplas, nomes enganosos, duplicados,
  sobreposição, **proteção contra ZIP bombs** com limites configuráveis), **DEX** (checksum/assinatura),
  **PE** (cabeçalhos, seções, entropia, importações, overlay), **ELF** (segmentos, pilha executável, UPX),
  **PDF** (JavaScript, ações automáticas, /Launch, arquivos embutidos, nomes ofuscados, ObjStm) e
  **EICAR** (única assinatura local; nenhuma assinatura de malware é inventada).
- **Motor de regras** com 46 regras (id, descrição, categoria, severidade, evidência, justificativa).
- **Classificação baseada em evidências**: seguro segundo as verificações, suspeito, ameaça detectada,
  inconclusivo ou erro na análise. Falhas e inspeções parciais nunca resultam em "seguro".
- **VirusTotal**: consulta por hash e envio do arquivo com consentimentos separados, polling da análise,
  tratamento de 401/403/404/429, timeouts e falta de conexão.
- Histórico (Room), relatório completo, detalhes técnicos expansíveis, tema claro/escuro, limites de análise.

## Compilar

```bash
./gradlew assembleDebug                      # APK de debug
./gradlew assembleRelease                    # APK de release com R8
./gradlew :domain:test testDebugUnitTest     # testes unitários
./gradlew :core:database:connectedDebugAndroidTest   # instrumentados (emulador)
cd backend && npm test                       # testes do backend
```

O GitHub Actions executa tudo isso a cada push e publica os APKs como artefatos.

### Assinatura de release

Sem configuração, o APK de release é assinado com a chave de depuração do CI (instalável, mas
cada build pode ter assinatura diferente). Para uma chave definitiva, crie os segredos do repositório:

```bash
keytool -genkeypair -v -keystore aegis-release.jks -alias aegis -keyalg RSA -keysize 4096 -validity 10000
base64 -w0 aegis-release.jks   # valor de AEGIS_KEYSTORE_B64
```

Segredos: `AEGIS_KEYSTORE_B64`, `AEGIS_KEYSTORE_PASSWORD`, `AEGIS_KEY_ALIAS`, `AEGIS_KEY_PASSWORD`.
Guarde o keystore fora do repositório: sem ele não é possível publicar atualizações.

## Serviço online

Veja [`backend/README.md`](backend/README.md). Depois de subir o servidor com HTTPS, informe no app
(Configurações → Serviço online) o endereço e o token gerado por `npm run token`.

## Estrutura

```
app/                    Application, MainActivity, splash, navegação, segurança de rede
build-logic/convention/ convention plugins
backend/                servidor Node.js (VirusTotal API v3)
core/common             dispatchers e escopos
core/database           Room (v2, com migração)
core/designsystem       tema, cores semânticas, tipografia, logo, componentes
core/network            cliente HTTPS do backend (OkHttp)
core/security           identificação, analisadores, regras
core/ui                 apresentação de modelos de domínio
domain/                 modelos, contratos, casos de uso, classificador (Kotlin puro)
data/                   SAF, DataStore, Keystore, Room, repositório de reputação
feature/dashboard | scanner | reports | filedetails | history | settings
```
