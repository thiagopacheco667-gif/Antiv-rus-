# AEGIS backend (VirusTotal API v3)

Servidor mínimo, sem dependências externas (Node.js ≥ 20), que intermedeia o VirusTotal para o app.
A **chave da API fica somente aqui** — nunca no APK, em XML, BuildConfig ou recursos.

## Responsabilidades

| Item | Como |
|---|---|
| Guardar a chave | Variável de ambiente `VT_API_KEY` |
| Autenticar o app | `Authorization: Bearer <token>`; o servidor guarda só o SHA-256 do token e compara em tempo constante |
| Limites da conta | Modo `public`: 4/min e 500/dia (termos da API pública, uso não comercial). Modo `private`: `VT_RATE_PER_MINUTE`/`VT_RATE_PER_DAY` |
| Limite por cliente | `CLIENT_RATE_PER_MINUTE` (padrão 30) |
| Uploads | `POST /files`; acima de 32 MB obtém `GET /files/upload_url`. Máx. `MAX_UPLOAD_MB` (padrão 650). Streaming, sem gravar em disco. Pode ser desativado com `ALLOW_UPLOADS=false` |
| Relatórios | `GET /files/{sha256}` e `GET /analyses/{id}` |
| Erros | 401/403/404/429/5xx e timeouts traduzidos em códigos estáveis; falhas nunca viram "seguro" |
| HTTPS | Obrigatório: `TLS_CERT_FILE` + `TLS_KEY_FILE`, ou `TRUST_PROXY_TLS=1` atrás de proxy HTTPS (Caddy, Nginx, Cloudflare) |

## API para o app

| Método | Rota | Resposta |
|---|---|---|
| GET | `/v1/health` | `{status, mode, uploads_enabled, daily_quota_remaining}` |
| GET | `/v1/files/{sha256}` | `{status:"found", sha256, stats, detections, last_analysis_date, permalink}` ou `{status:"not_found"}` |
| POST | `/v1/files` (corpo binário, `Content-Length`, `X-File-Name`) | `{analysis_id}` |
| GET | `/v1/analyses/{id}` | `{status:"queued"|"in-progress"|"completed", sha256, stats, detections, date}` |

Erros: `{error, message}` com HTTP 400/401/403/404/411/413/429/502/504 e `Retry-After` quando aplicável.

## Como rodar

```bash
cd backend
npm run token                       # gera o token do app e o hash do servidor
cp .env.example .env                # preencha VT_API_KEY e AEGIS_CLIENT_TOKEN_HASHES
set -a; . ./.env; set +a
npm start
npm test                            # 13 testes com um VirusTotal simulado
```

No app: **Configurações → Serviço online** → endereço `https://…` e o token gerado.

## Docker

```bash
docker build -t aegis-backend .
docker run --env-file .env -p 8443:8443 aegis-backend
```
