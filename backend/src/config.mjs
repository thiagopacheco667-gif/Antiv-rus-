import { readFileSync } from 'node:fs';

const SHA256_HEX = /^[0-9a-f]{64}$/;

function int(value, fallback, name) {
  if (value === undefined || value === '') return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) throw new Error(`${name} deve ser um inteiro positivo`);
  return parsed;
}

/**
 * Lê a configuração do ambiente. Nenhum segredo tem valor padrão: o servidor não inicia sem eles.
 * Limites públicos do VirusTotal: 4 requisições/minuto e 500/dia (uso não comercial).
 */
export function loadConfig(env = process.env) {
  const apiKey = env.VT_API_KEY?.trim();
  if (!apiKey) throw new Error('VT_API_KEY não definida');

  const tokenHashes = (env.AEGIS_CLIENT_TOKEN_HASHES ?? '')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  if (tokenHashes.length === 0) throw new Error('AEGIS_CLIENT_TOKEN_HASHES não definida (use npm run token)');
  for (const hash of tokenHashes) {
    if (!SHA256_HEX.test(hash)) throw new Error('AEGIS_CLIENT_TOKEN_HASHES deve conter hashes SHA-256 em hexadecimal');
  }

  const mode = (env.VT_MODE ?? 'public').toLowerCase();
  if (mode !== 'public' && mode !== 'private') throw new Error('VT_MODE deve ser "public" ou "private"');

  const vtBaseUrl = (env.VT_BASE_URL ?? 'https://www.virustotal.com/api/v3').replace(/\/+$/, '');
  if (!vtBaseUrl.startsWith('https://') && env.VT_ALLOW_INSECURE_FOR_TESTS !== '1') {
    throw new Error('VT_BASE_URL deve usar HTTPS');
  }

  const tlsCert = env.TLS_CERT_FILE;
  const tlsKey = env.TLS_KEY_FILE;
  const behindProxy = env.TRUST_PROXY_TLS === '1';
  if (!(tlsCert && tlsKey) && !behindProxy) {
    throw new Error('HTTPS obrigatório: defina TLS_CERT_FILE e TLS_KEY_FILE, ou TRUST_PROXY_TLS=1 atrás de um proxy HTTPS');
  }

  return {
    apiKey,
    tokenHashes,
    mode,
    vtBaseUrl,
    allowUploads: (env.ALLOW_UPLOADS ?? 'true').toLowerCase() === 'true',
    perMinute: mode === 'public' ? 4 : int(env.VT_RATE_PER_MINUTE, 1000, 'VT_RATE_PER_MINUTE'),
    perDay: mode === 'public' ? 500 : int(env.VT_RATE_PER_DAY, 1_000_000, 'VT_RATE_PER_DAY'),
    clientPerMinute: int(env.CLIENT_RATE_PER_MINUTE, 30, 'CLIENT_RATE_PER_MINUTE'),
    maxUploadBytes: int(env.MAX_UPLOAD_MB, 650, 'MAX_UPLOAD_MB') * 1024 * 1024,
    directUploadLimit: 32 * 1024 * 1024,
    requestTimeoutMs: int(env.REQUEST_TIMEOUT_MS, 30_000, 'REQUEST_TIMEOUT_MS'),
    uploadTimeoutMs: int(env.UPLOAD_TIMEOUT_MS, 15 * 60_000, 'UPLOAD_TIMEOUT_MS'),
    host: env.HOST ?? '0.0.0.0',
    port: int(env.PORT, 8443, 'PORT'),
    tls: tlsCert && tlsKey ? { cert: readFileSync(tlsCert), key: readFileSync(tlsKey) } : null,
  };
}
