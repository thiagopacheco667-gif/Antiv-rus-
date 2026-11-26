import http from 'node:http';
import https from 'node:https';
import { createHash, timingSafeEqual } from 'node:crypto';
import { RateLimiter } from './limits.mjs';
import { UpstreamError, VirusTotalClient } from './virustotal.mjs';

const SHA256 = /^[0-9a-fA-F]{64}$/;
const ANALYSIS_ID = /^[A-Za-z0-9=_-]{1,200}$/;

function send(res, status, body, headers = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'strict-transport-security': 'max-age=31536000',
    ...headers,
  });
  res.end(payload);
}

const error = (res, status, code, message, headers) => send(res, status, { error: code, message }, headers);

/** Compara o hash SHA-256 do token recebido com os autorizados, em tempo constante. */
function authorize(req, tokenHashes) {
  const header = req.headers.authorization ?? '';
  const match = /^Bearer ([A-Za-z0-9._~+/=-]{16,512})$/.exec(header);
  if (!match) return null;
  const digest = createHash('sha256').update(match[1]).digest();
  for (const hash of tokenHashes) {
    const expected = Buffer.from(hash, 'hex');
    if (expected.length === digest.length && timingSafeEqual(expected, digest)) return hash;
  }
  return null;
}

/** Garante que o corpo enviado tenha exatamente o tamanho declarado. */
async function* exactly(req, size) {
  let received = 0;
  for await (const chunk of req) {
    received += chunk.length;
    if (received > size) throw new UpstreamError(400, 'size_mismatch', 'corpo maior que o Content-Length');
    yield chunk;
  }
  if (received !== size) throw new UpstreamError(400, 'size_mismatch', 'corpo incompleto');
}

export function createApp(config, { fetchImpl = fetch, now = () => Date.now(), log = console } = {}) {
  const vt = new VirusTotalClient(config, fetchImpl);
  const quota = new RateLimiter({ perMinute: config.perMinute, perDay: config.perDay, now });
  const clients = new Map();

  function clientLimiter(id) {
    if (!clients.has(id)) clients.set(id, new RateLimiter({ perMinute: config.clientPerMinute, now }));
    return clients.get(id);
  }

  function takeQuota(res) {
    const result = quota.take();
    if (!result.allowed) {
      error(res, 429, result.reason, 'limite de consultas ao VirusTotal atingido', { 'retry-after': String(result.retryAfter) });
      return false;
    }
    return true;
  }

  async function handle(req, res) {
    const url = new URL(req.url ?? '/', 'https://aegis.local');
    const parts = url.pathname.split('/').filter(Boolean);

    const client = authorize(req, config.tokenHashes);
    if (!client) return error(res, 401, 'unauthorized', 'token de acesso inválido');
    const perClient = clientLimiter(client).take();
    if (!perClient.allowed) return error(res, 429, 'client_rate', 'muitas requisições', { 'retry-after': String(perClient.retryAfter) });

    if (parts[0] !== 'v1') return error(res, 404, 'not_found', 'rota inexistente');

    if (req.method === 'GET' && parts.length === 2 && parts[1] === 'health') {
      return send(res, 200, { status: 'ok', mode: config.mode, uploads_enabled: config.allowUploads, daily_quota_remaining: quota.remainingToday() });
    }

    if (req.method === 'GET' && parts.length === 3 && parts[1] === 'files') {
      const sha256 = parts[2];
      if (!SHA256.test(sha256)) return error(res, 400, 'invalid_hash', 'SHA-256 inválido');
      if (!takeQuota(res)) return;
      return send(res, 200, await vt.fileReport(sha256.toLowerCase()));
    }

    if (req.method === 'POST' && parts.length === 2 && parts[1] === 'files') {
      if (!config.allowUploads) return error(res, 403, 'uploads_disabled', 'envio de arquivos desativado neste servidor');
      const size = Number.parseInt(req.headers['content-length'] ?? '', 10);
      if (!Number.isFinite(size) || size <= 0) return error(res, 411, 'length_required', 'Content-Length obrigatório');
      if (size > config.maxUploadBytes) return error(res, 413, 'too_large', 'arquivo maior que o permitido');
      const fileName = String(req.headers['x-file-name'] ?? 'arquivo');
      if (!takeQuota(res)) return;
      let absoluteUrl;
      if (size > config.directUploadLimit) {
        if (!takeQuota(res)) return;
        absoluteUrl = await vt.uploadUrl();
      }
      return send(res, 200, await vt.upload({ source: exactly(req, size), size, fileName, absoluteUrl }));
    }

    if (req.method === 'GET' && parts.length === 3 && parts[1] === 'analyses') {
      if (!ANALYSIS_ID.test(parts[2])) return error(res, 400, 'invalid_id', 'identificador inválido');
      if (!takeQuota(res)) return;
      return send(res, 200, await vt.analysis(parts[2]));
    }

    return error(res, 404, 'not_found', 'rota inexistente');
  }

  return async (req, res) => {
    try {
      await handle(req, res);
    } catch (err) {
      if (err instanceof UpstreamError) {
        const headers = err.retryAfter ? { 'retry-after': String(err.retryAfter) } : {};
        if (!res.headersSent) error(res, err.status, err.code, err.message, headers);
      } else {
        log.error?.('erro inesperado', err?.message);
        if (!res.headersSent) error(res, 500, 'internal', 'erro interno');
      }
      req.resume();
    }
  };
}

export function startServer(config, options) {
  const app = createApp(config, options);
  const server = config.tls ? https.createServer({ ...config.tls, minVersion: 'TLSv1.2' }, app) : http.createServer(app);
  server.requestTimeout = config.uploadTimeoutMs;
  server.headersTimeout = 30_000;
  return server;
}
