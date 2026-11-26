import { Readable } from 'node:stream';
import { randomBytes } from 'node:crypto';

/** Erro do VirusTotal (ou de rede) já traduzido para a resposta ao app. */
export class UpstreamError extends Error {
  constructor(status, code, message, retryAfter) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

const CATEGORY_KEYS = ['malicious', 'suspicious', 'undetected', 'harmless', 'timeout', 'confirmed-timeout', 'failure', 'type-unsupported'];

function nonNegative(value) {
  return Number.isInteger(value) && value >= 0 ? value : 0;
}

export function mapStats(raw = {}) {
  const s = {};
  for (const key of CATEGORY_KEYS) s[key] = nonNegative(raw[key]);
  return {
    malicious: s.malicious,
    suspicious: s.suspicious,
    undetected: s.undetected,
    harmless: s.harmless,
    timeout: s.timeout + s['confirmed-timeout'],
    failure: s.failure,
    type_unsupported: s['type-unsupported'],
  };
}

export function mapDetections(results = {}) {
  return Object.entries(results ?? {})
    .slice(0, 200)
    .map(([engine, r]) => ({
      engine: String(r?.engine_name ?? engine).slice(0, 80),
      category: String(r?.category ?? 'unknown').slice(0, 40),
      result: r?.result == null ? null : String(r.result).slice(0, 160),
    }));
}

/**
 * Cliente da VirusTotal API v3. Endpoints oficiais usados:
 * GET /files/{id}, POST /files, GET /files/upload_url (arquivos > 32 MB), GET /analyses/{id}.
 */
export class VirusTotalClient {
  constructor(config, fetchImpl = fetch) {
    this.config = config;
    this.fetch = fetchImpl;
  }

  async #request(path, { method = 'GET', body, headers = {}, timeoutMs, absoluteUrl } = {}) {
    const url = absoluteUrl ?? `${this.config.vtBaseUrl}${path}`;
    let response;
    try {
      response = await this.fetch(url, {
        method,
        body,
        duplex: body ? 'half' : undefined,
        headers: { 'x-apikey': this.config.apiKey, accept: 'application/json', ...headers },
        signal: AbortSignal.timeout(timeoutMs ?? this.config.requestTimeoutMs),
        redirect: 'error',
      });
    } catch (error) {
      if (error?.name === 'TimeoutError' || error?.name === 'AbortError') {
        throw new UpstreamError(504, 'upstream_timeout', 'o VirusTotal não respondeu a tempo');
      }
      throw new UpstreamError(502, 'upstream_unreachable', 'não foi possível conectar ao VirusTotal');
    }
    const text = await response.text();
    if (text.length > 4 * 1024 * 1024) throw new UpstreamError(502, 'upstream_invalid', 'resposta grande demais');
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      throw new UpstreamError(502, 'upstream_invalid', 'resposta inválida do VirusTotal');
    }
    return { status: response.status, json, retryAfter: response.headers.get('retry-after') };
  }

  #fail(status, retryAfter) {
    switch (status) {
      case 401:
        return new UpstreamError(502, 'upstream_auth', 'a chave da API do VirusTotal foi recusada');
      case 403:
        return new UpstreamError(403, 'upstream_forbidden', 'o VirusTotal recusou a operação para esta conta');
      case 429:
        return new UpstreamError(429, 'upstream_quota', 'cota do VirusTotal excedida', Number(retryAfter) || 60);
      default:
        return new UpstreamError(502, 'upstream_error', `erro do VirusTotal (HTTP ${status})`);
    }
  }

  async fileReport(sha256) {
    const { status, json, retryAfter } = await this.#request(`/files/${sha256}`);
    if (status === 404) return { status: 'not_found' };
    if (status !== 200) throw this.#fail(status, retryAfter);
    const attributes = json?.data?.attributes;
    const reportedSha = String(attributes?.sha256 ?? '').toLowerCase();
    if (!attributes || reportedSha !== sha256) throw new UpstreamError(502, 'upstream_invalid', 'relatório não corresponde ao hash');
    return {
      status: 'found',
      sha256,
      stats: mapStats(attributes.last_analysis_stats),
      detections: mapDetections(attributes.last_analysis_results),
      last_analysis_date: Number.isInteger(attributes.last_analysis_date) ? attributes.last_analysis_date : null,
      permalink: `https://www.virustotal.com/gui/file/${sha256}`,
    };
  }

  async uploadUrl() {
    const { status, json, retryAfter } = await this.#request('/files/upload_url');
    if (status !== 200) throw this.#fail(status, retryAfter);
    const url = json?.data;
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      throw new UpstreamError(502, 'upstream_invalid', 'URL de upload inválida');
    }
    const trusted = parsed.protocol === 'https:' && (parsed.hostname === 'www.virustotal.com' || parsed.hostname.endsWith('.virustotal.com'));
    if (!trusted && this.config.vtBaseUrl.startsWith('https://')) throw new UpstreamError(502, 'upstream_invalid', 'URL de upload não confiável');
    return url;
  }

  /** Envia o corpo recebido do app em streaming (multipart/form-data), sem gravar em disco. */
  async upload({ source, size, fileName, absoluteUrl }) {
    const boundary = `----aegis${randomBytes(12).toString('hex')}`;
    const safeName = fileName.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_').slice(0, 200) || 'arquivo';
    const head = Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${safeName}"\r\n` +
        'Content-Type: application/octet-stream\r\n\r\n',
    );
    const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
    async function* multipart() {
      yield head;
      for await (const chunk of source) yield chunk;
      yield tail;
    }
    const { status, json, retryAfter } = await this.#request('/files', {
      method: 'POST',
      absoluteUrl,
      body: Readable.from(multipart()),
      headers: {
        'content-type': `multipart/form-data; boundary=${boundary}`,
        'content-length': String(head.length + size + tail.length),
      },
      timeoutMs: this.config.uploadTimeoutMs,
    });
    if (status !== 200) throw this.#fail(status, retryAfter);
    const id = json?.data?.id;
    if (typeof id !== 'string' || !/^[A-Za-z0-9=_-]{1,200}$/.test(id)) throw new UpstreamError(502, 'upstream_invalid', 'identificador de análise inválido');
    return { analysis_id: id };
  }

  async analysis(id) {
    const { status, json, retryAfter } = await this.#request(`/analyses/${encodeURIComponent(id)}`);
    if (status === 404) throw new UpstreamError(404, 'not_found', 'análise não encontrada');
    if (status !== 200) throw this.#fail(status, retryAfter);
    const attributes = json?.data?.attributes;
    const state = attributes?.status;
    if (!['queued', 'in-progress', 'completed'].includes(state)) throw new UpstreamError(502, 'upstream_invalid', 'estado de análise desconhecido');
    const sha = json?.meta?.file_info?.sha256;
    return {
      status: state,
      sha256: typeof sha === 'string' ? sha.toLowerCase() : null,
      stats: state === 'completed' ? mapStats(attributes.stats) : null,
      detections: state === 'completed' ? mapDetections(attributes.results) : [],
      date: Number.isInteger(attributes.date) ? attributes.date : null,
    };
  }
}
