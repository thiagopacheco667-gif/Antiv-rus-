import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { loadConfig } from '../src/config.mjs';
import { startServer } from '../src/server.mjs';

const TOKEN = 'token-de-teste-com-tamanho-suficiente';
const SHA = 'a'.repeat(64);
let vtCalls = [];
let vtBehavior = {};
let vt;
let aegis;
let base;

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

function json(res, status, body, headers = {}) {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

/** Servidor falso que imita as respostas documentadas da VirusTotal API v3. */
function fakeVirusTotal() {
  return http.createServer(async (req, res) => {
    let size = 0;
    for await (const chunk of req) size += chunk.length;
    vtCalls.push({ method: req.method, url: req.url, key: req.headers['x-apikey'], size });
    const override = vtBehavior[`${req.method} ${req.url}`];
    if (override) return json(res, override.status, override.body ?? {}, override.headers);
    if (req.url === `/files/${SHA}`) {
      return json(res, 200, {
        data: {
          attributes: {
            sha256: SHA,
            last_analysis_date: 1700000000,
            last_analysis_stats: { malicious: 2, suspicious: 1, undetected: 60, harmless: 0, 'type-unsupported': 5, timeout: 1, 'confirmed-timeout': 1, failure: 0 },
            last_analysis_results: { EngineA: { category: 'malicious', result: 'Trojan.Test', engine_name: 'EngineA' } },
          },
        },
      });
    }
    if (req.url.startsWith('/files/') && req.method === 'GET' && req.url !== '/files/upload_url') return json(res, 404, { error: { code: 'NotFoundError' } });
    if (req.url === '/files/upload_url') return json(res, 200, { data: `http://127.0.0.1:${vt.address().port}/big-upload` });
    if (req.method === 'POST' && (req.url === '/files' || req.url === '/big-upload')) return json(res, 200, { data: { type: 'analysis', id: 'YWJjMTIz' } });
    if (req.url === '/analyses/YWJjMTIz') {
      return json(res, 200, {
        data: { attributes: { status: 'completed', date: 1700000001, stats: { malicious: 0, undetected: 70 }, results: {} } },
        meta: { file_info: { sha256: SHA } },
      });
    }
    json(res, 500, {});
  });
}

async function startAegis(extraEnv = {}) {
  const config = loadConfig({
    VT_API_KEY: 'chave-secreta',
    AEGIS_CLIENT_TOKEN_HASHES: createHash('sha256').update(TOKEN).digest('hex'),
    VT_BASE_URL: `http://127.0.0.1:${vt.address().port}`,
    VT_ALLOW_INSECURE_FOR_TESTS: '1',
    TRUST_PROXY_TLS: '1',
    VT_MODE: 'private',
    ...extraEnv,
  });
  config.directUploadLimit = 1024; // força o fluxo de upload_url em testes pequenos
  const server = startServer(config, { log: { error() {} } });
  const port = await listen(server);
  return { server, base: `http://127.0.0.1:${port}` };
}

before(async () => {
  vt = fakeVirusTotal();
  await listen(vt);
  ({ server: aegis, base } = await startAegis());
});

after(() => {
  aegis.close();
  vt.close();
});

const auth = { authorization: `Bearer ${TOKEN}` };

test('rejeita requisições sem token válido', async () => {
  assert.equal((await fetch(`${base}/v1/health`)).status, 401);
  assert.equal((await fetch(`${base}/v1/health`, { headers: { authorization: 'Bearer token-errado-mas-longo' } })).status, 401);
});

test('health não expõe a chave e informa o modo', async () => {
  const body = await (await fetch(`${base}/v1/health`, { headers: auth })).json();
  assert.equal(body.mode, 'private');
  assert.equal(JSON.stringify(body).includes('chave-secreta'), false);
});

test('consulta de hash mapeia estatísticas e detecções', async () => {
  vtCalls = [];
  const res = await fetch(`${base}/v1/files/${SHA}`, { headers: auth });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.status, 'found');
  assert.deepEqual(body.stats, { malicious: 2, suspicious: 1, undetected: 60, harmless: 0, timeout: 2, failure: 0, type_unsupported: 5 });
  assert.equal(body.detections[0].result, 'Trojan.Test');
  assert.equal(vtCalls[0].key, 'chave-secreta');
});

test('hash desconhecido retorna not_found (nunca "seguro")', async () => {
  const body = await (await fetch(`${base}/v1/files/${'b'.repeat(64)}`, { headers: auth })).json();
  assert.deepEqual(body, { status: 'not_found' });
});

test('hash inválido é rejeitado sem consultar o VirusTotal', async () => {
  vtCalls = [];
  assert.equal((await fetch(`${base}/v1/files/nao-e-hash`, { headers: auth })).status, 400);
  assert.equal(vtCalls.length, 0);
});

test('cota do VirusTotal excedida vira 429 com Retry-After', async () => {
  vtBehavior = { [`GET /files/${'c'.repeat(64)}`]: { status: 429, headers: { 'retry-after': '30' } } };
  const res = await fetch(`${base}/v1/files/${'c'.repeat(64)}`, { headers: auth });
  assert.equal(res.status, 429);
  assert.equal(res.headers.get('retry-after'), '30');
  vtBehavior = {};
});

test('chave recusada pelo VirusTotal não é repassada como 401 ao app', async () => {
  vtBehavior = { [`GET /files/${'d'.repeat(64)}`]: { status: 401 } };
  const res = await fetch(`${base}/v1/files/${'d'.repeat(64)}`, { headers: auth });
  assert.equal(res.status, 502);
  assert.equal((await res.json()).error, 'upstream_auth');
  vtBehavior = {};
});

test('upload pequeno vai direto para POST /files', async () => {
  vtCalls = [];
  const res = await fetch(`${base}/v1/files`, { method: 'POST', headers: { ...auth, 'x-file-name': 'teste.bin' }, body: Buffer.alloc(512, 1) });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { analysis_id: 'YWJjMTIz' });
  assert.deepEqual(vtCalls.map((c) => `${c.method} ${c.url}`), ['POST /files']);
  assert.ok(vtCalls[0].size > 512, 'corpo multipart contém o arquivo');
});

test('upload grande usa upload_url', async () => {
  vtCalls = [];
  const res = await fetch(`${base}/v1/files`, { method: 'POST', headers: auth, body: Buffer.alloc(4096, 2) });
  assert.equal(res.status, 200);
  assert.deepEqual(vtCalls.map((c) => `${c.method} ${c.url}`), ['GET /files/upload_url', 'POST /big-upload']);
});

test('consulta de análise até a conclusão', async () => {
  const body = await (await fetch(`${base}/v1/analyses/YWJjMTIz`, { headers: auth })).json();
  assert.equal(body.status, 'completed');
  assert.equal(body.sha256, SHA);
  assert.equal(body.stats.undetected, 70);
});

test('uploads podem ser desativados', async () => {
  const { server, base: other } = await startAegis({ ALLOW_UPLOADS: 'false' });
  const res = await fetch(`${other}/v1/files`, { method: 'POST', headers: auth, body: Buffer.alloc(10) });
  assert.equal(res.status, 403);
  server.close();
});

test('modo público respeita 4 consultas por minuto', async () => {
  const { server, base: pub } = await startAegis({ VT_MODE: 'public' });
  const statuses = [];
  for (let i = 0; i < 5; i++) statuses.push((await fetch(`${pub}/v1/files/${'e'.repeat(64)}`, { headers: auth })).status);
  assert.deepEqual(statuses, [200, 200, 200, 200, 429]);
  server.close();
});

test('servidor não inicia sem HTTPS nem segredos', () => {
  assert.throws(() => loadConfig({ AEGIS_CLIENT_TOKEN_HASHES: 'a'.repeat(64), TRUST_PROXY_TLS: '1' }), /VT_API_KEY/);
  assert.throws(() => loadConfig({ VT_API_KEY: 'x', AEGIS_CLIENT_TOKEN_HASHES: 'a'.repeat(64) }), /HTTPS/);
});
