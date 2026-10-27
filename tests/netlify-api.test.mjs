import test from 'node:test';
import assert from 'node:assert/strict';
import handler from '../netlify/functions/api.js';
import { onRequestPost as analyzePost, onRequestOptions as analyzeOptions } from '../functions/api/analyze.js';
import { _resetForTests } from '../functions/lib/guard.js';

const origin = 'https://rewrite.netlify.app';

function apiReq(path, { method = 'GET', headers = {}, body } = {}) {
  return new Request('https://rewrite.netlify.app' + path, {
    method,
    headers: { Origin: origin, ...headers },
    body
  });
}

test('analyze CORS: refleja origen Netlify, no *', async () => {
  const ctx = {
    request: apiReq('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: 'hello world this is a sentence. another one here.' })
    }),
    env: {}
  };
  const r = await analyzePost(ctx);
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('Access-Control-Allow-Origin'), origin);
  const opt = await analyzeOptions({ request: apiReq('/api/analyze', { method: 'OPTIONS' }), env: {} });
  assert.equal(opt.status, 204);
  assert.equal(opt.headers.get('Access-Control-Allow-Origin'), origin);
  const blocked = await analyzePost({
    request: new Request('https://rewrite.netlify.app/api/analyze', {
      method: 'POST',
      headers: { Origin: 'https://evil.example', 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: 'hello world this is a sentence.' })
    }),
    env: {}
  });
  assert.equal(blocked.headers.get('Access-Control-Allow-Origin'), null);
});

test('netlify adapter: OPTIONS rewrite CORS y cabeceras de seguridad', async () => {
  _resetForTests();
  const r = await handler(apiReq('/api/rewrite', { method: 'OPTIONS' }));
  assert.equal(r.status, 204);
  assert.equal(r.headers.get('Access-Control-Allow-Origin'), origin);
  assert.equal(r.headers.get('Access-Control-Allow-Methods'), 'POST, OPTIONS');
  assert.ok(r.headers.get('Access-Control-Allow-Headers').includes('Authorization'));
  assert.equal(r.headers.get('X-Frame-Options'), 'DENY');
  assert.ok(r.headers.get('Content-Security-Policy'));
});

test('netlify adapter: custom domain via URL env', async () => {
  _resetForTests();
  const custom = 'https://rewrite.example.com';
  const prev = process.env.URL;
  process.env.URL = custom;
  try {
    const r = await handler(new Request('https://rewrite.example.com/api/rewrite', {
      method: 'OPTIONS',
      headers: { Origin: custom }
    }));
    assert.equal(r.status, 204);
    assert.equal(r.headers.get('Access-Control-Allow-Origin'), custom);
  } finally {
    if (prev === undefined) delete process.env.URL;
    else process.env.URL = prev;
  }
});

test('netlify adapter: same-origin custom domain without ALLOWED_ORIGINS', async () => {
  _resetForTests();
  const custom = 'https://rewrite.custom.test';
  const r = await handler(new Request(custom + '/api/rewrite', {
    method: 'OPTIONS',
    headers: { Origin: custom }
  }));
  assert.equal(r.status, 204);
  assert.equal(r.headers.get('Access-Control-Allow-Origin'), custom);
});

test('netlify adapter: 404 y analyze POST', async () => {
  _resetForTests();
  const missing = await handler(apiReq('/api/nope'));
  assert.equal(missing.status, 404);
  const r = await handler(apiReq('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: 'hello world this is a sentence. another one here.' })
  }));
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.success, true);
  assert.ok(j.metrics.wordCount > 0);
  assert.equal(r.headers.get('Access-Control-Allow-Origin'), origin);
});

test('netlify adapter: login GET público', async () => {
  const r = await handler(apiReq('/api/auth/login'));
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.required, false);
  assert.equal(r.headers.get('Access-Control-Allow-Origin'), origin);
});
