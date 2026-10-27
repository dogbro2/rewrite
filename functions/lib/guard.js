// Protección barata para los endpoints que llaman a la IA (/api/rewrite, /api/humanize, /api/tools).
// Sin KV ni D1: no añade lecturas ni escrituras facturables.
//  · Origen: solo navegadores en rewrite.trujillomingorance.com, *.trujillomingorance.com o las vistas previas de Pages.
//  · Tamaño: el texto se limita a MAX_CHARS (evita peticiones gigantes que gastan neuronas).
//  · Ritmo: tope por IP y por instancia (ventana deslizante en memoria). No es un límite global,
//    pero corta los bucles y los scripts que repiten la misma petición.

import { verifyToken, requireAuth } from './auth.js';

export const MAX_CHARS = 12000;
const WINDOW_MS = 10 * 60 * 1000;
const MAX_HITS = 30;
const hits = new Map();

export function allowedOrigin(origin, extraOrigins = [], requestUrl) {
  if (!origin) return '';
  try {
    const u = new URL(origin);
    const h = u.hostname.toLowerCase();
    const isLocal = h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h === '::1';
    if (isLocal) {
      if (u.protocol === 'http:' || u.protocol === 'https:') return u.origin;
      return '';
    }
    if (u.protocol !== 'https:') return '';
    if (requestUrl) {
      try {
        if (new URL(requestUrl).origin === u.origin) return u.origin;
      } catch (_) {}
    }
    if (h === 'trujillomingorance.com' || h.endsWith('.trujillomingorance.com')) return u.origin;
    if (h.endsWith('.pages.dev')) return u.origin;
    if (h.endsWith('.netlify.app') || h.endsWith('.netlify.com')) return u.origin;
    if (h.endsWith('.monkeycode-ai.live') || h.endsWith('.monkeycode-ai.online')) return u.origin;
    for (const raw of extraOrigins) {
      const value = String(raw).trim();
      if (!value) continue;
      if (value.startsWith('*.') && (h === value.slice(2) || h.endsWith(value.slice(1)))) return u.origin;
      try {
        const allowed = new URL(value);
        if (allowed.origin === u.origin) return u.origin;
      } catch (_) {}
    }
  } catch (_) {}
  return '';
}

function extraOriginsFrom(env) {
  const raw = env && env.ALLOWED_ORIGINS;
  const listed = raw ? String(raw).split(',').map((s) => s.trim()).filter(Boolean) : [];
  const auto = [];
  if (env) {
    for (const key of ['URL', 'DEPLOY_PRIME_URL', 'DEPLOY_URL']) {
      if (env[key]) auto.push(String(env[key]).trim());
    }
  }
  return listed.concat(auto);
}

export function corsFor(request, extra = {}, env) {
  const o = allowedOrigin(request.headers.get('Origin'), extraOriginsFrom(env), request.url);
  return { ...(o ? { 'Access-Control-Allow-Origin': o } : {}), Vary: 'Origin', ...extra };
}

export function rateLimited(request, now = Date.now()) {
  const forwarded = (request.headers.get('x-forwarded-for') || '').split(',')[0].trim();
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('x-nf-client-connection-ip') || forwarded || 'local';
  const list = (hits.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  if (list.length >= MAX_HITS) { hits.set(ip, list); return Math.ceil((WINDOW_MS - (now - list[0])) / 1000); }
  list.push(now);
  hits.set(ip, list);
  if (hits.size > 5000) hits.clear();
  return 0;
}

// Devuelve una Response de rechazo o null si la petición puede seguir.
export async function guard(request, headers, env) {
  if (!allowedOrigin(request.headers.get('Origin'), extraOriginsFrom(env), request.url)) {
    return new Response(JSON.stringify({ error: 'Origen no permitido.' }), { status: 403, headers });
  }
  const wait = rateLimited(request);
  if (wait) {
    return new Response(JSON.stringify({ error: 'Demasiadas peticiones. Prueba de nuevo en unos minutos.' }), { status: 429, headers: { ...headers, 'Retry-After': String(wait) } });
  }
  if (requireAuth(env)) {
    const authHeader = request.headers.get('Authorization') || '';
    if (!authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Inicia sesión.' }), { status: 401, headers });
    }
    const token = authHeader.slice('Bearer '.length);
    const secret = env.APP_SECRET || env.APP_PASSWORD;
    const ok = await verifyToken(token, env.APP_USERNAME, secret);
    if (!ok) {
      return new Response(JSON.stringify({ error: 'Sesión no válida.' }), { status: 401, headers });
    }
  }
  return null;
}

export function tooLong(text) {
  return typeof text === 'string' && text.length > MAX_CHARS;
}

export function _resetForTests() { hits.clear(); }
