import { onRequestPost as rewritePost, onRequestOptions as rewriteOptions } from '../../functions/api/rewrite.js';
import { onRequestPost as humanizePost, onRequestOptions as humanizeOptions } from '../../functions/api/humanize.js';
import { onRequestPost as toolsPost, onRequestOptions as toolsOptions } from '../../functions/api/tools.js';
import { onRequestPost as analyzePost, onRequestOptions as analyzeOptions } from '../../functions/api/analyze.js';
import { onRequest as login } from '../../functions/api/auth/login.js';
import { onRequest as adminSummary } from '../../functions/api/admin/summary.js';
import { SECURITY_HEADERS } from '../../functions/_middleware.js';

function netlifyEnv() {
  return { ...process.env };
}

function applySecurity(response) {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    if (!headers.has(name)) headers.set(name, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function jsonError(status, error) {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function normalizePath(pathname) {
  if (pathname.length > 1 && pathname.endsWith('/')) return pathname.slice(0, -1);
  return pathname || '/';
}

async function dispatch(request, env) {
  const path = normalizePath(new URL(request.url).pathname);
  const context = { request, env, params: {} };
  const method = request.method;

  if (path === '/api/rewrite') {
    if (method === 'OPTIONS') return rewriteOptions(context);
    if (method === 'POST') return rewritePost(context);
    return jsonError(405, 'Método no permitido.');
  }
  if (path === '/api/humanize') {
    if (method === 'OPTIONS') return humanizeOptions(context);
    if (method === 'POST') return humanizePost(context);
    return jsonError(405, 'Método no permitido.');
  }
  if (path === '/api/tools') {
    if (method === 'OPTIONS') return toolsOptions(context);
    if (method === 'POST') return toolsPost(context);
    return jsonError(405, 'Método no permitido.');
  }
  if (path === '/api/analyze') {
    if (method === 'OPTIONS') return analyzeOptions(context);
    if (method === 'POST') return analyzePost(context);
    return jsonError(405, 'Método no permitido.');
  }
  if (path === '/api/auth/login') {
    return login(context);
  }
  if (path === '/api/admin/summary') {
    return adminSummary(context);
  }
  return jsonError(404, 'Ruta no encontrada');
}

export default async (request) => {
  const response = await dispatch(request, netlifyEnv());
  return applySecurity(response);
};

export const config = {
  path: '/api/*'
};
