// WHOOP API client: OAuth 2.0 and the v2 data endpoints.
// Docs: https://developer.whoop.com/docs/developing/oauth and https://developer.whoop.com/api

const AUTH_BASE = process.env.WHOOP_AUTH_BASE || 'https://api.prod.whoop.com/oauth/oauth2';
const API_BASE = process.env.WHOOP_API_BASE || 'https://api.prod.whoop.com/developer';

const SCOPES = [
  'offline', // needed to get a refresh token
  'read:profile',
  'read:recovery',
  'read:cycles',
  'read:sleep',
  'read:workout',
  'read:body_measurement'
];

function config() {
  const clientId = process.env.WHOOP_CLIENT_ID;
  const clientSecret = process.env.WHOOP_CLIENT_SECRET;
  const appUrl = (process.env.APP_URL || '').replace(/\/$/, '');
  return {
    clientId,
    clientSecret,
    redirectUri: process.env.WHOOP_REDIRECT_URI || appUrl + '/auth/whoop/callback',
    configured: Boolean(clientId && clientSecret && appUrl)
  };
}

function authorizeUrl(state) {
  const c = config();
  const u = new URL(AUTH_BASE + '/auth');
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', c.clientId);
  u.searchParams.set('redirect_uri', c.redirectUri);
  u.searchParams.set('scope', SCOPES.join(' '));
  u.searchParams.set('state', state);
  return u.toString();
}

async function tokenRequest(params) {
  const c = config();
  const body = new URLSearchParams(Object.assign({ client_id: c.clientId, client_secret: c.clientSecret }, params));
  const res = await fetch(AUTH_BASE + '/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch (e) { /* not JSON */ }
  if (!res.ok || !json || !json.access_token) {
    const err = new Error('WHOOP token request failed (' + res.status + ')');
    err.status = res.status;
    err.detail = json ? (json.error_description || json.error) : text.slice(0, 200);
    throw err;
  }
  return json;
}

function exchangeCode(code) {
  return tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: config().redirectUri });
}

function refresh(refreshToken) {
  return tokenRequest({ grant_type: 'refresh_token', refresh_token: refreshToken, scope: 'offline' });
}

async function api(accessToken, path, { method = 'GET', query } = {}) {
  const u = new URL(API_BASE + path);
  if (query) Object.entries(query).forEach(([k, v]) => { if (v !== undefined && v !== null) u.searchParams.set(k, v); });
  const res = await fetch(u, { method, headers: { Authorization: 'Bearer ' + accessToken, Accept: 'application/json' } });
  if (res.status === 204) return null;
  if (!res.ok) {
    const err = new Error('WHOOP API ' + path + ' failed (' + res.status + ')');
    err.status = res.status;
    throw err;
  }
  return res.json();
}

// Collection endpoints return { records, next_token } with up to 25 records per page.
async function collection(accessToken, path, start, end, maxPages = 6) {
  const out = [];
  let nextToken;
  for (let i = 0; i < maxPages; i++) {
    const page = await api(accessToken, path, { query: { start, end, limit: 25, nextToken } });
    out.push(...((page && page.records) || []));
    nextToken = page && page.next_token;
    if (!nextToken) break;
  }
  return out;
}

const profile = token => api(token, '/v2/user/profile/basic');
const revoke = token => api(token, '/v2/user/access', { method: 'DELETE' });

// Pull the last `days` days and reduce to the fields the dashboard uses.
async function summary(token, days) {
  const end = new Date();
  const start = new Date(end.getTime() - days * 86400000);
  const s = start.toISOString(), e = end.toISOString();
  const [recovery, sleep, cycles, body] = await Promise.all([
    collection(token, '/v2/recovery', s, e),
    collection(token, '/v2/activity/sleep', s, e),
    collection(token, '/v2/cycle', s, e),
    api(token, '/v2/user/measurement/body').catch(() => null)
  ]);
  return {
    recovery: recovery
      .filter(r => r.score_state === 'SCORED' && r.score)
      .map(r => ({
        at: r.created_at,
        sleepId: r.sleep_id,
        recovery: r.score.recovery_score,
        hrv: r.score.hrv_rmssd_milli,
        rhr: r.score.resting_heart_rate
      })),
    sleep: sleep
      .filter(x => !x.nap && x.score_state === 'SCORED' && x.score)
      .map(x => ({ id: x.id, end: x.end, performance: x.score.sleep_performance_percentage })),
    cycles: cycles
      .filter(c => c.score_state === 'SCORED' && c.score)
      .map(c => ({ start: c.start, strain: c.score.strain })),
    body: body ? { weightKg: body.weight_kilogram, heightM: body.height_meter } : null
  };
}

module.exports = { config, authorizeUrl, exchangeCode, refresh, profile, revoke, summary, SCOPES };
