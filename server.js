// My Morning Protocol server: serves the site, user accounts, and WHOOP connections.
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
const whoop = require('./whoop');

const PORT = process.env.PORT || 3000;
const APP_URL = (process.env.APP_URL || 'http://localhost:' + PORT).replace(/\/$/, '');
const APP_HOST = new URL(APP_URL).host;
const IS_HTTPS = APP_URL.startsWith('https://');
const SESSION_DAYS = 30;
const COOKIE = 'mmp_session';
const AGE_GROUPS = ['25–34', '35–44', '45–54', '55+'];

// MySQL / MariaDB. Use DB_HOST, DB_USER, DB_PASSWORD, DB_NAME (as shown in Hostinger), or a single DATABASE_URL.
const dbConfig = process.env.DATABASE_URL
  ? { uri: process.env.DATABASE_URL }
  : { host: process.env.DB_HOST || 'localhost', port: Number(process.env.DB_PORT) || 3306,
      user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME };
if (!dbConfig.uri && !(dbConfig.user && dbConfig.database)) {
  console.error('Database settings missing: set DB_HOST, DB_USER, DB_PASSWORD and DB_NAME.');
  process.exit(1);
}
const pool = mysql.createPool(Object.assign(dbConfig, {
  connectionLimit: 5, timezone: 'Z', charset: 'utf8mb4', waitForConnections: true
}));
// Keep the database clock in UTC so NOW() matches the dates the app writes.
pool.pool.on('connection', c => c.query("SET time_zone = '+00:00'"));
async function q(sql, params = []) {
  const [result] = await pool.query(sql, params);
  return Array.isArray(result) ? { rows: result } : { rows: [], affectedRows: result.affectedRows, insertId: result.insertId };
}

/* ---------- Token encryption (device tokens are stored encrypted) ---------- */
const ENC_KEY = process.env.TOKEN_ENCRYPTION_KEY
  ? crypto.createHash('sha256').update(process.env.TOKEN_ENCRYPTION_KEY).digest()
  : null;
if (!ENC_KEY) console.warn('TOKEN_ENCRYPTION_KEY is not set: device tokens will be stored unencrypted.');
function encrypt(text) {
  if (!ENC_KEY || text == null) return text;
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const enc = Buffer.concat([c.update(String(text), 'utf8'), c.final()]);
  return 'v1:' + Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64');
}
function decrypt(text) {
  if (!text || !text.startsWith('v1:')) return text;
  if (!ENC_KEY) throw new Error('TOKEN_ENCRYPTION_KEY missing');
  const buf = Buffer.from(text.slice(3), 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
}
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');

/* ---------- Schema ---------- */
const TABLE_OPTS = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';
async function migrate() {
  const statements = [
    `CREATE TABLE IF NOT EXISTS users (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(254) NOT NULL,
      password_hash VARCHAR(100) NOT NULL,
      name VARCHAR(80) NOT NULL DEFAULT '',
      age_group VARCHAR(16) NOT NULL DEFAULT '35–44',
      created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      UNIQUE KEY users_email (email)
    ) ${TABLE_OPTS}`,
    `CREATE TABLE IF NOT EXISTS sessions (
      token_hash CHAR(64) NOT NULL PRIMARY KEY,
      user_id BIGINT UNSIGNED NOT NULL,
      expires_at DATETIME(3) NOT NULL,
      KEY sessions_user (user_id),
      CONSTRAINT sessions_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ${TABLE_OPTS}`,
    `CREATE TABLE IF NOT EXISTS user_state (
      user_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
      data LONGTEXT NOT NULL,
      updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      CONSTRAINT user_state_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ${TABLE_OPTS}`,
    `CREATE TABLE IF NOT EXISTS device_connections (
      user_id BIGINT UNSIGNED NOT NULL,
      provider VARCHAR(32) NOT NULL,
      provider_user_id VARCHAR(64) NULL,
      access_token TEXT NOT NULL,
      refresh_token TEXT NULL,
      expires_at DATETIME(3) NOT NULL,
      scope TEXT NULL,
      connected_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      last_sync_at DATETIME(3) NULL,
      PRIMARY KEY (user_id, provider),
      CONSTRAINT device_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ${TABLE_OPTS}`,
    `CREATE TABLE IF NOT EXISTS oauth_states (
      state CHAR(32) NOT NULL PRIMARY KEY,
      user_id BIGINT UNSIGNED NOT NULL,
      provider VARCHAR(32) NOT NULL,
      created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      CONSTRAINT oauth_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ${TABLE_OPTS}`
  ];
  for (const s of statements) await q(s);
}

/* ---------- App ---------- */
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

app.get('/healthz', (req, res) => res.json({ ok: true }));

// Send everyone to one hostname (e.g. www) so the sign-in cookie always matches.
app.use((req, res, next) => {
  if (process.env.CANONICAL_REDIRECT !== 'false' && IS_HTTPS && req.headers.host && req.headers.host !== APP_HOST) {
    return res.redirect(301, APP_URL + req.originalUrl);
  }
  next();
});

app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.set('X-Frame-Options', 'DENY');
  if (IS_HTTPS) res.set('Strict-Transport-Security', 'max-age=15552000');
  next();
});

// Block cross-site form posts: state-changing API calls must come from our own pages.
app.use('/api', (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  const origin = req.get('origin');
  if (origin && new URL(origin).host !== req.get('host')) return res.status(403).json({ error: 'Cross-site request blocked.' });
  if (!req.is('application/json') && req.method !== 'DELETE') return res.status(415).json({ error: 'Expected JSON.' });
  next();
});

/* ---------- Sessions ---------- */
function cookieOpts(maxAgeMs) {
  return { httpOnly: true, secure: IS_HTTPS, sameSite: 'lax', path: '/', maxAge: maxAgeMs };
}
async function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000);
  await q('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?,?,?)', [sha256(token), userId, expires]);
  res.cookie(COOKIE, token, cookieOpts(SESSION_DAYS * 86400000));
}
async function currentUser(req) {
  const token = req.cookies[COOKIE];
  if (!token) return null;
  const r = await q(
    `SELECT u.id, u.email, u.name, u.age_group, u.created_at FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > NOW(3)`, [sha256(token)]);
  return r.rows[0] || null;
}
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const requireUser = wrap(async (req, res, next) => {
  req.user = await currentUser(req);
  if (!req.user) return res.status(401).json({ error: 'Please sign in.' });
  next();
});
const publicUser = u => ({ id: String(u.id), email: u.email, name: u.name, ageGroup: u.age_group, createdAt: u.created_at });

// Simple in-memory limiter for sign-in and sign-up attempts.
const attempts = new Map();
function limited(key, max = 10, windowMs = 15 * 60000) {
  const now = Date.now();
  const a = (attempts.get(key) || []).filter(t => now - t < windowMs);
  a.push(now);
  attempts.set(key, a);
  return a.length > max;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/* ---------- Account API ---------- */
app.post('/api/signup', wrap(async (req, res) => {
  if (limited('signup:' + req.ip, 20)) return res.status(429).json({ error: 'Too many attempts. Try again in a few minutes.' });
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const name = String(req.body.name || '').trim().slice(0, 80);
  const ageGroup = AGE_GROUPS.includes(req.body.ageGroup) ? req.body.ageGroup : '35–44';
  if (!EMAIL_RE.test(email) || email.length > 254) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 8) return res.status(400).json({ error: 'Use at least 8 characters for your password.' });
  if (password.length > 200) return res.status(400).json({ error: 'That password is too long.' });
  const hash = await bcrypt.hash(password, 12);
  let user;
  try {
    const ins = await q('INSERT INTO users (email, password_hash, name, age_group) VALUES (?,?,?,?)', [email, hash, name, ageGroup]);
    user = (await q('SELECT * FROM users WHERE id = ?', [ins.insertId])).rows[0];
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'An account with that email already exists. Try signing in.' });
    throw e;
  }
  await startSession(res, user.id);
  res.status(201).json({ user: publicUser(user) });
}));

app.post('/api/login', wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (limited('login:' + req.ip, 30) || limited('login:' + email, 10)) return res.status(429).json({ error: 'Too many attempts. Try again in a few minutes.' });
  const r = await q('SELECT * FROM users WHERE email = ?', [email]);
  const user = r.rows[0];
  const ok = user && await bcrypt.compare(String(req.body.password || ''), user.password_hash);
  if (!ok) return res.status(401).json({ error: 'That email and password don’t match.' });
  await startSession(res, user.id);
  res.json({ user: publicUser(user) });
}));

app.post('/api/logout', wrap(async (req, res) => {
  const token = req.cookies[COOKIE];
  if (token) await q('DELETE FROM sessions WHERE token_hash = ?', [sha256(token)]);
  res.clearCookie(COOKIE, cookieOpts(0));
  res.json({ ok: true });
}));

app.get('/api/me', wrap(async (req, res) => {
  const user = await currentUser(req);
  if (!user) return res.json({ user: null, whoopAvailable: whoop.config().configured });
  const devices = await q('SELECT provider, connected_at, last_sync_at FROM device_connections WHERE user_id = ?', [user.id]);
  res.json({
    user: publicUser(user),
    devices: Object.fromEntries(devices.rows.map(d => [d.provider, { connectedAt: d.connected_at, lastSyncAt: d.last_sync_at }])),
    whoopAvailable: whoop.config().configured
  });
}));

app.patch('/api/me', requireUser, wrap(async (req, res) => {
  const name = req.body.name !== undefined ? String(req.body.name).trim().slice(0, 80) : req.user.name;
  const ageGroup = AGE_GROUPS.includes(req.body.ageGroup) ? req.body.ageGroup : req.user.age_group;
  await q('UPDATE users SET name = ?, age_group = ? WHERE id = ?', [name, ageGroup, req.user.id]);
  const r = await q('SELECT * FROM users WHERE id = ?', [req.user.id]);
  res.json({ user: publicUser(r.rows[0]) });
}));

app.post('/api/me/password', requireUser, wrap(async (req, res) => {
  const r = await q('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);
  if (!await bcrypt.compare(String(req.body.current || ''), r.rows[0].password_hash)) return res.status(401).json({ error: 'Your current password isn’t right.' });
  const next = String(req.body.next || '');
  if (next.length < 8 || next.length > 200) return res.status(400).json({ error: 'Use at least 8 characters for your new password.' });
  await q('UPDATE users SET password_hash = ? WHERE id = ?', [await bcrypt.hash(next, 12), req.user.id]);
  await q('DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?', [req.user.id, sha256(req.cookies[COOKIE])]);
  res.json({ ok: true });
}));

app.delete('/api/me', requireUser, wrap(async (req, res) => {
  const conn = await q('SELECT * FROM device_connections WHERE user_id = ? AND provider = ?', [req.user.id, 'whoop']);
  if (conn.rows[0]) await whoop.revoke(decrypt(conn.rows[0].access_token)).catch(() => {});
  await q('DELETE FROM users WHERE id = ?', [req.user.id]);
  res.clearCookie(COOKIE, cookieOpts(0));
  res.json({ ok: true });
}));

/* ---------- Saved protocol, logs and settings ---------- */
app.get('/api/state', requireUser, wrap(async (req, res) => {
  const r = await q('SELECT data FROM user_state WHERE user_id = ?', [req.user.id]);
  let state = null;
  if (r.rows[0]) { try { state = typeof r.rows[0].data === 'string' ? JSON.parse(r.rows[0].data) : r.rows[0].data; } catch (e) { state = null; } }
  res.json({ state });
}));
app.put('/api/state', requireUser, wrap(async (req, res) => {
  const data = req.body && req.body.state;
  if (!data || typeof data !== 'object') return res.status(400).json({ error: 'Missing state.' });
  const json = JSON.stringify(data);
  if (json.length > 2000000) return res.status(413).json({ error: 'Too much data.' });
  await q(`INSERT INTO user_state (user_id, data, updated_at) VALUES (?,?,NOW(3))
           ON DUPLICATE KEY UPDATE data = VALUES(data), updated_at = NOW(3)`, [req.user.id, json]);
  res.json({ ok: true });
}));

/* ---------- WHOOP ---------- */
app.get('/auth/whoop/start', wrap(async (req, res) => {
  const user = await currentUser(req);
  if (!user) return res.redirect('/?view=account&next=whoop');
  if (!whoop.config().configured) return res.redirect('/?view=devices&whoop=unavailable');
  const state = crypto.randomBytes(16).toString('hex');
  await q("DELETE FROM oauth_states WHERE created_at < NOW(3) - INTERVAL 15 MINUTE");
  await q('INSERT INTO oauth_states (state, user_id, provider) VALUES (?,?,?)', [state, user.id, 'whoop']);
  res.redirect(whoop.authorizeUrl(state));
}));

app.get('/auth/whoop/callback', wrap(async (req, res) => {
  const { code, state, error } = req.query;
  const user = await currentUser(req);
  if (!user) return res.redirect('/?view=account&next=whoop');
  if (error) return res.redirect('/?view=devices&whoop=denied');
  const s = await q(
    'DELETE FROM oauth_states WHERE state = ? AND user_id = ? AND created_at > NOW(3) - INTERVAL 15 MINUTE',
    [String(state || ''), user.id]);
  if (s.affectedRows !== 1 || !code) return res.redirect('/?view=devices&whoop=expired');
  try {
    const tok = await whoop.exchangeCode(String(code));
    let whoopId = null;
    try { const p = await whoop.profile(tok.access_token); whoopId = p && p.user_id != null ? String(p.user_id) : null; } catch (e) { /* profile is optional */ }
    await q(`
      INSERT INTO device_connections (user_id, provider, provider_user_id, access_token, refresh_token, expires_at, scope, connected_at)
      VALUES (?,'whoop',?,?,?,?,?,NOW(3))
      ON DUPLICATE KEY UPDATE provider_user_id = VALUES(provider_user_id), access_token = VALUES(access_token),
        refresh_token = VALUES(refresh_token), expires_at = VALUES(expires_at), scope = VALUES(scope), connected_at = NOW(3)`,
      [user.id, whoopId, encrypt(tok.access_token), encrypt(tok.refresh_token || null),
       new Date(Date.now() + (Number(tok.expires_in) || 3600) * 1000), tok.scope || null]);
    res.redirect('/?view=devices&whoop=connected');
  } catch (e) {
    console.error('WHOOP connect failed:', e.message, e.detail || '');
    res.redirect('/?view=devices&whoop=failed');
  }
}));

// One refresh at a time per user: WHOOP invalidates the old refresh token on use.
const refreshing = new Map();
async function whoopToken(userId) {
  const r = await q("SELECT * FROM device_connections WHERE user_id = ? AND provider = 'whoop'", [userId]);
  const c = r.rows[0];
  if (!c) return null;
  if (new Date(c.expires_at).getTime() - Date.now() > 60000) return decrypt(c.access_token);
  if (!c.refresh_token) return null;
  if (!refreshing.has(userId)) {
    refreshing.set(userId, (async () => {
      try {
        const tok = await whoop.refresh(decrypt(c.refresh_token));
        await q(`UPDATE device_connections SET access_token = ?, refresh_token = COALESCE(?, refresh_token), expires_at = ?
                 WHERE user_id = ? AND provider = 'whoop'`,
          [encrypt(tok.access_token), tok.refresh_token ? encrypt(tok.refresh_token) : null,
           new Date(Date.now() + (Number(tok.expires_in) || 3600) * 1000), userId]);
        return tok.access_token;
      } finally {
        refreshing.delete(userId);
      }
    })());
  }
  return refreshing.get(userId);
}

const cache = new Map(); // userId -> { at, days, data }
app.get('/api/whoop/summary', requireUser, wrap(async (req, res) => {
  const days = Math.min(Math.max(parseInt(req.query.days, 10) || 60, 1), 90);
  const hit = cache.get(req.user.id);
  if (hit && hit.days >= days && Date.now() - hit.at < 10 * 60000 && req.query.fresh !== '1') return res.json(hit.data);
  let token;
  try { token = await whoopToken(req.user.id); } catch (e) {
    console.error('WHOOP refresh failed:', e.message, e.detail || '');
    return res.status(409).json({ error: 'Your WHOOP connection has expired. Please reconnect it.', reconnect: true });
  }
  if (!token) return res.status(404).json({ error: 'WHOOP isn’t connected.' });
  try {
    const data = await whoop.summary(token, days);
    await q("UPDATE device_connections SET last_sync_at = NOW(3) WHERE user_id = ? AND provider = 'whoop'", [req.user.id]);
    data.syncedAt = new Date().toISOString();
    cache.set(req.user.id, { at: Date.now(), days, data });
    res.json(data);
  } catch (e) {
    console.error('WHOOP summary failed:', e.message);
    if (e.status === 401) return res.status(409).json({ error: 'Your WHOOP connection has expired. Please reconnect it.', reconnect: true });
    res.status(502).json({ error: 'Couldn’t reach WHOOP just now. Try again shortly.' });
  }
}));

app.delete('/api/devices/whoop', requireUser, wrap(async (req, res) => {
  const token = await whoopToken(req.user.id).catch(() => null);
  if (token) await whoop.revoke(token).catch(e => console.warn('WHOOP revoke failed:', e.message));
  await q("DELETE FROM device_connections WHERE user_id = ? AND provider = 'whoop'", [req.user.id]);
  cache.delete(req.user.id);
  res.json({ ok: true });
}));

/* ---------- Site ---------- */
const INDEX = path.join(__dirname, 'index.html');
app.get('/', (req, res) => { res.set('Cache-Control', 'no-cache'); res.sendFile(INDEX); });
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((req, res) => res.redirect('/'));

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Something went wrong on our side.' });
});

migrate()
  .then(() => app.listen(PORT, () => console.log('My Morning Protocol listening on ' + PORT + ' (' + APP_URL + ')')))
  .catch(e => { console.error('Database setup failed:', e); process.exit(1); });
