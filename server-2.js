// ============================================================
// Vivian.exe — Key System (auth + one-time load)
// Harder to casual-dump: no script on /auth; /load is single-use token
// ============================================================
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Redis } = require('@upstash/redis');

const app = express();
app.use(express.json({ limit: '2mb' }));

const ADMIN_SECRET = process.env.ADMIN_SECRET;
if (!ADMIN_SECRET) {
  console.error('Set ADMIN_SECRET in Render env (no default).');
  process.exit(1);
}

const PORT = process.env.PORT || 3000;
const KEY_PREFIX = 'Vivian-';
const KEY_LENGTH = 16;
const TOKEN_TTL_SEC = 60; // one-time load token lifetime
const MIN_CLIENT_VER = process.env.MIN_CLIENT_VER || '1.6.6';

// ---------- REDIS ----------
const UPSTASH_URL = process.env.UPSTASH_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_TOKEN;
if (!UPSTASH_URL || !UPSTASH_TOKEN) {
  console.error('Missing UPSTASH_URL or UPSTASH_TOKEN');
  process.exit(1);
}
const redis = new Redis({ url: UPSTASH_URL, token: UPSTASH_TOKEN });
console.log('Redis ok');

// ---------- HELPERS ----------
async function getKey(key) {
  const data = await redis.get(`key:${key}`);
  if (!data) return null;
  return typeof data === 'string' ? JSON.parse(data) : data;
}
async function setKey(key, obj) {
  await redis.set(`key:${key}`, JSON.stringify(obj));
}
async function addLog(entry) {
  await redis.lpush('logs', JSON.stringify(entry));
  await redis.ltrim('logs', 0, 4999);
}

function genKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  let out = '';
  for (let i = 0; i < KEY_LENGTH; i++) {
    out += chars[crypto.randomInt(0, chars.length)];
  }
  return KEY_PREFIX + out;
}

function genToken() {
  return crypto.randomBytes(24).toString('hex');
}

function safeEqual(a, b) {
  try {
    const A = Buffer.from(String(a));
    const B = Buffer.from(String(b));
    if (A.length !== B.length) return false;
    return crypto.timingSafeEqual(A, B);
  } catch {
    return false;
  }
}

function requireAdmin(req, res, next) {
  const provided = req.headers['x-admin-secret'] || (req.body && req.body.admin_secret);
  if (!provided || !safeEqual(provided, ADMIN_SECRET)) {
    return res.status(403).json({ success: false, reason: 'Forbidden' });
  }
  next();
}

function clientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.length) return xf.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

// simple in-memory rate limit
const rateLimits = new Map();
function rateLimit(ip, maxPerMinute = 12) {
  const now = Date.now();
  const bucket = rateLimits.get(ip) || [];
  const recent = bucket.filter((t) => now - t < 60000);
  if (recent.length >= maxPerMinute) return false;
  recent.push(now);
  rateLimits.set(ip, recent);
  return true;
}

function verOk(ver) {
  if (!ver || typeof ver !== 'string') return false;
  // exact or >= min via simple string compare for dotted versions
  if (ver === MIN_CLIENT_VER) return true;
  const a = ver.split('.').map((n) => parseInt(n, 10) || 0);
  const b = MIN_CLIENT_VER.split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] || 0;
    const y = b[i] || 0;
    if (x > y) return true;
    if (x < y) return false;
  }
  return true;
}

function readPayload() {
  const p = path.join(__dirname, 'payload.lua');
  const chunk = fs.readFileSync(p, 'utf8');
  if (!chunk || !chunk.trim()) {
    const err = new Error('Payload empty');
    err.code = 'EMPTY_PAYLOAD';
    throw err;
  }
  return chunk;
}

// ---------- PUBLIC: AUTH (no script) ----------
app.post('/auth', async (req, res) => {
  const { key, hwid, ver } = req.body || {};
  const ip = clientIp(req);

  if (!rateLimit(ip)) {
    await addLog({ key, hwid, action: 'RATE_LIMITED', ip, timestamp: Date.now() });
    return res.json({ success: false, reason: 'Too many requests' });
  }
  if (!key || !hwid) {
    await addLog({ key, hwid, action: 'INVALID_REQUEST', ip, timestamp: Date.now() });
    return res.json({ success: false, reason: 'Missing parameters' });
  }
  if (!verOk(ver)) {
    await addLog({ key, hwid, action: 'BAD_VERSION', ip, ver, timestamp: Date.now() });
    return res.json({ success: false, reason: 'Update required' });
  }

  const row = await getKey(key);
  if (!row) {
    await addLog({ key, hwid, action: 'INVALID_KEY', ip, timestamp: Date.now() });
    return res.json({ success: false, reason: 'Invalid key' });
  }
  if (!row.active) {
    await addLog({ key, hwid, action: 'KEY_DISABLED', ip, timestamp: Date.now() });
    return res.json({ success: false, reason: 'Key disabled' });
  }
  if (row.expires_at && Date.now() > row.expires_at) {
    await addLog({ key, hwid, action: 'KEY_EXPIRED', ip, timestamp: Date.now() });
    return res.json({ success: false, reason: 'Key expired' });
  }

  if (!row.hwid) {
    row.hwid = hwid;
    await setKey(key, row);
  } else if (row.hwid !== hwid) {
    await addLog({ key, hwid, action: 'HWID_MISMATCH', ip, timestamp: Date.now() });
    return res.json({ success: false, reason: 'HWID mismatch' });
  }

  const token = genToken();
  await redis.set(`token:${token}`, JSON.stringify({
    key,
    hwid,
    exp: Date.now() + TOKEN_TTL_SEC * 1000,
  }), { ex: TOKEN_TTL_SEC });

  await addLog({ key, hwid, action: 'AUTH_OK', ip, timestamp: Date.now() });
  return res.json({
    success: true,
    token,
    expires_in: TOKEN_TTL_SEC,
  });
});

// ---------- PUBLIC: LOAD (one-time token → payload) ----------
app.post('/load', async (req, res) => {
  const { token, hwid, ver } = req.body || {};
  const ip = clientIp(req);

  if (!rateLimit(ip, 20)) {
    return res.json({ success: false, reason: 'Too many requests' });
  }
  if (!token || !hwid) {
    return res.json({ success: false, reason: 'Missing parameters' });
  }
  if (!verOk(ver)) {
    return res.json({ success: false, reason: 'Update required' });
  }

  const raw = await redis.get(`token:${token}`);
  if (!raw) {
    await addLog({ hwid, action: 'BAD_TOKEN', ip, timestamp: Date.now() });
    return res.json({ success: false, reason: 'Invalid or expired token' });
  }

  // one-time: delete before returning script
  await redis.del(`token:${token}`);

  const session = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (!session || session.hwid !== hwid) {
    await addLog({ hwid, action: 'TOKEN_HWID_MISMATCH', ip, timestamp: Date.now() });
    return res.json({ success: false, reason: 'Token mismatch' });
  }
  if (session.exp && Date.now() > session.exp) {
    return res.json({ success: false, reason: 'Token expired' });
  }

  const row = await getKey(session.key);
  if (!row || !row.active) {
    return res.json({ success: false, reason: 'Key disabled' });
  }
  if (row.expires_at && Date.now() > row.expires_at) {
    return res.json({ success: false, reason: 'Key expired' });
  }
  if (row.hwid && row.hwid !== hwid) {
    return res.json({ success: false, reason: 'HWID mismatch' });
  }

  let chunk;
  try {
    chunk = readPayload();
  } catch (e) {
    console.error('payload read failed', e.message);
    return res.json({ success: false, reason: 'Payload unavailable' });
  }

  row.uses = (row.uses || 0) + 1;
  await setKey(session.key, row);
  await addLog({ key: session.key, hwid, action: 'LOAD_OK', ip, timestamp: Date.now() });

  return res.json({ success: true, chunk });
});

// ---------- legacy: reject old single-shot loader ----------
app.post('/load_main', async (req, res) => {
  await addLog({
    key: (req.body || {}).key,
    action: 'LEGACY_LOAD_MAIN_BLOCKED',
    ip: clientIp(req),
    timestamp: Date.now(),
  });
  return res.json({
    success: false,
    reason: 'Update required — use new loader',
  });
});

// ---------- ADMIN ----------
app.post('/admin/gen', requireAdmin, async (req, res) => {
  const { count = 1, duration_hours = 0, label = '' } = req.body || {};
  const n = Math.min(parseInt(count, 10) || 1, 100);
  const newKeys = [];
  const expires_at = duration_hours > 0 ? Date.now() + duration_hours * 3600 * 1000 : null;
  for (let i = 0; i < n; i++) {
    let k;
    do {
      k = genKey();
    } while (await getKey(k));
    await setKey(k, {
      hwid: null,
      created_at: Date.now(),
      expires_at,
      active: 1,
      uses: 0,
      label,
    });
    newKeys.push(k);
  }
  res.json({ success: true, keys: newKeys });
});

app.post('/admin/reset', requireAdmin, async (req, res) => {
  const { key } = req.body || {};
  const row = await getKey(key);
  if (!row) return res.json({ success: false, reason: 'Key not found' });
  row.hwid = null;
  await setKey(key, row);
  await addLog({ key, action: 'HWID_RESET', timestamp: Date.now() });
  res.json({ success: true });
});

app.post('/admin/toggle', requireAdmin, async (req, res) => {
  const { key, active } = req.body || {};
  const row = await getKey(key);
  if (!row) return res.json({ success: false, reason: 'Key not found' });
  row.active = active ? 1 : 0;
  await setKey(key, row);
  await addLog({ key, action: active ? 'ENABLED' : 'DISABLED', timestamp: Date.now() });
  res.json({ success: true });
});

app.post('/admin/list', requireAdmin, async (req, res) => {
  const keys = await redis.keys('key:*');
  const list = [];
  for (const k of keys) {
    const row = await getKey(k.replace('key:', ''));
    if (row) list.push({ key: k.replace('key:', ''), ...row });
  }
  res.json({ success: true, keys: list });
});

app.post('/admin/logs', requireAdmin, async (req, res) => {
  const raw = await redis.lrange('logs', 0, 499);
  const logs = raw.map((r) => (typeof r === 'string' ? JSON.parse(r) : r));
  res.json({ success: true, logs });
});

app.get('/', (req, res) => res.send('vivian.exe key system online (auth+/load)'));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Vivian.exe key system on :${PORT}`);
  console.log(`MIN_CLIENT_VER=${MIN_CLIENT_VER} TOKEN_TTL=${TOKEN_TTL_SEC}s`);
});
