/**
 * Ph3ntom Auth API
 * Turso DB + sell.app webhook + Discord /redeem + loader verification
 */
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const { randomBytes, createHash } = require('crypto');
const { createClient } = require('@libsql/client');

const PORT = process.env.PHANTOM_PORT || process.env.PORT || 8787;
const JWT_SECRET = process.env.PHANTOM_JWT || 'CHANGE_ME_PHANTOM_SECRET';
const OWNER_EMAIL = (process.env.PHANTOM_OWNER_EMAIL || 'owner@ph3ntom.local').toLowerCase();
const OWNER_PASS = process.env.PHANTOM_OWNER_PASS || 'ChangeThisPassword123!';
const DLL_PATH = process.env.PHANTOM_DLL || path.join(__dirname, 'private', 'velocity.dll');
const LOADER_DOWNLOAD_URL = process.env.LOADER_DOWNLOAD_URL || '';
const SELLAPP_WEBHOOK_SECRET = process.env.SELLAPP_WEBHOOK_SECRET || '';
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || '';
const DISCORD_REDEEM_CHANNEL = (process.env.DISCORD_REDEEM_CHANNEL || 'redeem-sub').toLowerCase();
const DISCORD_GUILD_ID = (process.env.DISCORD_GUILD_ID || '').trim();
const PUBLIC_API_URL = (process.env.PUBLIC_API_URL || '').replace(/\/$/, '');

const privateDir = path.join(__dirname, 'private');
fs.mkdirSync(privateDir, { recursive: true });
fs.mkdirSync(path.join(__dirname, 'public'), { recursive: true });

const TURSO_URL = (process.env.TURSO_DATABASE_URL || process.env.TURSO_URL || '').trim();
const TURSO_TOKEN = (process.env.TURSO_AUTH_TOKEN || process.env.TURSO_TOKEN || '').trim();

if (!TURSO_URL) {
  console.error('[phantom] FATAL: set TURSO_DATABASE_URL');
  process.exit(1);
}

const db = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN || undefined });

function uid() { return randomBytes(16).toString('hex'); }
function now() { return Date.now(); }

function planMs(plan) {
  const h = 60 * 60 * 1000;
  const d = 24 * h;
  switch (String(plan || '').toLowerCase()) {
    case 'hour': case '1h': return 1 * h;
    case 'day': case '1d': return 1 * d;
    case 'week': case '1w': return 7 * d;
    case 'month': case '1m': return 30 * d;
    case '6month': case '6m': return 180 * d;
    case 'year': case '1y': return 365 * d;
    case 'lifetime': return 100 * 365 * d;
    default: return 30 * d;
  }
}
function normalizePlan(plan) {
  const p = String(plan || 'month').toLowerCase();
  const map = {
    '1 hour': 'hour', '1hour': 'hour', hour: 'hour', '1h': 'hour',
    '1 day': 'day', '1day': 'day', day: 'day', '1d': 'day',
    '1 week': 'week', week: 'week', '1w': 'week',
    '1 month': 'month', month: 'month', '1m': 'month',
    '6 month': '6month', '6 months': '6month', '6month': '6month', '6m': '6month',
    '1 year': 'year', year: 'year', '1y': 'year',
    lifetime: 'lifetime'
  };
  return map[p] || (['hour','day','week','month','6month','year','lifetime'].includes(p) ? p : 'month');
}
function genKey(plan) {
  const a = randomBytes(3).toString('hex').toUpperCase();
  const b = randomBytes(3).toString('hex').toUpperCase();
  const c = randomBytes(3).toString('hex').toUpperCase();
  const tag = String(plan || 'month').slice(0, 3).toUpperCase();
  return `PH3-${tag}-${a}-${b}-${c}`;
}
function dllMeta() {
  try {
    if (!fs.existsSync(DLL_PATH)) return { exists: false, size: 0, sha1: null };
    const st = fs.statSync(DLL_PATH);
    const buf = fs.readFileSync(DLL_PATH);
    const sha1 = createHash('sha1').update(buf).digest('hex').slice(0, 12);
    return { exists: true, size: st.size, mtime: st.mtimeMs, sha1 };
  } catch (e) {
    return { exists: false, size: 0, sha1: null };
  }
}

async function q(sql, args = []) { return db.execute({ sql, args }); }
async function one(sql, args = []) { const r = await q(sql, args); return r.rows[0] || null; }
async function all(sql, args = []) { const r = await q(sql, args); return r.rows; }

async function initDb() {
  await q(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    pass_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    sub_plan TEXT,
    sub_expires INTEGER,
    last_seen INTEGER,
    created_at INTEGER NOT NULL,
    discord_id TEXT,
    discord_tag TEXT,
    hwid TEXT,
    banned INTEGER DEFAULT 0
  )`);
  await q(`CREATE TABLE IF NOT EXISTS keys (
    id TEXT PRIMARY KEY,
    key_code TEXT UNIQUE NOT NULL,
    plan TEXT NOT NULL,
    note TEXT,
    created_at INTEGER NOT NULL,
    used_by TEXT,
    used_at INTEGER,
    order_id TEXT,
    revoked INTEGER DEFAULT 0
  )`);
  await q(`CREATE TABLE IF NOT EXISTS sessions (
    token_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  )`);

  const owner = await one('SELECT * FROM users WHERE email = ?', [OWNER_EMAIL]);
  const hash = await bcrypt.hash(OWNER_PASS, 10);
  if (!owner) {
    await q(
      `INSERT INTO users (id,email,username,pass_hash,role,created_at,last_seen,sub_plan,sub_expires)
       VALUES (?,?,?,?,?,?,?,?,?)`,
      [uid(), OWNER_EMAIL, 'owner', hash, 'owner', now(), now(), 'lifetime', now() + planMs('lifetime')]
    );
  } else {
    await q("UPDATE users SET role = 'owner', pass_hash = ? WHERE email = ?", [hash, OWNER_EMAIL]);
  }
}

function isActive(u) {
  if (!u || Number(u.banned) === 1) return false;
  if (u.role === 'owner' || u.role === 'admin') return true;
  return Number(u.sub_expires || 0) > now();
}

function publicUser(u) {
  if (!u) return null;
  let expires_label = '—';
  if (u.role === 'owner' || u.role === 'admin') expires_label = 'Never';
  else if (Number(u.sub_expires || 0) > 0) {
    expires_label = new Date(Number(u.sub_expires)).toISOString().slice(0, 10);
  }
  return {
    id: u.id,
    email: u.email,
    username: u.username,
    role: u.role,
    sub_plan: u.sub_plan,
    sub_expires: u.sub_expires,
    sub_active: isActive(u),
    expires_label,
    discord_id: u.discord_id || null,
    discord_tag: u.discord_tag || null,
    banned: Number(u.banned) === 1
  };
}

async function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : '';
    if (!token) return res.status(401).json({ error: 'no token' });
    const payload = jwt.verify(token, JWT_SECRET);
    const u = await one('SELECT * FROM users WHERE id = ?', [payload.uid]);
    if (!u) return res.status(401).json({ error: 'user gone' });
    if (Number(u.banned) === 1) return res.status(403).json({ error: 'banned' });
    req.user = u;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid token' });
  }
}
function adminOnly(req, res, next) {
  if (!req.user || (req.user.role !== 'owner' && req.user.role !== 'admin')) {
    return res.status(403).json({ error: 'admin only' });
  }
  next();
}

async function applyKeyToUser(user, keyRow) {
  const plan = normalizePlan(keyRow.plan);
  const base = Math.max(Number(user.sub_expires || 0), now());
  const exp = base + planMs(plan);
  await q('UPDATE users SET sub_plan = ?, sub_expires = ? WHERE id = ?', [plan, exp, user.id]);
  await q('UPDATE keys SET used_by = ?, used_at = ? WHERE id = ?', [user.email, now(), keyRow.id]);
  return exp;
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use('/public', express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.type('text').send('Ph3ntom Auth API OK');
});

app.get('/api/health', (req, res) => {
  const meta = dllMeta();
  res.json({
    ok: true,
    name: 'Ph3ntom Auth',
    version: '2.0',
    dll: meta.exists,
    dll_sha1: meta.sha1,
    dll_size: meta.size
  });
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

/** Public page after sell.app payment — shows the generated key */
app.get('/license', async (req, res) => {
  const order = String(req.query.order || req.query.order_id || '').trim();
  let keyRow = null;
  if (order) keyRow = await one('SELECT * FROM keys WHERE order_id = ?', [order]);
  const keyCode = keyRow ? keyRow.key_code : null;
  const plan = keyRow ? keyRow.plan : '';
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"/><title>Your Ph3ntom License</title>
<style>
body{font-family:system-ui,sans-serif;background:#0b0b0c;color:#fff;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{background:#141416;border:1px solid #2a2a2e;border-radius:16px;padding:32px;max-width:420px;text-align:center}
code{display:block;background:#0a0a0b;padding:14px;border-radius:10px;font-size:16px;letter-spacing:1px;margin:16px 0;word-break:break-all}
.muted{color:#888;font-size:13px;line-height:1.5}
</style></head><body><div class="card">
<h1>Ph3ntom</h1>
${keyCode
  ? `<p>Your license key</p><code id="k">${keyCode}</code>
     <p class="muted">Plan: ${plan}<br/>1) Copy this key<br/>2) Join Discord<br/>3) In #redeem-sub type<br/><b>/redeem key:${keyCode}</b><br/>4) Bot DMs you the loader<br/>5) Login → Verification → paste key → Launch</p>
     <button onclick="navigator.clipboard.writeText(document.getElementById('k').innerText)" style="padding:10px 18px;border-radius:8px;border:0;background:#fff;color:#000;cursor:pointer">Copy key</button>`
  : `<p class="muted">License not found yet. Wait a few seconds and refresh, or check your email / Discord.</p>`}
</div></body></html>`);
});

app.post('/api/register', async (req, res) => {
  try {
    const email = String(req.body.email || '').toLowerCase().trim();
    const password = String(req.body.password || '');
    const username = String(req.body.username || email.split('@')[0] || 'user').slice(0, 32);
    if (!email || password.length < 4) return res.status(400).json({ error: 'email + password required' });
    if (await one('SELECT id FROM users WHERE email = ?', [email])) {
      return res.status(400).json({ error: 'email already registered' });
    }
    const id = uid();
    const pass_hash = await bcrypt.hash(password, 10);
    await q(
      `INSERT INTO users (id,email,username,pass_hash,role,created_at,last_seen) VALUES (?,?,?,?,?,?,?)`,
      [id, email, username, pass_hash, 'user', now(), now()]
    );
    const token = jwt.sign({ uid: id }, JWT_SECRET, { expiresIn: '30d' });
    const u = await one('SELECT * FROM users WHERE id = ?', [id]);
    res.json({ token, ...publicUser(u), needs_verification: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').toLowerCase().trim();
    const password = String(req.body.password || '');
    const u = await one('SELECT * FROM users WHERE email = ?', [email]);
    if (!u) return res.status(401).json({ error: 'wrong email or password' });
    if (Number(u.banned) === 1) return res.status(403).json({ error: 'banned' });
    const ok = await bcrypt.compare(password, u.pass_hash);
    if (!ok) return res.status(401).json({ error: 'wrong email or password' });
    await q('UPDATE users SET last_seen = ? WHERE id = ?', [now(), u.id]);
    const token = jwt.sign({ uid: u.id }, JWT_SECRET, { expiresIn: '30d' });
    const pu = publicUser(u);
    res.json({
      token,
      ...pu,
      needs_verification: !pu.sub_active
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/me', auth, async (req, res) => {
  res.json(publicUser(req.user));
});


/** Loader: license-key only login (no email/password) */
app.post('/api/loader/license-login', async (req, res) => {
  try {
    const code = String(req.body.key || req.body.license || '').trim().toUpperCase();
    let username = String(req.body.username || '').trim();
    if (!code) return res.status(400).json({ error: 'license required' });

    const k = await one('SELECT * FROM keys WHERE key_code = ?', [code]);
    if (!k) return res.status(404).json({ error: 'invalid license' });
    if (Number(k.revoked) === 1) return res.status(400).json({ error: 'license revoked' });

    // Find existing user bound to this key, or create license-scoped user
    let user = null;
    if (k.used_by && !String(k.used_by).startsWith('discord:')) {
      user = await one('SELECT * FROM users WHERE email = ?', [k.used_by]);
    }
    if (!user && k.used_by && String(k.used_by).startsWith('discord:')) {
      const did = String(k.used_by).slice('discord:'.length);
      user = await one('SELECT * FROM users WHERE discord_id = ?', [did]);
    }

    const licenseEmail = ('license+' + code.replace(/[^A-Z0-9]/g, '') + '@ph3ntom.local').toLowerCase();
    if (!user) {
      user = await one('SELECT * FROM users WHERE email = ?', [licenseEmail]);
    }
    if (!user) {
      if (!username) username = 'Player';
      username = username.slice(0, 24);
      const id = uid();
      const pass_hash = await bcrypt.hash(randomBytes(16).toString('hex'), 10);
      await q(
        `INSERT INTO users (id,email,username,pass_hash,role,created_at,last_seen) VALUES (?,?,?,?,?,?,?)`,
        [id, licenseEmail, username, pass_hash, 'user', now(), now()]
      );
      user = await one('SELECT * FROM users WHERE id = ?', [id]);
    }

    // Apply / refresh subscription from key if needed
    if (!k.used_by || String(k.used_by).startsWith('discord:') || k.used_by === user.email) {
      await applyKeyToUser(user, k);
      user = await one('SELECT * FROM users WHERE id = ?', [user.id]);
    }

    if (!isActive(user)) {
      return res.status(403).json({ error: 'subscription expired' });
    }

    // Optional username update on this call
    if (username && username !== user.username) {
      username = username.slice(0, 24);
      await q('UPDATE users SET username = ? WHERE id = ?', [username, user.id]);
      user = await one('SELECT * FROM users WHERE id = ?', [user.id]);
    }

    const token = jwt.sign({ uid: user.id }, JWT_SECRET, { expiresIn: '30d' });
    const u = publicUser(user);
    res.json({
      ok: true,
      token,
      username: u.username,
      expires: u.expires_label,
      sub_expires: u.sub_expires,
      sub_active: u.sub_active,
      plan: u.sub_plan
    });
  } catch (e) {
    console.error('[license-login]', e);
    res.status(500).json({ error: e.message });
  }
});

/** Update display name while logged in */
app.post('/api/loader/set-username', auth, async (req, res) => {
  try {
    let username = String(req.body.username || '').trim().slice(0, 24);
    if (!username) return res.status(400).json({ error: 'username required' });
    await q('UPDATE users SET username = ? WHERE id = ?', [username, req.user.id]);
    const u = await one('SELECT * FROM users WHERE id = ?', [req.user.id]);
    res.json({ ok: true, username: u.username, user: publicUser(u) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


/** Loader Verification page — bind license to logged-in account */
app.post('/api/verify-license', auth, async (req, res) => {
  try {
    const code = String(req.body.key || req.body.license || '').trim().toUpperCase();
    if (!code) return res.status(400).json({ error: 'license required' });
    const k = await one('SELECT * FROM keys WHERE key_code = ?', [code]);
    if (!k) return res.status(404).json({ error: 'invalid license' });
    if (Number(k.revoked) === 1) return res.status(400).json({ error: 'license revoked' });
    if (k.used_by && k.used_by !== req.user.email && !String(k.used_by).startsWith('discord:')) {
      return res.status(400).json({ error: 'license already used on another account' });
    }
    // unused OR reserved by Discord redeem → bind to this account
    if (!k.used_by || String(k.used_by).startsWith('discord:')) {
      await applyKeyToUser(req.user, k);
    }
    const u = await one('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (!isActive(u)) return res.status(400).json({ error: 'subscription not active' });
    res.json({ ok: true, user: publicUser(u) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/redeem', auth, async (req, res) => {
  try {
    const code = String(req.body.key || req.body.code || '').trim().toUpperCase();
    if (!code) return res.status(400).json({ error: 'key required' });
    const k = await one('SELECT * FROM keys WHERE key_code = ?', [code]);
    if (!k) return res.status(404).json({ error: 'invalid key' });
    if (Number(k.revoked) === 1) return res.status(400).json({ error: 'key revoked' });
    if (k.used_by) return res.status(400).json({ error: 'key already used' });
    await applyKeyToUser(req.user, k);
    const u = await one('SELECT * FROM users WHERE id = ?', [req.user.id]);
    res.json({ ok: true, user: publicUser(u) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/loader/session', auth, async (req, res) => {
  const u = publicUser(req.user);
  if (!u.sub_active && req.user.role === 'user') {
    return res.status(403).json({ error: 'subscription expired', user: u, needs_verification: true });
  }
  res.json({
    ok: true,
    user: u.username,
    email: u.email,
    role: u.role,
    expires: u.expires_label,
    sub_expires: u.sub_expires,
    sub_active: u.sub_active
  });
});

app.get('/api/loader/payload-info', auth, async (req, res) => {
  res.json({ ok: true, dll: dllMeta() });
});

app.get('/api/loader/payload', auth, async (req, res) => {
  try {
    const u = await one('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (!isActive(u) && u.role === 'user') {
      return res.status(403).json({ error: 'subscription expired' });
    }
    if (!fs.existsSync(DLL_PATH)) {
      return res.status(503).json({ error: 'payload not staged — put velocity.dll in server/private and redeploy' });
    }
    const meta = dllMeta();
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment; filename="module.bin"');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('X-Phantom-Dll-Sha1', meta.sha1 || '');
    res.setHeader('X-Phantom-Dll-Size', String(meta.size || 0));
    fs.createReadStream(DLL_PATH).pipe(res);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const rows = await all('SELECT * FROM users ORDER BY created_at DESC');
  res.json({ users: rows.map(publicUser) });
});

app.post('/api/admin/keys', auth, adminOnly, async (req, res) => {
  const plan = normalizePlan(req.body.plan);
  const note = String(req.body.note || '');
  const id = uid();
  const key_code = genKey(plan);
  await q('INSERT INTO keys (id,key_code,plan,note,created_at) VALUES (?,?,?,?,?)',
    [id, key_code, plan, note, now()]);
  res.json({ key: key_code, plan, duration_ms: planMs(plan) });
});

app.get('/api/admin/keys', auth, adminOnly, async (req, res) => {
  const rows = await all('SELECT * FROM keys ORDER BY created_at DESC LIMIT 300');
  res.json({ keys: rows });
});

app.post('/api/admin/revoke-sub', auth, adminOnly, async (req, res) => {
  const email = String(req.body.email || '').toLowerCase();
  await q('UPDATE users SET sub_plan = NULL, sub_expires = 0 WHERE email = ?', [email]);
  res.json({ ok: true });
});

app.post('/api/admin/grant-sub', auth, adminOnly, async (req, res) => {
  const email = String(req.body.email || '').toLowerCase();
  const plan = normalizePlan(req.body.plan);
  const u = await one('SELECT * FROM users WHERE email = ?', [email]);
  if (!u) return res.status(404).json({ error: 'user not found' });
  const base = Math.max(Number(u.sub_expires || 0), now());
  await q('UPDATE users SET sub_plan = ?, sub_expires = ? WHERE id = ?', [plan, base + planMs(plan), u.id]);
  res.json({ ok: true, user: publicUser(await one('SELECT * FROM users WHERE id = ?', [u.id])) });
});

app.post('/api/admin/ban', auth, adminOnly, async (req, res) => {
  const email = String(req.body.email || '').toLowerCase();
  await q('UPDATE users SET banned = 1, sub_expires = 0 WHERE email = ?', [email]);
  res.json({ ok: true });
});

/**
 * sell.app webhook — auto create license on paid order
 * Map product name/id to plan via env or body
 * Success page should redirect to: PUBLIC_API_URL/license?order=ORDER_ID
 */
app.post('/webhooks/sellapp', async (req, res) => {
  try {
    if (SELLAPP_WEBHOOK_SECRET) {
      const sig = req.headers['x-sellapp-secret'] || req.headers['authorization'] || '';
      if (!String(sig).includes(SELLAPP_WEBHOOK_SECRET)) {
        return res.status(401).json({ error: 'bad secret' });
      }
    }
    const body = req.body || {};
    const data = body.data || body.order || body;
    const orderId = String(
      data.id || data.order_id || body.order_id || body.id || uid()
    );
    const productName = String(
      (data.product && (data.product.name || data.product.title)) ||
      data.product_name ||
      data.name ||
      body.product ||
      '1 month'
    ).toLowerCase();
    const plan = normalizePlan(productName);
    const existing = await one('SELECT * FROM keys WHERE order_id = ?', [orderId]);
    if (existing) {
      return res.json({ ok: true, key: existing.key_code, order_id: orderId, reused: true });
    }
    const key_code = genKey(plan);
    await q(
      'INSERT INTO keys (id,key_code,plan,note,created_at,order_id) VALUES (?,?,?,?,?,?)',
      [uid(), key_code, plan, 'sellapp:' + orderId, now(), orderId]
    );
    const licenseUrl = (PUBLIC_API_URL || '') + '/license?order=' + encodeURIComponent(orderId);
    console.log('[sellapp] key', key_code, 'order', orderId, 'plan', plan);
    res.json({ ok: true, key: key_code, plan, order_id: orderId, license_url: licenseUrl });
  } catch (e) {
    console.error('[sellapp]', e);
    res.status(500).json({ error: e.message });
  }
});

/** Discord bot calls this to redeem + get loader link */
app.post('/api/discord/redeem', async (req, res) => {
  try {
    const secret = process.env.DISCORD_API_SECRET || SELLAPP_WEBHOOK_SECRET || JWT_SECRET;
    if (req.headers['x-discord-secret'] !== secret) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    const code = String(req.body.key || '').trim().toUpperCase();
    const discord_id = String(req.body.discord_id || '');
    const discord_tag = String(req.body.discord_tag || '');
    if (!code || !discord_id) return res.status(400).json({ error: 'key + discord_id required' });

    const k = await one('SELECT * FROM keys WHERE key_code = ?', [code]);
    if (!k) return res.status(404).json({ error: 'invalid license' });
    if (Number(k.revoked) === 1) return res.status(400).json({ error: 'license revoked' });
    if (k.used_by) {
      // already used — still DM loader if same discord linked
      const u = await one('SELECT * FROM users WHERE email = ? OR discord_id = ?', [k.used_by, discord_id]);
      return res.json({
        ok: true,
        already_used: true,
        key: code,
        loader_url: LOADER_DOWNLOAD_URL,
        message: 'License already redeemed. Here is the loader.'
      });
    }

    // mark key reserved for this discord (used_by stores discord until account binds)
    await q('UPDATE keys SET used_by = ?, used_at = ? WHERE id = ?',
      ['discord:' + discord_id, now(), k.id]);

    // optional: attach discord to a user if email exists later via verify
    res.json({
      ok: true,
      key: code,
      plan: k.plan,
      loader_url: LOADER_DOWNLOAD_URL,
      message: 'License OK. Download the loader and login, then paste this key on the Verification page.'
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

async function startDiscordBot() {
  if (!DISCORD_BOT_TOKEN) {
    console.log('[discord] no DISCORD_BOT_TOKEN — bot disabled');
    return;
  }
  let Discord;
  try {
    Discord = require('discord.js');
  } catch (e) {
    console.error('[discord] install discord.js');
    return;
  }
  const { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder } = Discord;
  const client = new Client({ intents: [GatewayIntentBits.Guilds] });

  client.once('ready', async () => {
    console.log('[discord] logged in as', client.user.tag);
    try {
      const cmd = new SlashCommandBuilder()
        .setName('redeem')
        .setDescription('Redeem your Ph3ntom license')
        .addStringOption(o => o.setName('key').setDescription('License key from sell.app').setRequired(true));
      const rest = new REST({ version: '10' }).setToken(DISCORD_BOT_TOKEN);
      const body = [cmd.toJSON()];
      // guild commands appear in seconds; global can take up to 1 hour
      if (DISCORD_GUILD_ID) {
        await rest.put(Routes.applicationGuildCommands(client.user.id, DISCORD_GUILD_ID), { body });
        console.log('[discord] /redeem registered for guild', DISCORD_GUILD_ID);
      }
      await rest.put(Routes.applicationCommands(client.user.id), { body });
      console.log('[discord] /redeem registered globally');
    } catch (e) {
      console.error('[discord] command register', e.message);
    }
  });

  client.on('interactionCreate', async (interaction) => {
    if (!interaction.isChatInputCommand() || interaction.commandName !== 'redeem') return;
    const chName = (interaction.channel && interaction.channel.name || '').toLowerCase();
    // channel name may include emoji e.g. redeem-sub🎁 — match substring "redeem"
    if (DISCORD_REDEEM_CHANNEL && chName && !chName.includes('redeem')) {
      return interaction.reply({
        content: 'Use this command in a channel whose name contains **redeem** (e.g. redeem-sub).',
        ephemeral: true
      });
    }
    const key = interaction.options.getString('key', true);
    await interaction.deferReply({ ephemeral: true });
    try {
      const secret = process.env.DISCORD_API_SECRET || SELLAPP_WEBHOOK_SECRET || JWT_SECRET;
      const r = await fetch(
        (PUBLIC_API_URL || ('http://127.0.0.1:' + PORT)) + '/api/discord/redeem',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-discord-secret': secret },
          body: JSON.stringify({
            key,
            discord_id: interaction.user.id,
            discord_tag: interaction.user.tag
          })
        }
      );
      const j = await r.json();
      if (!r.ok) {
        await interaction.editReply({ content: 'Error: ' + (j.error || r.status) });
        return;
      }
      const loader = j.loader_url || LOADER_DOWNLOAD_URL || '(set LOADER_DOWNLOAD_URL on server)';
      const dm =
        '**Ph3ntom**\n' +
        'License: `' + (j.key || key) + '`\n' +
        (j.plan ? ('Plan: ' + j.plan + '\n') : '') +
        '\n1. Download loader: ' + loader + '\n' +
        '2. Open loader → Register/Login\n' +
        '3. **Verification** page → paste the same license key\n' +
        '4. Launch\n';
      try {
        await interaction.user.send(dm);
        await interaction.editReply({ content: 'Check your DMs — I sent the loader + instructions.' });
      } catch (e) {
        await interaction.editReply({
          content: 'Could not DM you (open DMs). Loader: ' + loader + '\nKey: `' + key + '`'
        });
      }
    } catch (e) {
      await interaction.editReply({ content: 'Server error: ' + e.message });
    }
  });

  client.login(DISCORD_BOT_TOKEN).catch(e => console.error('[discord] login', e.message));
}

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log('[phantom] auth on :' + PORT);
      console.log('[phantom] DLL', DLL_PATH, dllMeta());
      startDiscordBot();
    });
  })
  .catch((e) => {
    console.error('[phantom] DB init failed', e);
    process.exit(1);
  });
