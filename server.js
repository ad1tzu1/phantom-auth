/**
 * Phantom.wtf auth API
 * Uses Turso (free remote SQLite) when TURSO_DATABASE_URL is set.
 * Falls back to local file only for testing — on Render free use Turso so data never wipes.
 */
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const { randomBytes } = require('crypto');
const { createClient } = require('@libsql/client');

const Stripe = require('stripe');
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const STRIPE_PRICE_WEEK = process.env.STRIPE_PRICE_WEEK || '';
const STRIPE_PRICE_MONTH = process.env.STRIPE_PRICE_MONTH || '';
const PUBLIC_SITE = process.env.PUBLIC_SITE_URL || 'https://superb-cascaron-df7fc8.netlify.app';
const stripe = STRIPE_SECRET ? new Stripe(STRIPE_SECRET) : null;

const PORT = process.env.PHANTOM_PORT || process.env.PORT || 8787;
const JWT_SECRET = process.env.PHANTOM_JWT || 'CHANGE_ME_PHANTOM_SECRET_AXION_2026';
const OWNER_EMAIL = (process.env.PHANTOM_OWNER_EMAIL || 'axion@phantom.wtf').toLowerCase();
const OWNER_PASS = process.env.PHANTOM_OWNER_PASS || 'PhantomOwner#2026';
const DLL_PATH = process.env.PHANTOM_DLL || path.join(__dirname, 'private', 'velocity.dll');

const privateDir = path.join(__dirname, 'private');
fs.mkdirSync(privateDir, { recursive: true });

const TURSO_URL = (
  process.env.TURSO_DATABASE_URL ||
  process.env.TURSO_URL ||
  process.env.LIBSQL_URL ||
  ''
).trim();
const TURSO_TOKEN = (
  process.env.TURSO_AUTH_TOKEN ||
  process.env.TURSO_TOKEN ||
  process.env.LIBSQL_AUTH_TOKEN ||
  ''
).trim();

if (!TURSO_URL) {
  console.error('[phantom] FATAL: TURSO_DATABASE_URL is missing.');
  console.error('[phantom] Render → Environment → add TURSO_DATABASE_URL and TURSO_AUTH_TOKEN');
  console.error('[phantom] Then Manual Deploy again. Env seen keys:', Object.keys(process.env).filter(k => /TURSO|LIBSQL|PHANTOM/i.test(k)).join(', ') || '(none)');
  process.exit(1);
}

if (!TURSO_URL.startsWith('libsql://') && !TURSO_URL.startsWith('https://')) {
  console.error('[phantom] FATAL: TURSO_DATABASE_URL should look like libsql://name-user.turso.io');
  console.error('[phantom] Got:', TURSO_URL.slice(0, 40));
  process.exit(1);
}

console.log('[phantom] connecting Turso:', TURSO_URL.replace(/\/\/.*@/, '//***@'));
const db = createClient({
  url: TURSO_URL,
  authToken: TURSO_TOKEN || undefined
});

function uid() { return randomBytes(16).toString('hex'); }
function now() { return Date.now(); }
function genKey(plan) {
  const a = randomBytes(3).toString('hex').toUpperCase();
  const b = randomBytes(3).toString('hex').toUpperCase();
  const c = randomBytes(3).toString('hex').toUpperCase();
  return `PHM-${(plan || 'week').slice(0, 1).toUpperCase()}-${a}-${b}-${c}`;
}
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
    default: return 7 * d;
  }
}
function normalizePlan(plan) {
  const p = String(plan || 'week').toLowerCase();
  const ok = ['hour','day','week','month','6month','year','lifetime'];
  return ok.includes(p) ? p : 'week';
}
function dllMeta() {
  try {
    if (!fs.existsSync(DLL_PATH)) return { exists: false, size: 0, mtime: 0, sha1: null };
    const st = fs.statSync(DLL_PATH);
    const buf = fs.readFileSync(DLL_PATH);
    const sha1 = require('crypto').createHash('sha1').update(buf).digest('hex').slice(0, 12);
    return { exists: true, size: st.size, mtime: st.mtimeMs, sha1 };
  } catch (e) {
    return { exists: false, size: 0, mtime: 0, sha1: null, error: e.message };
  }
}

async function q(sql, args = []) {
  return db.execute({ sql, args });
}
async function one(sql, args = []) {
  const r = await q(sql, args);
  return r.rows[0] || null;
}
async function all(sql, args = []) {
  const r = await q(sql, args);
  return r.rows;
}

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
    vip_last_grant INTEGER,
    helper_last_grant INTEGER,
    hwid TEXT
  )`);
  await q(`CREATE TABLE IF NOT EXISTS keys (
    id TEXT PRIMARY KEY,
    key_code TEXT UNIQUE NOT NULL,
    plan TEXT NOT NULL,
    note TEXT,
    created_at INTEGER NOT NULL,
    used_by TEXT,
    used_at INTEGER
  )`);
  await q(`CREATE TABLE IF NOT EXISTS sessions (
    token_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  )`);

  let owner = await one('SELECT * FROM users WHERE email = ?', [OWNER_EMAIL]);
  if (!owner) {
    const id = uid();
    const hash = bcrypt.hashSync(OWNER_PASS, 10);
    await q(
      `INSERT INTO users (id,email,username,pass_hash,role,created_at,last_seen,sub_plan,sub_expires)
       VALUES (?,?,?,?,?,?,?,?,?)`,
      [id, OWNER_EMAIL, 'Axion', hash, 'owner', now(), now(), 'lifetime', now() + planMs('lifetime')]
    );
    console.log('[phantom] owner created:', OWNER_EMAIL);
  } else if (owner.role !== 'owner') {
    await q("UPDATE users SET role = 'owner', sub_plan = 'lifetime', sub_expires = ? WHERE id = ?",
      [now() + planMs('lifetime'), owner.id]);
  }
}

function isActive(u) {
  if (!u) return false;
  if (u.role === 'owner' || u.role === 'admin') return true;
  if (!u.sub_expires) return false;
  return Number(u.sub_expires) > now();
}

function publicUser(u) {
  if (!u) return null;
  const active = isActive(u);
  let expires_label = 'Expired';
  if (u.role === 'owner' || u.role === 'admin') expires_label = 'Never';
  else if (active && u.sub_expires) {
    const days = Math.ceil((Number(u.sub_expires) - now()) / (24 * 60 * 60 * 1000));
    if (days >= 36500) expires_label = 'Never';
    else if (days <= 0) expires_label = 'Expires today';
    else if (days === 1) expires_label = '1 day left';
    else expires_label = days + ' days left';
  } else if (!u.sub_expires) expires_label = 'None';

  return {
    id: u.id,
    email: u.email,
    username: u.username,
    role: u.role,
    sub_plan: u.sub_plan,
    sub_expires: u.sub_expires,
    sub_active: active,
    expires_label,
    last_seen: u.last_seen
  };
}

async function applyRoleGrants(u) {
  if (!u) return;
  if (u.role === 'vip') {
    const last = Number(u.vip_last_grant || 0);
    if (now() - last > 60 * 24 * 60 * 60 * 1000) {
      const base = Math.max(Number(u.sub_expires || 0), now());
      await q('UPDATE users SET sub_plan = ?, sub_expires = ?, vip_last_grant = ? WHERE id = ?',
        ['vip', base + 3 * 24 * 60 * 60 * 1000, now(), u.id]);
    }
  }
  if (u.role === 'helper') {
    const last = Number(u.helper_last_grant || 0);
    if (now() - last > 30 * 24 * 60 * 60 * 1000) {
      const base = Math.max(Number(u.sub_expires || 0), now());
      await q('UPDATE users SET sub_plan = ?, sub_expires = ?, helper_last_grant = ? WHERE id = ?',
        ['helper', base + 20 * 24 * 60 * 60 * 1000, now(), u.id]);
    }
  }
}

async function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : '';
    if (!token) return res.status(401).json({ error: 'no token' });
    const payload = jwt.verify(token, JWT_SECRET);
    const u = await one('SELECT * FROM users WHERE id = ?', [payload.sub]);
    if (!u) return res.status(401).json({ error: 'invalid user' });
    await q('UPDATE users SET last_seen = ? WHERE id = ?', [now(), u.id]);
    await applyRoleGrants(u);
    req.user = await one('SELECT * FROM users WHERE id = ?', [u.id]);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'unauthorized' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || (req.user.role !== 'owner' && req.user.role !== 'admin')) {
    return res.status(403).json({ error: 'admin only' });
  }
  next();
}

const app = express();
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

app.get('/', (req, res) => {
  res.json({ ok: true, name: 'Phantom.wtf', version: 'turso-1.1', turso: !!TURSO_URL });
});
app.get('/api/health', (req, res) => {
  const meta = dllMeta();
  res.json({
    ok: true,
    name: 'Ph3ntom Auth',
    version: 'turso-1.2',
    dll: meta.exists,
    dll_sha1: meta.sha1,
    dll_size: meta.size
  });
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});


app.post('/api/register', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    let username = String(req.body.username || '').trim() || email.split('@')[0];
    if (!email || !password || password.length < 4) {
      return res.status(400).json({ error: 'email + password required' });
    }
    const exists = await one('SELECT id FROM users WHERE email = ?', [email]);
    if (exists) return res.status(409).json({ error: 'email already registered' });
    const id = uid();
    const hash = bcrypt.hashSync(password, 10);
    await q(
      `INSERT INTO users (id,email,username,pass_hash,role,created_at,last_seen)
       VALUES (?,?,?,?,?,?,?)`,
      [id, email, username, hash, 'user', now(), now()]
    );
    const token = jwt.sign({ sub: id }, JWT_SECRET, { expiresIn: '30d' });
    const u = await one('SELECT * FROM users WHERE id = ?', [id]);
    res.json({ token, user: publicUser(u) });
  } catch (e) {
    console.error('[register]', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const u = await one('SELECT * FROM users WHERE email = ?', [email]);
    if (!u || !bcrypt.compareSync(password, u.pass_hash)) {
      return res.status(401).json({ error: 'wrong email or password' });
    }
    await q('UPDATE users SET last_seen = ? WHERE id = ?', [now(), u.id]);
    await applyRoleGrants(u);
    const fresh = await one('SELECT * FROM users WHERE id = ?', [u.id]);
    const token = jwt.sign({ sub: u.id }, JWT_SECRET, { expiresIn: '30d' });
    const pu = publicUser(fresh);
    res.json({
      token,
      user: pu,
      username: pu.username,
      role: pu.role,
      expires: pu.expires_label,
      expires_label: pu.expires_label
    });
  } catch (e) {
    console.error('[login]', e.message);
    res.status(500).json({ error: e.message });
  }
});


app.get('/api/me', auth, async (req, res) => {
  try {
    await applyRoleGrants(req.user);
    const u = await one('SELECT * FROM users WHERE id = ?', [req.user.id]);
    res.json({ user: publicUser(u) });
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
    if (k.used_by) return res.status(400).json({ error: 'key already used' });
    const base = Math.max(Number(req.user.sub_expires || 0), now());
    const exp = base + planMs(k.plan);
    await q('UPDATE users SET sub_plan = ?, sub_expires = ? WHERE id = ?', [k.plan, exp, req.user.id]);
    await q('UPDATE keys SET used_by = ?, used_at = ? WHERE id = ?', [req.user.email, now(), k.id]);
    const u = await one('SELECT * FROM users WHERE id = ?', [req.user.id]);
    res.json({ user: publicUser(u) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/loader/session', auth, async (req, res) => {
  try {
    const u = publicUser(req.user);
    if (!u.sub_active && req.user.role === 'user') {
      return res.status(403).json({ error: 'subscription expired', user: u });
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
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/loader/payload-info', auth, async (req, res) => {
  res.json({ ok: true, dll: dllMeta() });
});

app.get('/api/loader/payload', auth, async (req, res) => {
  try {
    await applyRoleGrants(req.user);
    const u = await one('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (!isActive(u) && u.role === 'user') {
      return res.status(403).json({ error: 'subscription expired' });
    }
    if (!fs.existsSync(DLL_PATH)) {
      return res.status(503).json({ error: 'payload not staged — put velocity.dll in server/private/ and redeploy' });
    }
    // always read from disk on each launch — new GitHub push + Render deploy = new dll
    const meta = dllMeta();
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment; filename="module.bin"');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('X-Phantom-User', u.username);
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
  const rows = await all('SELECT * FROM keys ORDER BY created_at DESC LIMIT 200');
  res.json({ keys: rows });
});

app.post('/api/admin/set-role', auth, adminOnly, async (req, res) => {
  const email = String(req.body.email || '').toLowerCase();
  const role = String(req.body.role || 'user');
  const allowed = ['user', 'vip', 'helper', 'admin', 'owner'];
  if (!allowed.includes(role)) return res.status(400).json({ error: 'bad role' });
  await q('UPDATE users SET role = ? WHERE email = ?', [role, email]);
  res.json({ ok: true });
});

app.post('/api/admin/grant-sub', auth, adminOnly, async (req, res) => {
  const email = String(req.body.email || '').toLowerCase();
  const plan = normalizePlan(req.body.plan);
  const u = await one('SELECT * FROM users WHERE email = ?', [email]);
  if (!u) return res.status(404).json({ error: 'user not found' });
  const base = Math.max(Number(u.sub_expires || 0), now());
  const exp = base + planMs(plan);
  await q('UPDATE users SET sub_plan = ?, sub_expires = ? WHERE id = ?', [plan, exp, u.id]);
  res.json({ ok: true, user: publicUser(await one('SELECT * FROM users WHERE id = ?', [u.id])) });
});

app.post('/api/admin/revoke-sub', auth, adminOnly, async (req, res) => {
  const email = String(req.body.email || '').toLowerCase();
  await q('UPDATE users SET sub_plan = NULL, sub_expires = 0 WHERE email = ?', [email]);
  res.json({ ok: true });
});

app.post('/api/pay/checkout', auth, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'stripe not configured' });
  try {
    const plan = req.body.plan === 'month' ? 'month' : 'week';
    const price = plan === 'month' ? STRIPE_PRICE_MONTH : STRIPE_PRICE_WEEK;
    if (!price) return res.status(503).json({ error: 'price id missing' });
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{ price, quantity: 1 }],
      success_url: PUBLIC_SITE + '/dashboard.html?paid=1',
      cancel_url: PUBLIC_SITE + '/dashboard.html?paid=0',
      customer_email: req.user.email,
      metadata: { user_id: req.user.id, email: req.user.email, plan }
    });
    res.json({ url: session.url });
  } catch (e) {
    res.status(500).json({ error: e.message || 'checkout failed' });
  }
});

app.post('/api/pay/webhook', async (req, res) => {
  if (!stripe) return res.status(503).send('no stripe');
  let event = req.body;
  try {
    const payload = req.rawBody || (Buffer.isBuffer(req.body) ? req.body : Buffer.from(JSON.stringify(req.body)));
    if (STRIPE_WEBHOOK_SECRET) {
      const sig = req.headers['stripe-signature'];
      event = stripe.webhooks.constructEvent(payload, sig, STRIPE_WEBHOOK_SECRET);
    } else if (Buffer.isBuffer(payload)) {
      event = JSON.parse(payload.toString('utf8'));
    }
  } catch (err) {
    return res.status(400).send('webhook error');
  }
  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const plan = (session.metadata && session.metadata.plan) === 'month' ? 'month' : 'week';
      const email = (session.metadata && session.metadata.email) || session.customer_email;
      const userId = session.metadata && session.metadata.user_id;
      let u = userId ? await one('SELECT * FROM users WHERE id = ?', [userId]) : null;
      if (!u && email) u = await one('SELECT * FROM users WHERE email = ?', [String(email).toLowerCase()]);
      if (u) {
        const base = Math.max(Number(u.sub_expires || 0), now());
        await q('UPDATE users SET sub_plan = ?, sub_expires = ? WHERE id = ?', [plan, base + planMs(plan), u.id]);
      }
    }
  } catch (e) {
    console.error('[stripe]', e.message);
  }
  res.json({ received: true });
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log('[phantom] auth on :' + PORT + ' turso=' + !!TURSO_URL);
      console.log('[phantom] DLL path ' + DLL_PATH);
    });
  })
  .catch((e) => {
    console.error('[phantom] DB init failed', e);
    process.exit(1);
  });
