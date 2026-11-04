// Oil Stock Manager - zero-dependency Node server (Node 18+)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const FILE = path.join(DATA_DIR, 'db.json');
fs.mkdirSync(DATA_DIR, { recursive: true });

const hash = (p, salt = crypto.randomBytes(16).toString('hex')) =>
  salt + ':' + crypto.scryptSync(p, salt, 32).toString('hex');
const verify = (p, h) => { const [s] = h.split(':'); const a = Buffer.from(hash(p, s)), b = Buffer.from(h); return a.length === b.length && crypto.timingSafeEqual(a, b); };

let DB, pool = null;
const defaults = () => ({
  secret: crypto.randomBytes(32).toString('hex'),
  users: [{ u: 'admin', h: hash('admin123'), role: 'admin' }, { u: 'employee', h: hash('emp123'), role: 'employee' }],
  oils: ['Sunflower Oil', 'Groundnut Oil', 'Gingelly Oil', 'Ghee', 'Coconut Oil', 'Deepam Oil'],
  sizes: ['50 ml', '100 ml', '200 ml', '500 ml', '1 L', '5 L', '15 L'],
  brands: {}, tx: []
});
// Storage: Postgres when DATABASE_URL is set (Neon), otherwise local db.json file.
async function init() {
  if (process.env.DATABASE_URL) {
    const { Pool } = require('pg');
    pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 3, idleTimeoutMillis: 10000, connectionTimeoutMillis: 20000 });
    pool.on('error', e => console.error('pg pool error', e.message));
    await pool.query('CREATE TABLE IF NOT EXISTS kv (id INT PRIMARY KEY, data JSONB NOT NULL)');
    const r = await pool.query('SELECT data FROM kv WHERE id=1');
    DB = r.rows.length ? r.rows[0].data : defaults();
    if (!r.rows.length) await write();
    console.log('Storage: Postgres');
  } else {
    try { DB = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch { DB = defaults(); }
    await write();
    console.log('Storage: file ' + FILE);
  }
}
async function write() {
  if (pool) { await pool.query('INSERT INTO kv(id,data) VALUES(1,$1::jsonb) ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data', [JSON.stringify(DB)]); return; }
  const t = FILE + '.tmp'; fs.writeFileSync(t, JSON.stringify(DB)); fs.renameSync(t, FILE);
}
let chain = Promise.resolve();
function persist() { const p = chain.then(write); chain = p.catch(() => {}); return p; }

const sign = v => crypto.createHmac('sha256', DB.secret).update(v).digest('hex');
function makeToken(u) { const v = u + '|' + (Date.now() + 30 * 864e5); return Buffer.from(v).toString('base64url') + '.' + sign(v); }
function auth(req) {
  const m = /(?:^|;\s*)tok=([^;]+)/.exec(req.headers.cookie || ''); if (!m) return null;
  const [b, s] = m[1].split('.'); if (!b || !s) return null;
  const v = Buffer.from(b, 'base64url').toString(); if (sign(v) !== s) return null;
  const [u, exp] = v.split('|'); if (Date.now() > +exp) return null;
  const x = DB.users.find(a => a.u === u); return x ? { u: x.u, role: x.role } : null;
}
const fails = {};
const json = (res, code, obj, extra = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', ...extra }); res.end(JSON.stringify(obj)); };
function body(req) { return new Promise((ok, no) => { let d = ''; req.on('data', c => { d += c; if (d.length > 1e6) { no(); req.destroy(); } }); req.on('end', () => { try { ok(JSON.parse(d || '{}')); } catch { ok({}); } }); }); }
const str = (v, n = 80) => String(v ?? '').trim().slice(0, n);

const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  if (url === '/healthz') { res.writeHead(200); return res.end('ok'); }
  if (!url.startsWith('/api/')) {
    if (url === '/' || url === '/index.html') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(fs.readFileSync(path.join(__dirname, 'public', 'index.html'))); }
    res.writeHead(404); return res.end('Not found');
  }
  try {
    if (url === '/api/login' && req.method === 'POST') {
      const ip = req.socket.remoteAddress, f = fails[ip] || { n: 0, t: Date.now() };
      if (Date.now() - f.t > 6e5) { f.n = 0; f.t = Date.now(); }
      if (f.n >= 10) return json(res, 429, { error: 'Too many attempts, wait 10 minutes' });
      const { u, p } = await body(req); const x = DB.users.find(a => a.u === str(u));
      if (!x || !verify(String(p || ''), x.h)) { f.n++; fails[ip] = f; return json(res, 401, { error: 'Wrong username or password' }); }
      return json(res, 200, { user: { u: x.u, role: x.role } }, { 'Set-Cookie': `tok=${makeToken(x.u)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000` });
    }
    if (url === '/api/logout') return json(res, 200, {}, { 'Set-Cookie': 'tok=; HttpOnly; Path=/; Max-Age=0' });
    const me = auth(req); if (!me) return json(res, 401, { error: 'Login required' });
    const admin = me.role === 'admin';
    if (url === '/api/state' && req.method === 'GET')
      return json(res, 200, { me, oils: DB.oils, sizes: DB.sizes, brands: DB.brands, tx: DB.tx, users: admin ? DB.users.map(a => ({ u: a.u, role: a.role })) : [] });
    if (url === '/api/tx' && req.method === 'POST') {
      const b = await body(req), n = parseInt(b.n, 10);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(b.d || '') || !DB.oils.includes(b.o) || !(DB.brands[b.o] || []).includes(b.b) || !DB.sizes.includes(b.s) || !['P', 'S'].includes(b.k) || !(n > 0)) return json(res, 400, { error: 'Invalid entry' });
      DB.tx.push({ id: crypto.randomBytes(6).toString('hex'), d: b.d, o: b.o, b: b.b, s: b.s, k: b.k, n, by: me.u, at: Date.now() }); await persist(); return json(res, 200, { ok: 1 });
    }
    if (!admin) { if (req.method !== 'GET') return json(res, 403, { error: 'Admin only' }); }
    if (url.startsWith('/api/tx/') && req.method === 'DELETE') { const id = url.slice(8); DB.tx = DB.tx.filter(t => t.id !== id); await persist(); return json(res, 200, { ok: 1 }); }
    if (url === '/api/config' && req.method === 'POST') {
      const b = await body(req);
      if (Array.isArray(b.oils)) DB.oils = b.oils.map(x => str(x)).filter(Boolean);
      if (Array.isArray(b.sizes)) DB.sizes = b.sizes.map(x => str(x)).filter(Boolean);
      if (b.brands && typeof b.brands === 'object') { DB.brands = {}; for (const o of DB.oils) DB.brands[o] = (Array.isArray(b.brands[o]) ? b.brands[o] : []).map(x => str(x)).filter(Boolean); }
      await persist(); return json(res, 200, { ok: 1 });
    }
    if (url === '/api/user' && req.method === 'POST') {
      const b = await body(req), u = str(b.u, 40), p = String(b.p || ''), role = b.role === 'admin' ? 'admin' : 'employee';
      if (!u || p.length < 4) return json(res, 400, { error: 'Username and password (min 4 chars) required' });
      const x = DB.users.find(a => a.u === u); if (x) { x.h = hash(p); x.role = role; } else DB.users.push({ u, h: hash(p), role });
      await persist(); return json(res, 200, { ok: 1 });
    }
    if (url.startsWith('/api/user/') && req.method === 'DELETE') {
      const u = decodeURIComponent(url.slice(10)); if (u === me.u) return json(res, 400, { error: 'Cannot delete yourself' });
      DB.users = DB.users.filter(a => a.u !== u); await persist(); return json(res, 200, { ok: 1 });
    }
    json(res, 404, { error: 'Not found' });
  } catch (e) { console.error(e); json(res, 500, { error: 'Server error' }); }
});
init().then(() => server.listen(PORT, () => console.log('Oil Stock Manager running on port ' + PORT))).catch(e => { console.error('Startup failed', e); process.exit(1); });
