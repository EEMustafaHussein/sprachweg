// =============================================================
//  خادم موقع درب الألمانية — Cloudflare Worker (مجاني)
//  - يخفي مفتاح Gemini (Secret اسمه GEMINI_KEY)
//  - حسابات المستخدمين + لوحة المالك + الرسائل (قاعدة بيانات D1 باسم DB)
//  - المالك: الإيميل المكتوب بمتغير OWNER_EMAIL
// =============================================================
const ALLOWED = ['https://eemustafahussein.github.io'];
const MODELS = ['gemini-flash-lite-latest', 'gemini-flash-latest', 'gemini-3.8-flash'];

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, name TEXT, phone TEXT, pass TEXT, created INTEGER, last INTEGER, data TEXT)`,
  `CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, email TEXT, exp INTEGER)`,
  `CREATE TABLE IF NOT EXISTS config (k TEXT PRIMARY KEY, v TEXT)`,
  `CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, to_email TEXT, title TEXT, body TEXT, created INTEGER)`,
];
let ready = false;

async function sha(s) {
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
}
const token = () => [...crypto.getRandomValues(new Uint8Array(24))].map(x => x.toString(16).padStart(2, '0')).join('');

export default {
  async fetch(req, env) {
    const origin = req.headers.get('Origin') || '';
    const cors = {
      'Access-Control-Allow-Origin': ALLOWED.includes(origin) ? origin : ALLOWED[0],
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };
    const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { ...cors, 'Content-Type': 'application/json' } });
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    if (!ALLOWED.includes(origin)) return new Response('Forbidden', { status: 403, headers: cors });
    const url = new URL(req.url);
    const path = url.pathname;

    // ---------- AI proxy ----------
    if (path === '/' || path === '/ai') {
      const model = url.searchParams.get('model');
      if (req.method !== 'POST' || !MODELS.includes(model)) return json({ error: 'bad request' }, 400);
      const body = await req.text();
      if (body.length > 20000) return json({ error: 'too large' }, 413);
      const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${env.GEMINI_KEY}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
      });
      return new Response(r.body, { status: r.status, headers: { ...cors, 'Content-Type': 'application/json' } });
    }

    // ---------- API ----------
    if (!env.DB) return json({ error: 'no_db' }, 503);
    if (!ready) { for (const q of SCHEMA) await env.DB.prepare(q).run(); ready = true; }
    const OWNER = (env.OWNER_EMAIL || '').trim().toLowerCase();
    const body = req.method === 'POST' ? await req.json().catch(() => ({})) : {};
    if (JSON.stringify(body).length > 400000) return json({ error: 'too large' }, 413);

    const auth = async () => {
      const t = (req.headers.get('Authorization') || '').replace('Bearer ', '');
      if (!t) return null;
      const s = await env.DB.prepare('SELECT email, exp FROM sessions WHERE token=?').bind(t).first();
      if (!s || s.exp < Date.now()) return null;
      return await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(s.email).first();
    };
    const pub = u => ({ email: u.email, name: u.name, phone: u.phone, role: u.email === OWNER ? 'owner' : 'user', created: u.created, last: u.last, data: JSON.parse(u.data || '{}') });
    const session = async email => {
      const t = token();
      await env.DB.prepare('INSERT INTO sessions VALUES (?,?,?)').bind(t, email, Date.now() + 60 * 864e5).run();
      return t;
    };

    if (path === '/api/config' && req.method === 'GET') {
      const r = await env.DB.prepare('SELECT v FROM config WHERE k=?').bind('site').first();
      return json(r ? JSON.parse(r.v) : {});
    }
    if (path === '/api/signup') {
      const email = String(body.email || '').trim().toLowerCase();
      const name = String(body.name || '').trim().slice(0, 80);
      const phone = String(body.phone || '').replace(/[^0-9+]/g, '').slice(0, 20);
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !name || phone.length < 8 || String(body.pass || '').length < 20) return json({ error: 'invalid' }, 400);
      if (await env.DB.prepare('SELECT 1 FROM users WHERE email=?').bind(email).first()) return json({ error: 'exists' }, 409);
      const pass = await sha(body.pass + ':' + email);
      const now = Date.now();
      await env.DB.prepare('INSERT INTO users VALUES (?,?,?,?,?,?,?)').bind(email, name, phone, pass, now, now, JSON.stringify(body.data || {})).run();
      const u = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
      return json({ token: await session(email), user: pub(u) });
    }
    if (path === '/api/check') {
      const email = String(body.email || '').trim().toLowerCase();
      return json({ exists: !!(await env.DB.prepare('SELECT 1 FROM users WHERE email=?').bind(email).first()) });
    }
    if (path === '/api/login') {
      const email = String(body.email || '').trim().toLowerCase();
      const u = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
      if (!u || u.pass !== await sha(body.pass + ':' + email)) return json({ error: 'wrong' }, 401);
      await env.DB.prepare('UPDATE users SET last=? WHERE email=?').bind(Date.now(), email).run();
      return json({ token: await session(email), user: pub(u) });
    }

    const me = await auth();
    if (!me) return json({ error: 'auth' }, 401);

    if (path === '/api/me') return json({ user: pub(me) });
    if (path === '/api/sync') {
      await env.DB.prepare('UPDATE users SET data=?, last=?, name=? WHERE email=?').bind(JSON.stringify(body.data || {}), Date.now(), String(body.name || me.name).slice(0, 80), me.email).run();
      return json({ ok: 1 });
    }
    if (path === '/api/password') {
      if (me.pass !== await sha(body.old + ':' + me.email)) return json({ error: 'wrong' }, 401);
      await env.DB.prepare('UPDATE users SET pass=? WHERE email=?').bind(await sha(body.pass + ':' + me.email), me.email).run();
      return json({ ok: 1 });
    }
    if (path === '/api/messages') {
      const r = await env.DB.prepare("SELECT id,title,body,created,to_email FROM messages WHERE to_email='all' OR to_email=? ORDER BY id DESC LIMIT 50").bind(me.email).all();
      return json({ messages: r.results });
    }
    if (path === '/api/logout') {
      await env.DB.prepare('DELETE FROM sessions WHERE email=? AND token=?').bind(me.email, (req.headers.get('Authorization') || '').replace('Bearer ', '')).run();
      return json({ ok: 1 });
    }

    // ---------- Owner only ----------
    if (me.email !== OWNER) return json({ error: 'forbidden' }, 403);
    if (path === '/api/admin/config') {
      await env.DB.prepare('INSERT INTO config VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').bind('site', JSON.stringify(body.config || {})).run();
      return json({ ok: 1 });
    }
    if (path === '/api/admin/users') {
      const r = await env.DB.prepare('SELECT email,name,phone,created,last,data FROM users ORDER BY created DESC LIMIT 1000').all();
      return json({ users: r.results.map(u => { const d = JSON.parse(u.data || '{}'); return { email: u.email, name: u.name, phone: u.phone, created: u.created, last: u.last, xp: d.xp || 0, level: (d.unlocked || ['A1']).slice(-1)[0], streak: d.streak || 0, role: u.email === OWNER ? 'owner' : 'user' }; }) });
    }
    if (path === '/api/admin/message') {
      const to = body.to === 'all' ? 'all' : String(body.to || '').toLowerCase();
      if (!to || !body.title) return json({ error: 'invalid' }, 400);
      await env.DB.prepare('INSERT INTO messages (to_email,title,body,created) VALUES (?,?,?,?)').bind(to, String(body.title).slice(0, 200), String(body.body || '').slice(0, 4000), Date.now()).run();
      return json({ ok: 1 });
    }
    if (path === '/api/admin/messages') {
      const r = await env.DB.prepare('SELECT * FROM messages ORDER BY id DESC LIMIT 100').all();
      return json({ messages: r.results });
    }
    if (path === '/api/admin/delmsg') {
      await env.DB.prepare('DELETE FROM messages WHERE id=?').bind(+body.id).run();
      return json({ ok: 1 });
    }
    if (path === '/api/admin/delete') {
      const e = String(body.email || '').toLowerCase();
      if (e === OWNER) return json({ error: 'no' }, 400);
      await env.DB.prepare('DELETE FROM users WHERE email=?').bind(e).run();
      await env.DB.prepare('DELETE FROM sessions WHERE email=?').bind(e).run();
      return json({ ok: 1 });
    }
    return json({ error: 'not found' }, 404);
  },
};
