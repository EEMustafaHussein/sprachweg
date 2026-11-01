// Cloudflare Worker (مجاني) يخفي مفتاح Gemini عن زوار الموقع.
// 1) dash.cloudflare.com → Workers & Pages → Create → Hello World → الصق هذا الكود → Deploy
// 2) Settings → Variables and Secrets → أضف Secret اسمه GEMINI_KEY وقيمته مفتاحك
// 3) انسخ رابط الـ Worker وحطه بـ SITE.aiProxy في index.html
const ALLOWED = ['https://eemustafahussein.github.io'];
const MODELS = ['gemini-flash-lite-latest', 'gemini-flash-latest', 'gemini-3.8-flash'];
export default {
  async fetch(req, env) {
    const origin = req.headers.get('Origin') || '';
    const cors = {
      'Access-Control-Allow-Origin': ALLOWED.includes(origin) ? origin : ALLOWED[0],
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    if (req.method !== 'POST' || !ALLOWED.includes(origin)) return new Response('Forbidden', { status: 403, headers: cors });
    const model = new URL(req.url).searchParams.get('model');
    if (!MODELS.includes(model)) return new Response('Bad model', { status: 400, headers: cors });
    const body = await req.text();
    if (body.length > 20000) return new Response('Too large', { status: 413, headers: cors });
    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${env.GEMINI_KEY}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
    });
    return new Response(r.body, { status: r.status, headers: { ...cors, 'Content-Type': 'application/json' } });
  },
};
