// hollow-inbox.js — Webhook ping inbox for Hollow.
// POST /pings — dispatcher posts pings (HMAC verified)
// GET /pings?since=<id> — Hollow polls for new pings
const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const WEBHOOK_SECRET = process.env.HOLLOW_INBOX_SECRET || '';

let pings = [];
let nextId = 1;
// Keep last 1000 pings in memory
const MAX_PINGS = 1000;

function verifySignature(body, sigHeader) {
  if (!WEBHOOK_SECRET) return true;
  const expected = 'sha256=' + crypto.createHmac('sha256', WEBHOOK_SECRET).update(body).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(sigHeader || ''), Buffer.from(expected));
  } catch { return false; }
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  // POST /pings — dispatcher posts a ping
  if (req.method === 'POST' && url.pathname === '/pings') {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      if (!verifySignature(body, req.headers['x-signature'])) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid signature' }));
        return;
      }
      try {
        const data = JSON.parse(body);
        const ping = {
          id: nextId++,
          at: new Date().toISOString(),
          ...data,
        };
        pings.push(ping);
        if (pings.length > MAX_PINGS) pings = pings.slice(-MAX_PINGS);
        console.log(`[inbox] Ping #${ping.id} stored for ${data.agent || 'unknown'}`);
        res.writeHead(202, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, id: ping.id }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // GET /pings?since=<id> — Hollow polls for new pings
  if (req.method === 'GET' && url.pathname === '/pings') {
    const since = parseInt(url.searchParams.get('since') || '0', 10);
    const newPings = pings.filter(p => p.id > since);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ pings: newPings, latest_id: nextId - 1 }));
    return;
  }

  // GET /health
  if (req.method === 'GET' && url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, pings: pings.length }));
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, () => {
  console.log(`Hollow inbox on :${PORT}`);
});
