/**
 * RotE Guide - Roster Proxy (Render / Node version)
 * ---------------------------------------------------------------------------
 * Same job as the Cloudflare Worker draft: sits between the guide's webpage
 * and the swgoh-comlink instance already running on Render, holding the
 * ACCESS_KEY/SECRET_KEY privately and doing the HMAC request-signing
 * comlink requires. This version runs as a plain Node web service instead,
 * so it can live on the same Render account as comlink itself.
 *
 * IMPORTANT - same caveat as before: the HMAC signing here follows
 * comlink's documented spec exactly, but the relic-field extraction
 * (parseRelicTier below) is a best-effort guess at the raw data shape,
 * since I have no way to call the live service myself to confirm it.
 * If the first test errors or the relic numbers look wrong, send me the
 * raw JSON for one character from the roster and I'll fix that one
 * function - everything else here is unlikely to need changes.
 *
 * ENVIRONMENT VARIABLES (set these in Render's dashboard for THIS service,
 * same "Environment Variables" section you already used for comlink):
 *   COMLINK_URL         e.g. https://ssc-rote-guide.onrender.com
 *   COMLINK_ACCESS_KEY  (the ACCESS_KEY you set on the comlink service)
 *   COMLINK_SECRET_KEY  (the SECRET_KEY you set on the comlink service)
 *
 * USAGE from the guide's page, once deployed:
 *   fetch(`https://YOUR-PROXY-NAME.onrender.com/?allyCode=123456789`)
 *     .then(r => r.json())
 *     .then(data => console.log(data));
 *   // data.roster is { "<internal_char_id>": <relic_tier_number>, ... }
 */

const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

function md5Hex(str) {
  return crypto.createHash('md5').update(str, 'utf8').digest('hex');
}

function hmacSha256Hex(key, message) {
  return crypto.createHmac('sha256', key).update(message, 'utf8').digest('hex');
}

async function signedComlinkRequest(path, bodyObj) {
  const bodyStr = bodyObj ? JSON.stringify(bodyObj) : '';
  const reqTime = String(Date.now());
  const bodyHash = md5Hex(bodyStr);
  const toSign = reqTime + 'POST' + path + bodyHash;
  const signature = hmacSha256Hex(process.env.COMLINK_SECRET_KEY, toSign);

  const resp = await fetch(process.env.COMLINK_URL.replace(/\/$/, '') + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Date': reqTime,
      'Authorization': `HMAC-SHA256 Credential=${process.env.COMLINK_ACCESS_KEY},Signature=${signature}`,
    },
    body: bodyStr,
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`Comlink request to ${path} failed (${resp.status}): ${text}`);
  }
  return resp.json();
}

// Most likely to need a tweak once tested against real data - see the
// caveat in the file header comment.
function parseRelicTier(unit) {
  if (unit.relic && typeof unit.relic.currentTier === 'number') {
    return Math.max(0, unit.relic.currentTier - 2);
  }
  if (typeof unit.relicTier === 'number') return Math.max(0, unit.relicTier - 2);
  if (typeof unit.relic === 'number') return Math.max(0, unit.relic - 2);
  return 0;
}

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS_HEADERS);
    res.end();
    return;
  }

  const allyCode = (url.searchParams.get('allyCode') || '').replace(/[^0-9]/g, '');
  if (!allyCode || allyCode.length < 9) {
    res.writeHead(400, { 'Content-Type': 'application/json', ...CORS_HEADERS });
    res.end(JSON.stringify({ error: 'Provide a valid 9-digit ally code as ?allyCode=123456789' }));
    return;
  }

  try {
    const player = await signedComlinkRequest('/player', {
      payload: { allyCode },
      enums: false,
    });

    const rosterOut = {};
    for (const unit of player.rosterUnit || player.roster || []) {
      const defId = (unit.definitionId || unit.defId || '').split(':')[0];
      if (!defId) continue;
      rosterOut[defId] = parseRelicTier(unit);
    }

    res.writeHead(200, { 'Content-Type': 'application/json', ...CORS_HEADERS });
    res.end(JSON.stringify({ allyCode, playerName: player.name, roster: rosterOut }));
  } catch (err) {
    res.writeHead(502, { 'Content-Type': 'application/json', ...CORS_HEADERS });
    res.end(JSON.stringify({ error: String(err.message || err) }));
  }
});

const port = process.env.PORT || 3000;
server.listen(port, () => console.log(`Roster proxy listening on port ${port}`));
