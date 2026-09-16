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

// Safety net: never let an unexpected error kill the whole process. Without
// this, a single bad request could crash the server and cause every
// following request to 502 until Render restarts it - which looks exactly
// like what's been happening.
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err);
});
process.on('unhandledRejection', (err) => {
  console.error('[unhandledRejection]', err);
});

function md5Hex(str) {
  try {
    return crypto.createHash('md5').update(str, 'utf8').digest('hex');
  } catch (err) {
    console.error('[md5Hex] MD5 not available, falling back to sha256:', err.message);
    return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
  }
}

function hmacSha256Hex(key, message) {
  return crypto.createHmac('sha256', key).update(message, 'utf8').digest('hex');
}

async function fetchOnce(targetUrl, reqTime, signature, bodyStr, timeoutMs){
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(targetUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Date': reqTime,
        'Authorization': `HMAC-SHA256 Credential=${process.env.COMLINK_ACCESS_KEY},Signature=${signature}`,
      },
      body: bodyStr,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }

async function signedComlinkRequest(path, bodyObj) {
  console.log('[signedComlinkRequest] start', path);

  if (!process.env.COMLINK_URL || !process.env.COMLINK_SECRET_KEY || !process.env.COMLINK_ACCESS_KEY) {
    console.error('[signedComlinkRequest] missing env vars', {
      hasUrl: !!process.env.COMLINK_URL,
      hasSecret: !!process.env.COMLINK_SECRET_KEY,
      hasAccess: !!process.env.COMLINK_ACCESS_KEY,
    });
    throw new Error('Server misconfigured: missing COMLINK_URL/COMLINK_ACCESS_KEY/COMLINK_SECRET_KEY');
  }

  const bodyStr = bodyObj ? JSON.stringify(bodyObj) : '';
  const reqTime = String(Date.now());
  const bodyHash = md5Hex(bodyStr);
  const toSign = reqTime + 'POST' + path + bodyHash;
  const signature = hmacSha256Hex(process.env.COMLINK_SECRET_KEY, toSign);
  const targetUrl = process.env.COMLINK_URL.replace(/\/$/, '') + path;

  console.log('[signedComlinkRequest] calling', targetUrl);

  // Comlink can be mid-cold-start even when it's about to be fine - a 502/503/504
  // there usually means "not ready yet", not a real failure. Retry a few times
  // with a short wait before giving up, so a guildmate never has to manually
  // retry themselves. Bounded to keep the whole thing well under a minute.
  const RETRY_DELAYS_MS = [4000, 8000, 15000]; // up to 3 retries after the first try
  let resp, lastErr;

  for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt++) {
    try {
      resp = await fetchOnce(targetUrl, reqTime, signature, bodyStr, 20000);
    } catch (err) {
      lastErr = err;
      console.error(`[signedComlinkRequest] attempt ${attempt} fetch threw:`, err.message);
      resp = null;
    }

    const upstreamNotReady = resp && [502, 503, 504].includes(resp.status);
    if (resp && resp.ok) break;
    if (!upstreamNotReady && resp) break; // a real error (4xx etc) - don't retry

    if (attempt < RETRY_DELAYS_MS.length) {
      console.log(`[signedComlinkRequest] upstream not ready (status ${resp ? resp.status : 'network error'}), retrying in ${RETRY_DELAYS_MS[attempt]}ms`);
      await sleep(RETRY_DELAYS_MS[attempt]);
    }
  }

  if (!resp) {
    throw new Error(`Could not reach comlink at ${targetUrl}: ${lastErr ? lastErr.message : 'unknown error'}`);
  }

  console.log('[signedComlinkRequest] comlink responded with status', resp.status);

  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    console.error('[signedComlinkRequest] comlink error body:', text.slice(0, 500));
    throw new Error(`Comlink request to ${path} failed (${resp.status}): ${text.slice(0, 300)}`);
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
  console.log('[request]', req.method, req.url);
  try {
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

    console.log('[request] success, roster size', Object.keys(rosterOut).length);
    res.writeHead(200, { 'Content-Type': 'application/json', ...CORS_HEADERS });
    res.end(JSON.stringify({ allyCode, playerName: player.name, roster: rosterOut }));
  } catch (err) {
    console.error('[request] failed:', err.message);
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json', ...CORS_HEADERS });
      res.end(JSON.stringify({ error: String(err.message || err) }));
    }
  }
});

const port = process.env.PORT || 3000;
server.listen(port, () => console.log(`Roster proxy listening on port ${port}`));
