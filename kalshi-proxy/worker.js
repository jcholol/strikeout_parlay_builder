/**
 * Kalshi CORS proxy — Cloudflare Worker (authenticated)
 * -----------------------------------------------------
 * Kalshi blocks browser calls (403 with an Origin header) and rate-limits
 * unauthenticated traffic from Cloudflare's shared IPs (429). The fix is to
 * authenticate: signed API-key requests get proper per-account rate limits.
 *
 * The API key is a Key ID + an RSA private key, and every request must be
 * RSA-PSS signed. The private key must stay server-side (NEVER in the browser),
 * so it lives here as a Cloudflare Worker secret.
 *
 * ── Set these in the Worker (Settings → Variables and Secrets) ──
 *   KALSHI_KEY_ID        (variable)  your API key id, e.g. a UUID
 *   KALSHI_PRIVATE_KEY   (secret)    the full PEM private key, BEGIN/END lines included
 *
 * If those aren't set, it falls back to unauthenticated (works, but gets 429s).
 *
 * Only read-only GETs under /trade-api/ are forwarded. No writes/orders.
 *
 * Signing (per Kalshi docs): sign  `${timestampMs}${METHOD}${path}`  where path
 * excludes the query string; RSA-PSS, SHA-256, MGF1-SHA256, salt length 32;
 * base64 the signature. Headers: KALSHI-ACCESS-KEY / -TIMESTAMP / -SIGNATURE.
 */

const KALSHI_ORIGIN = "https://api.elections.kalshi.com";
const FRESH_MS = 30 * 1000;   // serve cache without touching Kalshi for 30s

let _privKey = null;          // cached imported CryptoKey across requests

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return cors(new Response(null, { status: 204 }));
    if (request.method !== "GET") return cors(json({ error: "method not allowed" }, 405));

    const path = url.pathname.replace(/\/{2,}/g, "/");       // tolerate double slashes
    if (!path.startsWith("/trade-api/")) return cors(json({ error: "only /trade-api/* is proxied" }, 400));

    // strip empty query params (e.g. "?limit=") that Kalshi rejects
    const sp = url.searchParams;
    for (const k of [...sp.keys()]) if (sp.get(k) === "") sp.delete(k);
    const search = sp.toString() ? "?" + sp.toString() : "";
    const target = KALSHI_ORIGIN + path + search;

    const cache = caches.default;
    const cacheKey = new Request("https://kalshi-cache" + path + search, { method: "GET" });

    // 1) fresh cache → serve immediately
    const cached = await cache.match(cacheKey);
    if (cached && Date.now() - Number(cached.headers.get("x-cached-at") || 0) < FRESH_MS) {
      return withCors(cached, "fresh");
    }

    // 2) build (optionally signed) request headers
    let headers;
    try {
      headers = await buildHeaders(env, "GET", path);   // signs the path WITHOUT query
    } catch (e) {
      return cors(json({ error: "bad KALSHI_PRIVATE_KEY (must be a PKCS#8 PEM)", detail: String(e) }, 500));
    }

    let upstream = await tryFetch(target, headers);
    if (upstream && upstream.status === 429) { await sleep(400); upstream = await tryFetch(target, headers); }

    if (upstream && upstream.ok) {
      const body = await upstream.text();
      const store = new Response(body, {
        status: 200,
        headers: { "content-type": "application/json", "cache-control": "public, max-age=30", "x-cached-at": String(Date.now()) },
      });
      ctx.waitUntil(cache.put(cacheKey, store.clone()));
      return cors(store);
    }

    // 3) failed → serve last good copy if we have one
    if (cached) return withCors(cached, "stale");

    const status = upstream ? upstream.status : 502;
    const detail = upstream ? await upstream.text().catch(() => "") : "network error";
    return cors(json({ error: "kalshi unavailable", status, detail: detail.slice(0, 300) }, status));
  },
};

/* ---- auth ---- */
async function buildHeaders(env, method, path) {
  const h = { accept: "application/json" };
  if (env && env.KALSHI_KEY_ID && env.KALSHI_PRIVATE_KEY) {
    const ts = Date.now().toString();
    const key = await getPrivateKey(env.KALSHI_PRIVATE_KEY);
    const sig = await crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 32 },
      key,
      new TextEncoder().encode(ts + method + path),
    );
    h["KALSHI-ACCESS-KEY"] = env.KALSHI_KEY_ID;
    h["KALSHI-ACCESS-TIMESTAMP"] = ts;
    h["KALSHI-ACCESS-SIGNATURE"] = bufToB64(sig);
  }
  return h;
}
async function getPrivateKey(pem) {
  if (_privKey) return _privKey;
  let der = pemToDer(pem);
  // Web Crypto only imports PKCS#8 ("BEGIN PRIVATE KEY"). If the key is PKCS#1
  // ("BEGIN RSA PRIVATE KEY"), wrap it into a PKCS#8 PrivateKeyInfo first.
  if (/BEGIN RSA PRIVATE KEY/.test(pem)) der = pkcs1ToPkcs8(new Uint8Array(der));
  _privKey = await crypto.subtle.importKey("pkcs8", der, { name: "RSA-PSS", hash: "SHA-256" }, false, ["sign"]);
  return _privKey;
}
function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const bin = atob(b64);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u.buffer;
}
// minimal DER helpers to wrap a PKCS#1 RSAPrivateKey into PKCS#8 PrivateKeyInfo
function derLen(n) {
  if (n < 0x80) return [n];
  const bytes = [];
  for (let x = n; x > 0; x >>= 8) bytes.unshift(x & 0xff);
  return [0x80 | bytes.length, ...bytes];
}
function derTLV(tag, content) {
  const c = Array.from(content);
  return [tag, ...derLen(c.length), ...c];
}
function pkcs1ToPkcs8(pkcs1) {
  const version = [0x02, 0x01, 0x00];                                  // INTEGER 0
  const algId = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,       // SEQ { OID rsaEncryption, NULL }
                 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
  const pk = derTLV(0x04, pkcs1);                                      // OCTET STRING { pkcs1 }
  return new Uint8Array(derTLV(0x30, [...version, ...algId, ...pk])).buffer;
}
function bufToB64(buf) {
  const u = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s);
}

/* ---- helpers ---- */
async function tryFetch(target, headers) {
  try { return await fetch(target, { method: "GET", headers }); } catch (e) { return null; }
}
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function cors(resp) {
  resp.headers.set("Access-Control-Allow-Origin", "*");
  resp.headers.set("Access-Control-Allow-Methods", "GET,OPTIONS");
  resp.headers.set("Access-Control-Allow-Headers", "*");
  return resp;
}
function withCors(resp, state) {
  const h = new Headers(resp.headers);
  h.set("x-proxy-cache", state);
  return cors(new Response(resp.body, { status: 200, headers: h }));
}
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });
}
