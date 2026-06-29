/**
 * Kalshi CORS proxy — Cloudflare Worker (with resilient caching)
 * --------------------------------------------------------------
 * Kalshi's API (https://api.elections.kalshi.com) blocks browser requests
 * (403 when an Origin header is present) AND rate-limits Cloudflare's shared
 * egress IPs (429 "too many requests"). This Worker:
 *   1. fetches Kalshi server-side with no Origin header,
 *   2. caches each successful response in Cloudflare's cache,
 *   3. serves the cached copy without re-hitting Kalshi while it's still fresh,
 *   4. and serves the last good copy (stale) if Kalshi is throttling — so one
 *      success keeps the app working through 429 storms.
 *
 * Only read-only GETs under /trade-api/ are forwarded. No keys, no writes.
 *
 * Deploy: dash.cloudflare.com → Workers & Pages → your Worker → Edit code →
 * paste this whole file → Deploy.
 *
 * Test:  https://YOUR-WORKER-URL/trade-api/v2/events?series_ticker=KXMLBKS&status=open&limit=2
 */

const KALSHI_ORIGIN = "https://api.elections.kalshi.com";
const FRESH_MS = 60 * 1000;     // serve cache without touching Kalshi for 60s
const UA = "Mozilla/5.0 (compatible; bullpen/1.0)";

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

    // 1) fresh cache hit → serve immediately, never touch Kalshi
    const cached = await cache.match(cacheKey);
    if (cached) {
      const age = Date.now() - Number(cached.headers.get("x-cached-at") || 0);
      if (age < FRESH_MS) return withCors(cached, "fresh");
    }

    // 2) try Kalshi (one quick retry on 429)
    let upstream = await tryKalshi(target);
    if (upstream && upstream.status === 429) { await sleep(400); upstream = await tryKalshi(target); }

    if (upstream && upstream.ok) {
      const body = await upstream.text();
      const headers = new Headers({
        "content-type": "application/json",
        "cache-control": "public, max-age=60",
        "x-cached-at": String(Date.now()),
        "x-proxy-cache": "miss",
      });
      const store = new Response(body, { status: 200, headers });
      ctx.waitUntil(cache.put(cacheKey, store.clone()));
      return cors(store);
    }

    // 3) Kalshi failed (429 / 5xx / network) → serve last good copy if we have one
    if (cached) return withCors(cached, "stale");

    // 4) nothing to fall back on
    const status = upstream ? upstream.status : 502;
    return cors(json({ error: "kalshi unavailable", status, note: "rate-limited and no cached copy yet — retry shortly" }, status));
  },
};

async function tryKalshi(target) {
  try {
    return await fetch(target, { method: "GET", headers: { accept: "application/json", "user-agent": UA } });
  } catch (e) { return null; }
}
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function cors(resp) {
  resp.headers.set("Access-Control-Allow-Origin", "*");
  resp.headers.set("Access-Control-Allow-Methods", "GET,OPTIONS");
  resp.headers.set("Access-Control-Allow-Headers", "*");
  return resp;
}
function withCors(resp, cacheState) {
  const h = new Headers(resp.headers);
  h.set("x-proxy-cache", cacheState);
  return cors(new Response(resp.body, { status: 200, headers: h }));
}
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });
}
