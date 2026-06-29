/**
 * Kalshi CORS proxy — Cloudflare Worker
 * --------------------------------------
 * Kalshi's public API (https://api.elections.kalshi.com) blocks browser requests:
 * it returns 403 the moment a browser "Origin" header is present. This Worker
 * fetches Kalshi server-side (no Origin → 200) and re-serves the JSON with an
 * Access-Control-Allow-Origin header so the static site can read it.
 *
 * Only read-only GETs under /trade-api/ are forwarded. No keys, no auth, no writes.
 *
 * Deploy (free):
 *   1. Sign up at https://dash.cloudflare.com  → Workers & Pages → Create → Worker
 *   2. Replace the starter code with this file, Deploy.
 *   3. Copy your Worker URL (e.g. https://kalshi-proxy.YOURNAME.workers.dev)
 *   4. Paste it into the app's Odds settings (Kalshi proxy URL), or send it to me.
 *
 * Test it: open  https://YOUR-WORKER-URL/trade-api/v2/events?series_ticker=KXMLBKS&status=open&limit=2
 * You should see JSON.
 */

const KALSHI_ORIGIN = "https://api.elections.kalshi.com";

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === "OPTIONS") return cors(new Response(null, { status: 204 }));

    // only allow read-only GETs to the Kalshi trade API
    if (request.method !== "GET") return cors(json({ error: "method not allowed" }, 405));
    const path = url.pathname.replace(/\/{2,}/g, "/"); // tolerate accidental double slashes
    if (!path.startsWith("/trade-api/")) {
      return cors(json({ error: "only /trade-api/* is proxied" }, 400));
    }

    // drop empty-valued query params (e.g. "?limit=") — Kalshi rejects those
    const sp = url.searchParams;
    for (const k of [...sp.keys()]) if (sp.get(k) === "") sp.delete(k);
    const search = sp.toString() ? "?" + sp.toString() : "";

    const target = KALSHI_ORIGIN + path + search;
    try {
      // IMPORTANT:
      //  - no Origin header (that's what Kalshi blocks for browsers)
      //  - edge-cache successful responses ~45s so we don't hit Kalshi on every page
      //    load (avoids 429 rate limits; all visitors share one cached response)
      const upstream = await fetch(target, {
        method: "GET",
        headers: { accept: "application/json", "user-agent": "bullpen-kalshi-proxy" },
        cf: { cacheEverything: true, cacheTtlByStatus: { "200-299": 45, "300-599": 0 } },
      });
      const body = await upstream.text();
      return cors(new Response(body, {
        status: upstream.status,
        headers: { "content-type": "application/json", "cache-control": "public, max-age=45" },
      }));
    } catch (e) {
      return cors(json({ error: "upstream fetch failed", detail: String(e) }, 502));
    }
  },
};

function cors(resp) {
  resp.headers.set("Access-Control-Allow-Origin", "*");
  resp.headers.set("Access-Control-Allow-Methods", "GET,OPTIONS");
  resp.headers.set("Access-Control-Allow-Headers", "*");
  return resp;
}
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });
}
