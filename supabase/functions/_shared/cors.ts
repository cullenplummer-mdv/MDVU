// Shared CORS headers for MDVU Edge Functions.
//
// Origin-aware allowlist. Browsers enforce CORS, so the security benefit is
// real but limited to browser-based callers. The function is also JWT-gated
// (Phase 1.5b.2), so a request from a disallowed origin would also fail
// auth even if CORS were wildcard. Defense in depth.
//
// Allowed origins:
//   - https://mdv-university.vercel.app          (production)
//   - https://mdv-university-staging.vercel.app  (staging branch, stable URL)
//
// To add a new origin (e.g. a custom domain at launch, or a local dev URL):
//   add it to ALLOWED_ORIGINS and redeploy. There is no wildcard fallback;
//   unknown origins receive an empty Allow-Origin header, which the browser
//   treats as "not allowed" and blocks the response.

const ALLOWED_ORIGINS = new Set<string>([
  "https://mdv-university.vercel.app",
  "https://mdv-university-staging.vercel.app",
]);

const STATIC_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  // Vary: Origin tells caches (CDN, browser) that the response varies by
  // origin. Without this, an Allow-Origin header for one origin could be
  // cached and served to a request from a different origin.
  "Vary": "Origin",
};

/**
 * Build CORS headers for a response based on the incoming request's Origin.
 *
 * If the origin is in the allowlist, echo it back. If not, omit the
 * Allow-Origin header entirely so the browser blocks the response. We do
 * NOT return a 4xx here — CORS rejection is enforced by the browser, not
 * the server. The actual request still runs server-side; the browser just
 * refuses to expose the response to JavaScript.
 *
 * For preflight (OPTIONS), the same logic applies. If the origin is not
 * allowed, the preflight returns no Allow-Origin header and the browser
 * blocks the real request before it is sent.
 */
export function corsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get("Origin");
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    return { ...STATIC_HEADERS, "Access-Control-Allow-Origin": origin };
  }
  return { ...STATIC_HEADERS };
}
