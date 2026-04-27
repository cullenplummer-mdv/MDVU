// Shared CORS headers for MDVU Edge Functions.
//
// For staging we allow any origin because:
//   1. The function is JWT-gated, so an unauthenticated origin gains nothing
//      by being allowed past the CORS preflight.
//   2. Vercel preview URLs are not predictable (mdvu-git-staging-*.vercel.app
//      with hashed suffixes), and locking origins down requires maintaining a
//      changing allowlist for no real security benefit.
//
// For production (Phase 4), tighten this to:
//   "Access-Control-Allow-Origin": "https://mdvu.vercel.app"
// and any other final domains.

export const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
