// supabase/functions/grade-exam/index.ts
//
// Phase 1.5b.2 — grade-exam Edge Function (skeleton + JWT auth + admin lookup).
//
// What this sub-phase delivers:
//   1. A deployable Edge Function reachable at POST /functions/v1/grade-exam
//   2. JWT verification via supabase.auth.getUser(jwt). We do NOT decode the
//      JWT manually because anyone could forge "sub". getUser() validates the
//      signature server-side against Supabase's JWKS.
//   3. Admin lookup against the admins table using the service role client,
//      so RLS can never accidentally hide an admin row from us.
//   4. Three terminal states with distinct semantics:
//        - "admin"   : caller is mdv_super → no rows are written; respond OK
//                      (Decision 10: admins do not pollute the audit trail)
//        - "tech"    : caller is a regular signed-in tech → proceed to grade
//                      (grading itself is 1.5b.3; this stub returns NOT_IMPLEMENTED)
//        - "error"   : auth failed, admin lookup failed, or something else
//                      went wrong → fail closed (Decision C). No grading,
//                      no rows. Tech retries later.
//
// What this sub-phase does NOT do (intentionally):
//   - 1.5b.3: hardcoded answer key and the actual grading logic
//   - 1.5b.4: response shape matching the existing mcts.html results UI,
//             and the mcts.html cutover. Stub response shape below is
//             explicitly placeholder.
//   - 1.5b.5: stripping correct_answer from BAKED_CONTENT
//
// Deploy:
//   supabase functions deploy grade-exam --project-ref emtdcczglhkboftyktiq
//
// Required secrets (set once via supabase secrets set):
//   SUPABASE_URL              (auto-injected by platform; do NOT set manually)
//   SUPABASE_ANON_KEY         (auto-injected by platform)
//   SUPABASE_SERVICE_ROLE_KEY (auto-injected by platform IF you set it via
//                              supabase secrets set; required for admin lookup)
// Verify with: supabase secrets list --project-ref emtdcczglhkboftyktiq
//
// IMPORTANT: SUPABASE_SERVICE_ROLE_KEY is auto-populated for Edge Functions
// in modern Supabase projects, but verify on first deploy. If missing, set
// with: supabase secrets set SUPABASE_SERVICE_ROLE_KEY=<key> --project-ref ...

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";
import { corsHeaders } from "../_shared/cors.ts";

// ─── Types ─────────────────────────────────────────────────────────────────

type CallerRole = "admin" | "tech" | "error";

interface CallerResolution {
  role: CallerRole;
  user_id: string | null;
  // Why the lookup ended up where it did. Logged, never returned to the
  // client. Returning the reason to the client would leak signal about
  // whether a given email exists, etc.
  reason: string;
}

// ─── Constants ─────────────────────────────────────────────────────────────

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
const SUPABASE_SERVICE_ROLE_KEY =
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

// ─── Caller resolution ─────────────────────────────────────────────────────

/**
 * Resolve the caller's identity and role.
 *
 * Steps:
 *   1. Pull the JWT from the Authorization header.
 *   2. Validate it via supabase.auth.getUser(jwt) using the anon-key client.
 *      This call hits Supabase's auth service and verifies the signature.
 *      It is the ONLY trustworthy way to extract user_id from a JWT.
 *   3. Use the service-role client to look up the user_id in the admins
 *      table. Service role bypasses RLS so we cannot be tricked by a SELECT
 *      policy that hides admin rows from the caller.
 *   4. If admins.role = 'mdv_super' → "admin".
 *      If no admins row → "tech".
 *      If lookup itself errors → "error" (fail closed).
 *
 * Why a separate service-role client (not the anon-key client) for the
 * admins lookup: an authenticated tech reading admins via the anon-key
 * client would be subject to RLS. The admins table currently has its own
 * RLS posture which we do not want this function to depend on. Using
 * service-role guarantees the lookup result is determined by data, not by
 * whatever RLS we may add to admins later.
 */
async function resolveCaller(req: Request): Promise<CallerResolution> {
  const authHeader = req.headers.get("Authorization") ?? "";
  if (!authHeader.toLowerCase().startsWith("bearer ")) {
    return { role: "error", user_id: null, reason: "missing_bearer_token" };
  }
  const jwt = authHeader.slice("bearer ".length).trim();
  if (!jwt) {
    return { role: "error", user_id: null, reason: "empty_jwt" };
  }

  // Validate JWT against Supabase auth service.
  const anonClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
  const { data: userData, error: userErr } = await anonClient.auth.getUser(jwt);
  if (userErr || !userData?.user) {
    return {
      role: "error",
      user_id: null,
      reason: `getUser_failed:${userErr?.message ?? "no_user"}`,
    };
  }
  const userId = userData.user.id;

  // Admin lookup, bypassing RLS.
  const adminClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: adminRow, error: adminErr } = await adminClient
    .from("admins")
    .select("role")
    .eq("id", userId)
    .maybeSingle();

  // .maybeSingle() returns data=null + error=null when no row exists.
  // Any actual error (network, schema, etc) goes to error branch.
  if (adminErr) {
    return {
      role: "error",
      user_id: userId,
      reason: `admin_lookup_failed:${adminErr.message}`,
    };
  }

  if (adminRow?.role === "mdv_super") {
    return { role: "admin", user_id: userId, reason: "mdv_super" };
  }

  // Future: if (adminRow?.role === "dealer_admin") -> still "tech" for grading
  // purposes (Decision 10 open question). Phase 3b territory.
  return { role: "tech", user_id: userId, reason: "no_admin_row" };
}

// ─── Request handler ───────────────────────────────────────────────────────

serve(async (req: Request) => {
  // CORS preflight
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return jsonResponse({ error: "method_not_allowed" }, 405);
  }

  // Parse body. We do not yet validate its shape against a schema; that is
  // 1.5b.3's responsibility (along with the answer key and grading).
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonResponse({ error: "invalid_json" }, 400);
  }

  // Resolve caller. Errors here are fail-closed (Decision C).
  const caller = await resolveCaller(req);
  console.log(
    JSON.stringify({
      event: "caller_resolved",
      role: caller.role,
      user_id: caller.user_id,
      reason: caller.reason,
    }),
  );

  if (caller.role === "error") {
    // 401 because every error path in resolveCaller is fundamentally an
    // authentication problem (missing/invalid JWT, or DB lookup failed and
    // we cannot trust ANY claim about who the caller is).
    return jsonResponse({ error: "unauthorized" }, 401);
  }

  // ─── Admin path ──────────────────────────────────────────────────────────
  // Decision 10: mdv_super sees the program but produces no rows.
  // In 1.5b.3 this branch will return a graded result computed from `body`
  // without touching record_exam_attempt. For 1.5b.2 we just confirm the
  // branch is reached.
  if (caller.role === "admin") {
    return jsonResponse({
      status: "admin_bypass",
      message: "Admin walkthrough: graded but no rows written.",
      // TODO 1.5b.3: replace with { score, passed, per-question breakdown }
      // computed from `body.answers`. No exam_attempts/certificates writes.
      // TODO 1.5b.4: shape this response to match existing mcts.html UI.
      _placeholder: true,
    }, 200);
  }

  // ─── Tech path ──────────────────────────────────────────────────────────
  // Real path. 1.5b.3 will:
  //   1. Validate request body shape (program_slug, content_version_id,
  //      started_at, submitted_at, answers[]).
  //   2. Grade against hardcoded answer key.
  //   3. Call record_exam_attempt RPC with the grade and answers.
  //   4. Return a response shaped for the UI (1.5b.4).
  //
  // For 1.5b.2 we confirm the branch is reached and explicitly mark
  // not-yet-implemented so a premature mcts.html cutover surfaces loudly
  // rather than silently dropping submissions.
  return jsonResponse({
    status: "not_implemented",
    message:
      "Auth verified and tech identity resolved. Grading + RPC arrive in 1.5b.3.",
    // TODO 1.5b.3: remove these fields; return real grading result.
    user_id: caller.user_id,
    received_keys: Object.keys((body ?? {}) as Record<string, unknown>),
  }, 501);
});

// ─── Helpers ───────────────────────────────────────────────────────────────

function jsonResponse(payload: unknown, status: number): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}
