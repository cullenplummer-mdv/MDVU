# Phase 1.5b.2 Verification Protocol

Five tests. Negative tests are the important ones; positive tests can pass for the wrong reasons (a function that always returns 200 will pass Test 1).

Run these against the staging project (`emtdcczglhkboftyktiq`) AFTER deploying the function with `supabase functions deploy grade-exam --project-ref emtdcczglhkboftyktiq` and confirming `SUPABASE_SERVICE_ROLE_KEY` is set in function secrets.

The function URL on staging is:
```
https://emtdcczglhkboftyktiq.supabase.co/functions/v1/grade-exam
```

Get a JWT by signing in via the browser (DevTools → Application → Local Storage → look for `sb-emtdcczglhkboftyktiq-auth-token`, the `access_token` field is the JWT). Or run `sb.auth.getSession()` in the console and copy `data.session.access_token`.

---

## Test 1 (positive, tech): tech path returns 501 not_implemented

Sign in as Test Tech One (`cullenplummer@gmail.com`) and grab the JWT. Then:

```bash
curl -i -X POST \
  https://emtdcczglhkboftyktiq.supabase.co/functions/v1/grade-exam \
  -H "Authorization: Bearer $TECH_JWT" \
  -H "Content-Type: application/json" \
  -d '{"program_slug":"mcts","answers":[]}'
```

**Expected:** HTTP 501. Body contains `"status":"not_implemented"` and `"user_id":"<tech uuid>"`. The `received_keys` array contains `["program_slug","answers"]`.

**Why this is the positive test:** 501 is the correct response for the tech path in 1.5b.2. It proves auth succeeded, admin lookup succeeded, and the function correctly identified this caller as not-an-admin. A 200 here would be wrong.

## Test 2 (positive, admin): admin path returns 200 admin_bypass

Sign in as Cullen the mdv_super (`cullen.plummer@mydoorview.com`) and grab the JWT.

```bash
curl -i -X POST \
  https://emtdcczglhkboftyktiq.supabase.co/functions/v1/grade-exam \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"program_slug":"mcts","answers":[]}'
```

**Expected:** HTTP 200. Body contains `"status":"admin_bypass"` and `"_placeholder":true`.

**Why this matters:** confirms the admin lookup correctly identifies an mdv_super and routes to the bypass branch. Decision 10 enforcement starts here.

## Test 3 (negative): no Authorization header → 401 unauthorized

```bash
curl -i -X POST \
  https://emtdcczglhkboftyktiq.supabase.co/functions/v1/grade-exam \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Expected:** HTTP 401. Body: `{"error":"unauthorized"}`.

**Gotcha:** Supabase's gateway may reject the request before it reaches your function with a different 401 error if you forget to pass `--no-verify-jwt` style flags during deploy. The default function deploy enforces JWT presence at the gateway level. In that case you would see a body like `{"code":401,"message":"Missing authorization header"}` from the gateway, not your function's `{"error":"unauthorized"}`. Either is acceptable for this test — both correctly refuse the unauthenticated request. If you see the gateway error, your function's own header check is unreachable, which is fine because the gateway already rejected it.

## Test 4 (negative): garbage JWT → 401 unauthorized

```bash
curl -i -X POST \
  https://emtdcczglhkboftyktiq.supabase.co/functions/v1/grade-exam \
  -H "Authorization: Bearer not.a.real.jwt" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Expected:** HTTP 401. Body: `{"error":"unauthorized"}`. Same gateway caveat as Test 3 applies.

**Why this matters:** confirms `getUser(jwt)` actually validates the signature. If a malformed or signature-invalid JWT slipped through, this would be the most dangerous failure mode of the whole function.

## Test 5 (negative): forged-payload JWT → 401 unauthorized

This is the test that matters most. Take a valid tech JWT and tamper with its payload to claim a different `sub` (user_id), without re-signing it.

```bash
# Decode middle (payload) part of $TECH_JWT
python3 -c "
import base64, json, sys
jwt = '$TECH_JWT'
header, payload, sig = jwt.split('.')
def pad(s): return s + '=' * (-len(s) % 4)
p = json.loads(base64.urlsafe_b64decode(pad(payload)))
print('Original sub:', p['sub'])
# Replace sub with the mdv_super user's UUID (fetch from supabase dashboard)
p['sub'] = 'INSERT-MDV-SUPER-UUID-HERE'
new_payload = base64.urlsafe_b64encode(
    json.dumps(p, separators=(',',':')).encode()
).rstrip(b'=').decode()
print(f'{header}.{new_payload}.{sig}')
"
```

Take the printed forged JWT and send it:

```bash
curl -i -X POST \
  https://emtdcczglhkboftyktiq.supabase.co/functions/v1/grade-exam \
  -H "Authorization: Bearer $FORGED_JWT" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Expected:** HTTP 401. Body: `{"error":"unauthorized"}`.

**Why this is the most important test:** if this returns 200 with `"status":"admin_bypass"`, the function is treating the JWT payload as trustworthy without verifying the signature. That would mean any tech could claim to be an admin. Failure here is a critical security bug.

---

## Logs to check

After running all five tests:
1. Supabase Dashboard → Edge Functions → grade-exam → Logs.
2. You should see five `caller_resolved` log lines with `role` values: `tech`, `admin`, `error`, `error`, `error`.
3. The three `error` rows should have `reason` values like `missing_bearer_token`, `getUser_failed:...`, and `getUser_failed:...`.

If any reason field reveals user-controlled data (PII, JWT contents, etc.), update the logging to redact it before 1.5b.3.

---

## Pass criteria for 1.5b.2

All five tests pass exactly as described. Anything else and 1.5b.3 is BLOCKED until resolved. The whole point of 1.5b.2 being its own sub-phase is that it isolates auth correctness from grading correctness; debugging both at once is harder than debugging each alone.
