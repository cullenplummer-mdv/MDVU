-- ============================================================================
-- Migration: record_exam_attempt RPC
-- Phase: 1.5b.1
-- Purpose: Atomic write of one exam attempt + N answers + (on pass) one cert.
--
-- Why an RPC (Decision D, locked):
--   The Edge Function in 1.5b.2 needs to write to three tables. Doing that as
--   three separate PostgREST calls means a partial-failure window where the
--   attempt row exists but answers do not, leaving an unauditable row. Wrapping
--   in one Postgres function gives us a single transaction: all rows commit, or
--   none do.
--
-- What this RPC does NOT do:
--   - Admin awareness. The Edge Function checks the admins table and decides
--     whether to call this RPC at all (Decision 10, Decision B).
--   - Grading. Edge Function applies the answer key, computes score and passed,
--     and passes the results in (Decision A).
--   - Auth. RPC trusts its inputs because it runs SECURITY DEFINER, callable
--     only by service_role.
--
-- cert_number generation:
--   Uses a Postgres sequence (mcts_cert_seq) created in this migration. Sequence
--   is concurrency-safe by construction. Gaps are possible on rolled-back
--   transactions; this is acceptable for a customer-visible monotonic number.
--   Format: MCTS-000001.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Sequence for cert numbers. Starts at 1.
-- One sequence per program. If sales_enablement is added in Phase 3, create
-- sales_enablement_cert_seq and branch on program_slug inside the RPC.
-- ----------------------------------------------------------------------------
CREATE SEQUENCE IF NOT EXISTS mcts_cert_seq
  START WITH 1
  INCREMENT BY 1
  NO CYCLE;

-- ----------------------------------------------------------------------------
-- The RPC.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.record_exam_attempt(
  p_tech_id            uuid,
  p_program_slug       text,
  p_content_version_id text,
  p_started_at         timestamptz,
  p_submitted_at       timestamptz,
  p_score              int,
  p_passed             boolean,
  p_answers            jsonb  -- array of {question_id, chosen_option, is_correct, question_type}
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_attempt_id    uuid;
  v_cert_id       uuid;
  v_cert_number   text;
  v_answer        jsonb;
  v_answer_count  int;
BEGIN
  -- ---------------------------------------------------------------------
  -- Input validation. Fail fast and loud. The Edge Function should have
  -- caught most of these already; this is defense in depth and gives
  -- clearer error messages than letting CHECK constraints fire.
  -- ---------------------------------------------------------------------
  IF p_tech_id IS NULL THEN
    RAISE EXCEPTION 'p_tech_id is required';
  END IF;

  IF p_program_slug IS NULL OR p_program_slug = '' THEN
    RAISE EXCEPTION 'p_program_slug is required';
  END IF;

  IF p_content_version_id IS NULL OR p_content_version_id = '' THEN
    -- Decision 9: content_version_id is mandatory for the audit trail.
    -- Defaulting it would silently break warranty traceability.
    RAISE EXCEPTION 'p_content_version_id is required (Decision 9)';
  END IF;

  IF p_score IS NULL THEN
    RAISE EXCEPTION 'p_score is required';
  END IF;

  IF p_score < 0 OR p_score > 100 THEN
    -- CHECK constraint would catch this; clearer error here.
    RAISE EXCEPTION 'p_score must be between 0 and 100, got %', p_score;
  END IF;

  IF p_passed IS NULL THEN
    RAISE EXCEPTION 'p_passed is required';
  END IF;

  IF jsonb_typeof(p_answers) IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'p_answers must be a jsonb array, got %', jsonb_typeof(p_answers);
  END IF;

  v_answer_count := jsonb_array_length(p_answers);
  IF v_answer_count = 0 THEN
    -- An attempt with zero answers is almost certainly a bug. Reject.
    RAISE EXCEPTION 'p_answers must contain at least one answer';
  END IF;

  -- ---------------------------------------------------------------------
  -- Insert the attempt row. Capture the new id for FK use below.
  -- ---------------------------------------------------------------------
  INSERT INTO exam_attempts (
    tech_id,
    program_slug,
    started_at,
    submitted_at,
    score,
    passed,
    content_version_id
  ) VALUES (
    p_tech_id,
    p_program_slug,
    p_started_at,
    p_submitted_at,
    p_score,
    p_passed,
    p_content_version_id
  )
  RETURNING id INTO v_attempt_id;

  -- ---------------------------------------------------------------------
  -- Insert answer rows. Iterate the jsonb array.
  -- ---------------------------------------------------------------------
  FOR v_answer IN SELECT * FROM jsonb_array_elements(p_answers)
  LOOP
    -- Element shape validation. The Edge Function enforces shape (Phase 1.5a
    -- notes: "the application enforces shape, not the database"), but a
    -- missing key here would silently insert NULL into a NOT NULL column
    -- with a confusing error. Catch it cleanly.
    IF v_answer->>'question_id' IS NULL THEN
      RAISE EXCEPTION 'answer element missing question_id: %', v_answer;
    END IF;
    IF v_answer->'chosen_option' IS NULL THEN
      RAISE EXCEPTION 'answer element missing chosen_option: %', v_answer;
    END IF;
    IF v_answer->>'is_correct' IS NULL THEN
      RAISE EXCEPTION 'answer element missing is_correct: %', v_answer;
    END IF;
    IF v_answer->>'question_type' IS NULL THEN
      RAISE EXCEPTION 'answer element missing question_type: %', v_answer;
    END IF;

    INSERT INTO exam_attempt_answers (
      attempt_id,
      question_id,
      chosen_option,
      is_correct,
      question_type
    ) VALUES (
      v_attempt_id,
      v_answer->>'question_id',
      v_answer->'chosen_option',           -- jsonb passthrough, NOT ->>
      (v_answer->>'is_correct')::boolean,
      v_answer->>'question_type'
    );
  END LOOP;

  -- ---------------------------------------------------------------------
  -- Issue cert if passed. Generate cert_number from sequence.
  -- ---------------------------------------------------------------------
  IF p_passed THEN
    -- Format: MCTS-000001. lpad to 6 digits gives 999,999 certs of headroom,
    -- well past any realistic projection.
    -- Guard: the sequence is mcts-specific. If we ever reach this branch
    -- with a different program_slug, that's a bug in the caller.
    IF p_program_slug <> 'mcts' THEN
      RAISE EXCEPTION 'cert_number generation only implemented for mcts; got %', p_program_slug;
    END IF;

    v_cert_number := 'MCTS-' || lpad(nextval('mcts_cert_seq')::text, 6, '0');

    INSERT INTO certificates (
      tech_id,
      program_slug,
      content_version_id,
      score,
      cert_number
      -- issued_at uses default now()
      -- expires_at left null (Decision 3: no expiry)
    ) VALUES (
      p_tech_id,
      p_program_slug,
      p_content_version_id,
      p_score,
      v_cert_number
    )
    RETURNING id INTO v_cert_id;
    -- Note: certificates has UNIQUE (tech_id, program_slug). If this tech
    -- already has an mcts cert, this INSERT raises unique_violation and the
    -- entire transaction rolls back, including the exam_attempts row. That
    -- is intentional: a retake by an already-certified tech should not
    -- create a phantom attempt with no audit-visible outcome. The Edge
    -- Function should detect "already certified" earlier and either skip the
    -- write or implement renewal logic, neither of which is in 1.5b scope.
  END IF;

  -- ---------------------------------------------------------------------
  -- Return shape. Stable contract for the Edge Function (1.5b.2) to consume.
  -- ---------------------------------------------------------------------
  RETURN jsonb_build_object(
    'attempt_id',      v_attempt_id,
    'cert_id',         v_cert_id,           -- null if not passed
    'cert_number',     v_cert_number,       -- null if not passed
    'answers_written', v_answer_count
  );
END;
$$;

-- ----------------------------------------------------------------------------
-- Permissions: only service_role calls this. Revoke from PUBLIC for safety.
-- The Edge Function uses the service role key to invoke it.
-- ----------------------------------------------------------------------------
REVOKE ALL ON FUNCTION public.record_exam_attempt(uuid, text, text, timestamptz, timestamptz, int, boolean, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.record_exam_attempt(uuid, text, text, timestamptz, timestamptz, int, boolean, jsonb) TO service_role;

COMMENT ON FUNCTION public.record_exam_attempt IS
  'Phase 1.5b.1. Atomic write of one exam_attempts row, N exam_attempt_answers rows, and (on pass) one certificates row. Called only by the Phase 1.5b.2 Edge Function via service_role. Has no admin awareness; Edge Function decides whether to call.';
  