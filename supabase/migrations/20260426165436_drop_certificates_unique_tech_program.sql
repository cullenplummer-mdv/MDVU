-- ============================================================================
-- Migration: drop UNIQUE (tech_id, program_slug) on certificates
-- Phase: 1.5b.1 follow-up
-- Reason: Free retakes are the intended user behavior. Each pass produces a
--   new cert row. The original constraint forced "one cert per tech per
--   program ever," which would cause the record_exam_attempt RPC to roll back
--   on legitimate retakes after a previous pass.
--
-- Customer-facing "your cert number" UI should select the most recent passing
-- cert (ORDER BY issued_at DESC LIMIT 1). Cert numbers remain globally unique
-- via certificates_cert_number_key, untouched by this migration.
--
-- Idempotent: uses IF EXISTS so re-application against a database where the
-- constraint is already dropped (e.g. staging post-2026-04-26) is a no-op.
-- ============================================================================

ALTER TABLE certificates
  DROP CONSTRAINT IF EXISTS certificates_tech_id_program_slug_key;