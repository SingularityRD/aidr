-- Credential mutations must use the audited, rate-limited Edge endpoints.
-- RLS membership alone must not bypass ownership, binding or admission checks.
revoke insert, update, delete on public.api_keys, public.enrollment_tokens from authenticated, anon;
