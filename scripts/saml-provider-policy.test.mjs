import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const migration = readFileSync(new URL("../supabase/migrations/20260923000021_tenant_saml_provider_barrier.sql", import.meta.url), "utf8");
const binding = readFileSync(new URL("../supabase/migrations/20260923000025_scim_saml_identity_binding.sql", import.meta.url), "utf8");
const priorPolicy = readFileSync(new URL("../supabase/migrations/20260912000013_identity_security.sql", import.meta.url), "utf8");

test("tenant SAML enforcement remains optional until a provider UUID is configured", () => {
	assert.match(migration, /add column required_saml_provider_id uuid\s*;/i);
	assert.match(priorPolicy, /create or replace function public\.set_tenant_identity_policy\s*\(\s*p_tenant_id uuid,\s*p_actor_user_id uuid,\s*p_require_mfa boolean,\s*p_break_glass_enabled boolean\s*\)/i);
	assert.doesNotMatch(migration, /update public\.tenant_identity_policies\s+set required_saml_provider_id/i);
});

test("RLS requires one exact SAML method and provider pair across the AMR array", () => {
	assert.match(migration, /create or replace function public\.tenant_identity_access_allowed\(p_tenant_id uuid\)/i);
	assert.match(migration, /p\.required_saml_provider_id is not null\s+and not exists/i);
	assert.match(migration, /jsonb_typeof\(auth\.jwt\(\)->'amr'\) = 'array'/i);
	assert.match(migration, /amr\.entry->>'method' = 'sso\/saml'\s+and amr\.entry->>'provider' = p\.required_saml_provider_id::text/i);
	assert.match(migration, /s\.global_revoke_pending_session_id is not null/i);
	assert.match(migration, /p\.require_mfa[\s\S]+coalesce\(auth\.jwt\(\)->>'aal', 'aal1'\) <> 'aal2'/i);
});

test("all current tenant RLS tables retain the restrictive identity barrier", () => {
	assert.match(migration, /pc\.relrowsecurity/i);
	assert.match(migration, /c\.column_name = 'tenant_id'/i);
	assert.match(migration, /create policy tenant_identity_access_restrict[\s\S]+as restrictive for all to authenticated/i);
});

test("SCIM SAML binding uses one provider-qualified Auth subject, not email", () => {
	assert.match(binding, /unique index tenant_identity_policies_saml_provider_unique/i);
	assert.match(binding, /i\.provider_id = su\.external_id/i);
	assert.match(binding, /i\.provider = 'sso:' \|\| (?:new\.required_saml_provider_id|v_provider_id|p_provider_id)::text/i);
	assert.match(binding, /scim_bind_saml_identity\(p_auth_user_id uuid, p_provider_id uuid\)/i);
	assert.doesNotMatch(binding, /lower\([^\n]*email/i);
	assert.match(binding, /grant execute on function public\.scim_bind_saml_identity\(uuid, uuid\) to service_role/i);
	assert.match(binding, /pg_advisory_xact_lock\(hashtextextended\(new\.tenant_id::text, 2607\)\)/i);
	assert.match(binding, /pg_advisory_xact_lock\(hashtextextended\(p_tenant_id::text, 2607\)\)/i);
});
