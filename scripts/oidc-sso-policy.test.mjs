import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const read = (name) => readFileSync(new URL(`../supabase/migrations/${name}`, import.meta.url), "utf8");
const migration = read("20261005000001_oidc_sso.sql");
const samlBarrier = read("20260923000021_tenant_saml_provider_barrier.sql");

function functionBody(sql, name) {
	const start = sql.search(new RegExp(`create or replace function public\\.${name}\\(`, "i"));
	assert.ok(start >= 0, `${name} is not defined`);
	const end = sql.indexOf("\n$$;", start);
	return sql.slice(start, end + 4);
}

test("every OIDC table is service-role only", () => {
	const tables = ["oidc_providers", "oidc_tenant_domains", "oidc_auth_requests", "oidc_identities", "oidc_login_tickets", "oidc_sso_sessions"];
	for (const table of tables) {
		assert.match(migration, new RegExp(`alter table public\\.${table} enable row level security`, "i"), table);
		assert.match(migration, new RegExp(`create table public\\.${table}\\b`, "i"), table);
	}
	assert.match(migration, /revoke all on public\.oidc_providers[\s\S]+from public, anon, authenticated;/i);
	assert.match(migration, /grant select, insert, update, delete on public\.oidc_providers[\s\S]+to service_role;/i);
	assert.doesNotMatch(migration, /create policy/i, "no RLS policy may expose OIDC tables to end users");
	assert.doesNotMatch(migration, /grant [^;]*to (authenticated|anon|public)\b[^;]*oidc_(providers|identities|auth_requests|login_tickets|sso_sessions|tenant_domains)/i);
});

test("client secrets are never stored: only a reference to an Edge secret", () => {
	assert.match(migration, /client_secret_ref text check \(client_secret_ref is null or client_secret_ref ~ '\^\[A-Z0-9_\]\{1,40\}\$'\)/);
	assert.doesNotMatch(migration, /client_secret\s+text/i);
	assert.match(migration, /check \(token_auth_method = 'none' or client_secret_ref is not null\)/i);
});

test("provider constraints: https issuer, asymmetric algorithms only, bounded lifetimes", () => {
	assert.match(migration, /issuer ~ '\^https:\/\/\[\^\\s\?#@\]\+\$'/);
	assert.match(migration, /allowed_algs <@ array\['RS256', 'PS256', 'ES256'\]/i);
	const algs = migration.split("\n").filter((line) => /allowed_algs/.test(line)).join(" ");
	assert.doesNotMatch(algs, /HS(256|384|512)|none/i);
	assert.match(migration, /session_max_seconds integer not null default 43200 check \(session_max_seconds between 900 and 86400\)/);
	assert.match(migration, /clock_skew_seconds integer not null default 60 check \(clock_skew_seconds between 0 and 120\)/);
	assert.match(migration, /tenant_id uuid not null unique references public\.tenants/i, "one provider per tenant");
	assert.match(migration, /check \(not enabled or discovery is not null\)/i);
});

test("a tenant enforces SAML or OIDC, never both, and one provider is required by one policy", () => {
	assert.match(migration, /add column required_oidc_provider_id uuid references public\.oidc_providers\(id\) on delete restrict/i);
	assert.match(migration, /check \(required_saml_provider_id is null or required_oidc_provider_id is null\)/i);
	assert.match(migration, /unique index tenant_identity_policies_oidc_provider_unique[\s\S]+where required_oidc_provider_id is not null/i);
	const outsideFunctions = migration.replace(/\$\$[\s\S]*?\$\$/g, "");
	assert.doesNotMatch(
		outsideFunctions,
		/update public\.tenant_identity_policies|insert into public\.tenant_identity_policies/i,
		"migration must not enforce anything for existing tenants",
	);
});

test("domain verification is tenant-bound and a verified domain has one owner", () => {
	assert.match(migration, /primary key \(tenant_id, domain\)/i);
	assert.match(migration, /create unique index oidc_tenant_domains_verified_unique\s+on public\.oidc_tenant_domains\(domain\) where verified_at is not null/i);
	assert.match(migration, /domain = lower\(domain\)/i);
});

test("authorization requests are single-use, hashed and short-lived", () => {
	assert.match(migration, /state_hash text not null unique check \(state_hash ~ '\^\[0-9a-f\]\{64\}\$'\)/i);
	assert.match(migration, /nonce_hash text not null check/i);
	assert.match(migration, /binding_hash text not null check/i);
	assert.match(migration, /consumed_at timestamptz/i);
	assert.match(migration, /check \(expires_at > created_at\)/i);
	assert.match(migration, /check \(\(mode = 'link'\) = \(link_user_id is not null\)\)/i);
});

test("identities are provider-qualified subjects, never emails", () => {
	assert.match(migration, /primary key \(provider_id, subject\)/i);
	assert.match(migration, /unique \(provider_id, auth_user_id\)/i);
	const bind = functionBody(migration, "oidc_bind_scim_identity");
	assert.match(bind, /su\.external_id = v_subject/i);
	assert.match(bind, /p\.required_oidc_provider_id = p_provider_id/i);
	assert.match(bind, /position\('@' in v_subject\) > 0/i);
	assert.match(bind, /scim_cannot_take_over_manual_membership/i);
	assert.match(bind, /pg_advisory_xact_lock\(hashtextextended\(v_tenant_id::text, 2607\)\)/i);
	assert.doesNotMatch(bind, /email/i, "binding must never use email");
	assert.match(migration, /grant execute on function public\.oidc_bind_scim_identity\(uuid, uuid\) to service_role/i);
});

test("RLS keeps every earlier identity clause and adds a live per-session OIDC binding", () => {
	const body = functionBody(migration, "tenant_identity_access_allowed");
	const previous = functionBody(samlBarrier, "tenant_identity_access_allowed");
	// Everything the SAML-era predicate required is still required, verbatim.
	const clauses = previous.split("\n").map((line) => line.trim()).filter((line) => line.length > 0);
	for (const line of clauses) {
		if (/^(create or replace|returns|language|stable|security definer|set search_path|as \$\$|\$\$;)/i.test(line)) continue;
		assert.ok(body.includes(line), `lost previous clause: ${line}`);
	}
	assert.match(body, /p\.required_oidc_provider_id is not null\s+and not exists/i);
	assert.match(body, /o\.session_id = \(auth\.jwt\(\)->>'session_id'\)::uuid/i);
	assert.match(body, /o\.user_id = auth\.uid\(\)/i);
	assert.match(body, /o\.provider_id = p\.required_oidc_provider_id/i);
	assert.match(body, /o\.tenant_id = p_tenant_id/i);
	assert.match(body, /o\.revoked_at is null/i);
	assert.match(body, /o\.expires_at > now\(\)/i);
	assert.match(body, /security definer\s+set search_path = public, pg_temp/i);
});

test("a login ticket is consumed atomically and ties the Auth session to the provider", () => {
	const body = functionBody(migration, "oidc_record_sso_session");
	assert.match(body, /update public\.oidc_login_tickets\s+set consumed_at = clock_timestamp\(\)\s+where ticket_hash = p_ticket_hash\s+and auth_user_id = p_user_id\s+and consumed_at is null\s+and expires_at > clock_timestamp\(\)/i);
	assert.match(body, /on conflict \(session_id\) do nothing/i);
	assert.match(body, /identity\.oidc\.session_bound/);
	assert.match(body, /where id = v_ticket\.provider_id and enabled/i);
	assert.match(migration, /revoke all on function public\.oidc_record_sso_session\(text, uuid, uuid\) from public, anon, authenticated/i);
});

test("enforcement changes are owner-only, self-lockout-proof and audited", () => {
	const body = functionBody(migration, "oidc_set_enforcement");
	assert.match(body, /m\.role = 'owner'/i);
	assert.match(body, /oidc_enforcement_forbidden/);
	assert.match(body, /length\(coalesce\(btrim\(p_reason\), ''\)\) < 12/i);
	assert.match(body, /p_change_ref is null or p_change_ref !~/i);
	assert.match(body, /oidc_actor_session_required/);
	assert.match(body, /s\.session_id = p_session_id and s\.user_id = p_actor_user_id/i);
	assert.match(body, /v_verified_owner_count < 2 or v_verified_owner_count <> v_owner_count/i);
	assert.match(body, /oidc_existing_identity_conflict/);
	assert.match(body, /oidc_saml_enforcement_active/);
	assert.match(body, /identity\.oidc\.enforcement_enabled/);
	assert.match(body, /identity\.oidc\.enforcement_disabled/);
	assert.match(body, /pg_advisory_xact_lock\(hashtextextended\(p_tenant_id::text, 2607\)\)/i);
	assert.match(migration, /grant execute on function public\.oidc_set_enforcement\(uuid, uuid, uuid, uuid, text, text\) to service_role/i);
	assert.doesNotMatch(migration, /grant execute on function public\.oidc_set_enforcement[^;]*(authenticated|anon)/i);
});

test("break-glass spends one owner recovery code, needs break_glass_enabled, and is audited", () => {
	const body = functionBody(migration, "oidc_break_glass_suspend");
	assert.match(body, /m\.role = 'owner'/i);
	assert.match(body, /p\.break_glass_enabled/i);
	assert.match(body, /p\.required_oidc_provider_id is not null/i);
	assert.match(body, /c\.used_at is null/i);
	assert.match(body, /c\.expires_at > clock_timestamp\(\)/i);
	assert.match(body, /for update of c/i);
	assert.match(body, /set used_at = clock_timestamp\(\)/i);
	assert.match(body, /where id = v_code\.id and used_at is null/i);
	assert.match(body, /identity\.oidc\.break_glass_enforcement_suspended/);
	assert.match(body, /required_oidc_provider_id = null/i);
	// It suspends enforcement only; it never mints, extends or revokes a session itself.
	assert.doesNotMatch(body, /oidc_sso_sessions|auth\.sessions/i);
	assert.match(migration, /revoke all on function public\.oidc_break_glass_suspend\(text, text, text\) from public, anon, authenticated/i);
});

test("every security-definer function pins search_path and is closed to anon/authenticated", () => {
	const definers = [...migration.matchAll(/create or replace function public\.(\w+)\([^)]*\)[\s\S]*?\n\$\$;/g)];
	assert.ok(definers.length >= 6);
	for (const [text, name] of definers) {
		if (!/security definer/i.test(text)) continue;
		assert.match(text, /set search_path = [^\n]*pg_temp/i, `${name} must pin search_path`);
		if (name === "tenant_identity_access_allowed") continue; // intentionally callable by `authenticated` for RLS
		assert.match(migration, new RegExp(`revoke all on function public\\.${name}\\([^)]*\\)\\s+from public, anon, authenticated`, "i"), `${name} must be closed to end users`);
	}
});
