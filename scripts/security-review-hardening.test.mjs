// Static contract for supabase/migrations/20261007120000_security_review_hardening.sql
// and for the function-privilege rule it establishes. The migration cannot be
// executed here (no database); these assertions pin its exact content so a
// regression is caught before deployment, and the privilege scan covers every
// migration in the chain.

import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { test } from "node:test";
import { splitStatements } from "./lib/security-definer-scan.mjs";

const migrationsDir = new URL("../supabase/migrations/", import.meta.url);
const MIGRATION = "20261007120000_security_review_hardening.sql";
// The migration whose per-schema default-privilege revokes could not remove the
// global PUBLIC EXECUTE default; every function created after it needs an
// explicit revoke from PUBLIC.
const CUTOFF = "20260922000002_database_boundary_hardening.sql";

const files = (await readdir(migrationsDir)).filter((name) => name.endsWith(".sql")).sort();
const sources = new Map(
	await Promise.all(files.map(async (name) => [name, await readFile(new URL(name, migrationsDir), "utf8")])),
);
const migration = sources.get(MIGRATION);
const statements = migration ? splitStatements(migration).map((s) => s.text) : [];
const normalize = (sql) => sql.replace(/\s+/g, " ").trim().toLowerCase();

function splitTopLevel(list) {
	const parts = [];
	let depth = 0;
	let current = "";
	for (const char of list) {
		if (char === "(") depth += 1;
		if (char === ")") depth -= 1;
		if (char === "," && depth === 0) {
			parts.push(current);
			current = "";
			continue;
		}
		current += char;
	}
	if (current.trim()) parts.push(current);
	return parts.map((part) => part.trim()).filter(Boolean);
}

function qualified(name) {
	const clean = name.replace(/"/g, "").toLowerCase();
	return clean.includes(".") ? clean : `public.${clean}`;
}

/** Function references `schema.name(args)` in a comma-separated list, keyed by name/arity. */
function functionKeys(list) {
	const keys = [];
	for (const match of list.matchAll(/((?:"?[a-z_][a-z0-9_]*"?\.)?"?[a-z_][a-z0-9_]*"?)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)/gi)) {
		keys.push(`${qualified(match[1])}/${splitTopLevel(match[2]).length}`);
	}
	return keys;
}

function grantees(list) {
	return splitTopLevel(list).map((role) => role.replace(/"/g, "").toLowerCase());
}

/**
 * Replays create/drop/revoke statements over the whole chain and returns every
 * function created after CUTOFF that does not end the chain revoked from PUBLIC.
 * `create or replace` keeps an existing ACL, so replacing an already-revoked
 * function is compliant; a drop resets it.
 */
export function functionsMissingPublicRevoke(chain, cutoff = CUTOFF) {
	const state = new Map();
	const createdAfterCutoff = new Map();
	for (const [file, sql] of chain) {
		for (const { text } of splitStatements(sql)) {
			const create = /^create\s+(or\s+replace\s+)?function\s+((?:"?[a-z_][a-z0-9_]*"?\.)?"?[a-z_][a-z0-9_]*"?)\s*\(/i.exec(text);
			if (create) {
				const open = text.indexOf("(", create.index + create[0].length - 1);
				let depth = 0;
				let close = open;
				for (; close < text.length; close += 1) {
					if (text[close] === "(") depth += 1;
					if (text[close] === ")") depth -= 1;
					if (depth === 0) break;
				}
				const key = `${qualified(create[2])}/${splitTopLevel(text.slice(open + 1, close)).length}`;
				const previous = state.get(key);
				state.set(key, { exists: true, revoked: Boolean(create[1] && previous?.exists && previous.revoked) });
				if (file > cutoff) createdAfterCutoff.set(key, file);
				continue;
			}
			const drop = /^drop\s+function\s+(?:if\s+exists\s+)?([\s\S]+?)(?:\s+(?:cascade|restrict))?$/i.exec(text);
			if (drop) {
				for (const key of functionKeys(drop[1])) state.set(key, { exists: false, revoked: false });
				continue;
			}
			const blanket = /^revoke\s+[\s\S]*?\s+on\s+all\s+functions\s+in\s+schema\s+([\s\S]+?)\s+from\s+([\s\S]+)$/i.exec(text);
			if (blanket) {
				if (!grantees(blanket[2]).includes("public")) continue;
				const schemas = grantees(blanket[1]);
				for (const [key, value] of state) {
					if (value.exists && schemas.includes(key.split(".")[0])) value.revoked = true;
				}
				continue;
			}
			const revoke = /^revoke\s+(?:all(?:\s+privileges)?|execute)\s+on\s+function\s+([\s\S]+?)\s+from\s+([\s\S]+)$/i.exec(text);
			if (revoke && grantees(revoke[2]).includes("public")) {
				for (const key of functionKeys(revoke[1])) {
					const value = state.get(key);
					if (value?.exists) value.revoked = true;
				}
			}
		}
	}
	return [...createdAfterCutoff]
		.filter(([key]) => state.get(key)?.exists && !state.get(key)?.revoked)
		.map(([key, file]) => `${file}: ${key}`);
}

test("the security review migration exists and runs after every function it recreates", () => {
	assert.ok(migration, `${MIGRATION} must exist`);
	for (const file of ["20261005000001_oidc_sso.sql", "20260924000010_idempotent_team_creation.sql", "20260912000019_tenant_lifecycle_rls.sql"]) {
		assert.ok(files.indexOf(file) >= 0 && files.indexOf(file) < files.indexOf(MIGRATION), file);
	}
});

test("a. revokes PUBLIC EXECUTE through the global (not per-schema) default privileges", () => {
	const statement = statements.find((s) => /^alter\s+default\s+privileges/i.test(s));
	assert.ok(statement, "missing ALTER DEFAULT PRIVILEGES");
	assert.equal(normalize(statement), "alter default privileges for role postgres revoke execute on functions from public");
	assert.doesNotMatch(statement, /\bin\s+schema\b/i);
});

test("a. every function created after 20260922000002 carries an explicit revoke from PUBLIC", () => {
	assert.deepEqual(functionsMissingPublicRevoke([...sources]), []);
});

test("a. the privilege scan detects a missing revoke, a drop that resets it, and a compliant replace", () => {
	const later = "20990101000000_later.sql";
	const sample = (sql) => functionsMissingPublicRevoke([[later, sql]], "20990101000000");
	assert.deepEqual(sample("create function public.leak(p uuid) returns int language sql as $$ select 1 $$;"), [`${later}: public.leak/1`]);
	assert.deepEqual(sample("create function app.ok() returns int language sql as $$ select 1 $$; revoke all on function app.ok() from public, anon;"), []);
	assert.deepEqual(sample("create function x(a int, b int) returns int language sql as $$ select 1 $$; revoke all on function x(int, int) from anon;"), [`${later}: public.x/2`]);
	assert.deepEqual(
		functionsMissingPublicRevoke([
			["20000101000000_a.sql", "create function public.f() returns int language sql as $$ select 1 $$; revoke all on function public.f() from public;"],
			["20990101000000_b.sql", "create or replace function public.f() returns int language sql as $$ select 2 $$;"],
		], "20000101000000_a.sql"),
		[],
	);
	assert.deepEqual(
		functionsMissingPublicRevoke([
			["20000101000000_a.sql", "create function public.f() returns int language sql as $$ select 1 $$; revoke all on function public.f() from public;"],
			["20990101000000_b.sql", "drop function if exists public.f(); create or replace function public.f() returns int language sql as $$ select 2 $$;"],
		], "20000101000000_a.sql"),
		["20990101000000_b.sql: public.f/0"],
	);
});

function definition(sql, name) {
	const pattern = new RegExp(`^create\\s+(?:or\\s+replace\\s+)?function\\s+${name.replace(".", "\\.")}\\s*\\(`, "i");
	return splitStatements(sql).map((s) => s.text).filter((text) => pattern.test(text)).at(-1) ?? null;
}

function latestBefore(name, file) {
	let found = null;
	for (const [candidate, sql] of sources) {
		if (candidate >= file) break;
		found = definition(sql, name) ?? found;
	}
	return found;
}

// Function body between the dollar quotes, with line comments removed.
const body = (text) => text?.slice(text.indexOf("$$"), text.lastIndexOf("$$") + 2).replace(/--[^\n]*/g, "") ?? null;

test("b. tenant_identity_access_allowed reveals no tenant policy to a caller without a membership row", () => {
	const text = definition(migration, "public.tenant_identity_access_allowed");
	assert.ok(text);
	const sql = normalize(text);
	assert.match(sql, /security definer set search_path = public, pg_temp/);
	// Session revocation applies to everyone; the tenant clauses only to members.
	const revocation = sql.indexOf("from public.identity_user_session_state");
	const guard = sql.indexOf("not exists ( select 1 from public.tenant_members m where m.tenant_id = p_tenant_id and m.user_id = auth.uid() ) or (");
	assert.ok(revocation > 0 && guard > revocation, "membership guard must follow the caller-level revocation clause");
	for (const clause of ["p.require_mfa", "p.required_saml_provider_id is not null", "p.required_oidc_provider_id is not null"]) {
		assert.ok(sql.indexOf(clause) > guard, `${clause} must sit behind the membership guard`);
	}
	// Apart from the guard, the clauses are the previous (OIDC) definition.
	const previous = normalize(body(latestBefore("public.tenant_identity_access_allowed", MIGRATION)));
	for (const clause of [
		"coalesce(auth.jwt()->>'aal', 'aal1') <> 'aal2'",
		"amr.entry->>'method' = 'sso/saml'",
		"o.provider_id = p.required_oidc_provider_id",
		"o.revoked_at is null and o.expires_at > now()",
		"to_timestamp((auth.jwt()->>'iat')::double precision) <= s.revoked_before",
	]) {
		assert.ok(previous.includes(clause) && sql.includes(clause), clause);
	}
	assert.match(normalize(migration), /revoke all on function public\.tenant_identity_access_allowed\(uuid\) from public, anon;/);
});

test("c. the audit export bucket is forced private on conflict", () => {
	assert.match(
		normalize(migration),
		/insert into storage\.buckets \(id, name, public\) values \('aidr-audit-exports', 'aidr-audit-exports', false\) on conflict \(id\) do update set public = false;/,
	);
});

test("d. create_team_tenant enforces a configurable per-user daily quota under the user lock", () => {
	const sql = normalize(migration);
	assert.match(sql, /create table if not exists app\.team_creation_quota \(.*max_per_day integer not null default 10 check \(max_per_day between 1 and 1000\)/);
	assert.match(sql, /revoke all on app\.team_creation_quota from public, anon, authenticated, service_role;/);
	assert.match(sql, /alter table app\.team_creation_quota enable row level security;/);
	const fn = normalize(definition(migration, "public.create_team_tenant"));
	assert.match(fn, /set search_path = pg_catalog, public, pg_temp/);
	const lock = fn.indexOf("perform pg_advisory_xact_lock(hashtextextended(v_user_id::text, 2611))");
	const replay = fn.indexOf("return v_team; end if;");
	const count = fn.indexOf("select count(*) into v_recent from public.team_creation_requests r where r.actor_user_id = v_user_id and r.created_at > clock_timestamp() - interval '1 day'");
	const refuse = fn.indexOf("if v_recent >= v_quota then raise exception 'team creation quota exceeded' using errcode = '54000'");
	const insert = fn.indexOf("insert into public.tenants");
	assert.ok(lock > 0 && replay > lock && count > replay && refuse > count && insert > refuse, "quota must be checked after the lock and replay, before any insert");
	assert.match(fn, /v_quota := coalesce\(v_quota, 10\)/);
	// Everything else in the function is the 20260924000010 body.
	const previous = normalize(body(definition(sources.get("20260924000010_idempotent_team_creation.sql"), "public.create_team_tenant")));
	const quotaBlock = /v_quota integer; v_recent integer; |select q\.max_per_day .*?end if; (?=v_team_id := gen_random_uuid)/g;
	assert.equal(normalize(body(definition(migration, "public.create_team_tenant"))).replace(quotaBlock, ""), previous);
	assert.match(sql, /revoke all on function public\.create_team_tenant\(text, uuid, text\) from public, anon;/);
});

// Membership helpers that 20261007000050 gated on app.directory_membership_grants.
const DIRECTORY_GATED = ["app.is_tenant_member", "app.is_tenant_member_with_role"];

test("e. tenant helpers resolve pg_catalog first and keep their exact bodies", () => {
	for (const name of [
		"app.current_tenant_id",
		"app.is_tenant_member",
		"app.is_tenant_member_with_role",
		"app.is_tenant_creator",
		"public.is_team_member",
		"public.is_team_member_with_role",
	]) {
		const text = definition(migration, name);
		assert.ok(text, `${name} must be recreated`);
		assert.match(normalize(text), /set search_path = pg_catalog, public, pg_temp as \$\$/, name);
		const previous = latestBefore(name, MIGRATION);
		assert.ok(previous, `${name} has a prior definition`);
		assert.match(normalize(previous), /set search_path = public, pg_catalog/, `${name} previously resolved public first`);
		// This migration re-created the two membership helpers from a body that
		// predates the directory-authoritative gate; 20261008000100 puts it back and
		// test g pins the final state, so their body is not compared here.
		if (DIRECTORY_GATED.includes(name)) continue;
		assert.equal(normalize(body(text)), normalize(body(previous)), `${name} body must be unchanged`);
	}
});

test("g. the directory-authoritative membership gate survives the hardening migration", () => {
	const gate = "and app.directory_membership_grants(tm.tenant_id, tm.user_id, tm.role)";
	const scim = sources.get("20261007000050_scim_directory_authoritative.sql");
	assert.ok(scim);
	const afterEveryMigration = "99999999999999_end.sql";
	for (const name of DIRECTORY_GATED) {
		const final = latestBefore(name, afterEveryMigration);
		assert.ok(final, `${name} must be defined`);
		assert.match(normalize(final), /set search_path = pg_catalog, public, pg_temp as \$\$/, `${name} must resolve pg_catalog first`);
		assert.ok(normalize(final).includes(gate), `${name} must still consult app.directory_membership_grants`);
		// 20261016000400 adds the read-only `auditor` role to the role helper and
		// nothing else: with its two role-list additions removed, the body is
		// still exactly the directory-authoritative one.
		const expected = name === "app.is_tenant_member_with_role" ? withoutAuditor(body(final)) : body(final);
		assert.equal(normalize(expected), normalize(body(definition(scim, name))), `${name} final body must equal the directory-authoritative body`);
	}
	const auditor = sources.get("20261016000400_auditor_role.sql");
	assert.ok(auditor);
	assert.equal(latestBefore("app.is_tenant_member_with_role", afterEveryMigration), definition(auditor, "app.is_tenant_member_with_role"));
});

function withoutAuditor(text) {
	const viewer = "when 'viewer' then array['owner', 'admin', 'member', 'viewer', 'auditor']";
	const level = "when 'auditor' then array['owner', 'admin', 'auditor']";
	const flat = normalize(text);
	assert.ok(flat.includes(viewer) && flat.includes(level), "the auditor role helper keeps exactly the two auditor additions");
	return flat.replace(viewer, "when 'viewer' then array['owner', 'admin', 'member', 'viewer']").replace(` ${level}`, "");
}

test("f. audit export objects are readable only by an owner/admin of the folder tenant behind the identity barrier", () => {
	const policy = statements.find((s) => /^create\s+policy\s+audit_exports_read_own_tenant/i.test(s));
	assert.ok(policy);
	const sql = normalize(policy);
	assert.match(sql, /on storage\.objects for select to authenticated/);
	assert.match(sql, /app\.is_tenant_member_with_role\(\(\(storage\.foldername\(name\)\)\[1\]\)::uuid, 'admin'\)/);
	assert.match(sql, /public\.tenant_identity_access_allowed\(\(\(storage\.foldername\(name\)\)\[1\]\)::uuid\)/);
	assert.match(sql, /when bucket_id = 'aidr-audit-exports' and \(storage\.foldername\(name\)\)\[1\] ~\* '\^\[0-9a-f\]\{8\}/);
	assert.match(sql, /else false end/);
	assert.doesNotMatch(sql, /current_tenant_id/);
	assert.ok(
		statements.findIndex((s) => /^drop\s+policy\s+if\s+exists\s+audit_exports_read_own_tenant/i.test(s)) <
			statements.indexOf(policy),
	);
});
