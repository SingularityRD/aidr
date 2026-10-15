// Static regression gate for the 2026-10-15 control-plane security audit
// (SEC-2..SEC-4). The migrations cannot run here; these assertions read the
// LATEST definition of each function across the whole migration chain, so a
// later migration that drops the fix fails the gate.

import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { test } from "node:test";

const migrationsDir = new URL("../supabase/migrations/", import.meta.url);
const files = (await readdir(migrationsDir)).filter((name) => name.endsWith(".sql")).sort();
const sources = await Promise.all(files.map(async (name) => [name, await readFile(new URL(name, migrationsDir), "utf8")]));
const normalize = (sql) => sql.replace(/--[^\n]*/g, "").replace(/\s+/g, " ").trim().toLowerCase();

/** Latest `create [or replace] function public.<name>(` body and the file it came from. */
function latestFunction(name) {
	let latest = null;
	const pattern = new RegExp(`create\\s+(?:or\\s+replace\\s+)?function\\s+public\\.${name}\\s*\\(`, "gi");
	for (const [file, sql] of sources) {
		for (const match of sql.matchAll(pattern)) {
			const rest = sql.slice(match.index);
			const end = rest.indexOf("\n$$;");
			assert.ok(end > 0, `${file}: unterminated ${name}`);
			latest = { file, body: normalize(rest.slice(0, end)) };
		}
	}
	assert.ok(latest, `public.${name} is not defined`);
	return latest;
}

/** Grants and revokes on a function, in chain order, normalized. */
function privilegeStatements(name) {
	const statements = [];
	for (const [, sql] of sources) {
		for (const match of normalize(sql).matchAll(new RegExp(`(grant|revoke) [^;]* on function public\\.${name}\\([^)]*\\)[^;]*;`, "g"))) {
			statements.push(match[0]);
		}
	}
	return statements;
}

test("SEC-2: get_approval_settings requires the tenant identity barrier and is browser-only", () => {
	const fn = latestFunction("get_approval_settings");
	assert.ok(fn.file >= "20261015000400", `latest definition is ${fn.file}`);
	assert.match(fn.body, /security definer/);
	assert.match(fn.body, /set search_path = pg_catalog, public, app, pg_temp/);
	assert.match(fn.body, /not app\.is_tenant_member\(p_tenant_id\)/);
	assert.match(fn.body, /not public\.tenant_identity_access_allowed\(p_tenant_id\)/);
	assert.match(fn.body, /auth\.uid\(\) is null/);
	const privileges = privilegeStatements("get_approval_settings");
	assert.equal(privileges.at(-2), "revoke all on function public.get_approval_settings(uuid) from public, anon, authenticated, service_role;");
	assert.equal(privileges.at(-1), "grant execute on function public.get_approval_settings(uuid) to authenticated;");
});

test("SEC-3: publishing an audit export writes an admin audit row in the same function", () => {
	const fn = latestFunction("finalize_audit_export_object");
	assert.ok(fn.file >= "20261015000410", `latest definition is ${fn.file}`);
	const update = fn.body.indexOf("update public.audit_export_objects set published_at");
	const audit = fn.body.indexOf("insert into public.admin_audit_logs");
	const published = fn.body.lastIndexOf("return 'published'");
	assert.ok(update > 0 && audit > update && published > audit, "audit row must follow the publication update and precede success");
	assert.match(fn.body, /'audit\.export\.published'/);
	assert.match(fn.body, /values \(p_actor_user_id, p_tenant_id,/);
	// The legal-hold barrier and lock stay in front of publication.
	assert.ok(fn.body.indexOf("pg_advisory_xact_lock") < fn.body.indexOf("tenant_legal_holds"));
	assert.ok(fn.body.indexOf("tenant_legal_holds") < update);
	assert.equal(
		privilegeStatements("finalize_audit_export_object").at(-1),
		"grant execute on function public.finalize_audit_export_object(uuid,uuid,text) to service_role;",
	);
});

test("SEC-4: the enrollment-token exchange audits atomically and re-checks an enrolling role", () => {
	const fn = latestFunction("exchange_enrollment_token");
	assert.ok(fn.file >= "20261015000420", `latest definition is ${fn.file}`);
	const keyInsert = fn.body.indexOf("insert into public.api_keys");
	const consume = fn.body.indexOf("update public.enrollment_tokens set consumed_at");
	const audit = fn.body.indexOf("insert into public.admin_audit_logs");
	assert.ok(keyInsert > 0 && consume > keyInsert && audit > consume, "audit must be in the same transaction as the key");
	assert.match(fn.body, /'enroll\.consume_token'/);
	assert.match(fn.body, /m\.role in \('owner', 'admin', 'member'\)/);
	assert.equal(
		privilegeStatements("exchange_enrollment_token").at(-1),
		"grant execute on function public.exchange_enrollment_token(text, text, text, text, text) to service_role;",
	);
});
