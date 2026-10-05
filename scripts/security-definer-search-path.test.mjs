import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
	SEARCH_PATH_HARDENING_VERSION,
	securityDefinerWithoutPgTemp,
	splitStatements,
} from "./lib/security-definer-scan.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("the scan flags a SECURITY DEFINER function without an explicit pg_temp", () => {
	const unsafe = `create or replace function public.a() returns int language sql security definer set search_path = public as $$ select 1 $$;`;
	assert.deepEqual(securityDefinerWithoutPgTemp(unsafe).map((f) => f.name), ["public.a"]);

	const noPath = `create function public.b() returns trigger language plpgsql security definer as $$ begin return new; end $$;`;
	assert.equal(securityDefinerWithoutPgTemp(noPath).length, 1);

	// pg_temp only inside the body or a comment does not satisfy the guard.
	const bodyOnly = `create function public.c() returns int language plpgsql security definer set search_path = public as $$ begin -- pg_temp
	  perform 'set search_path = public, pg_temp'; return 1; end $$;`;
	assert.equal(securityDefinerWithoutPgTemp(bodyOnly).length, 1);
});

test("the scan accepts pinned paths, SECURITY INVOKER functions and either clause order", () => {
	const ok = [
		`create function public.a() returns int language sql security definer set search_path = public, pg_catalog, pg_temp as $$ select 1 $$;`,
		`create function public.b() returns int security definer language sql set search_path to pg_catalog, pg_temp as $$ select 1 $$;`,
		`create function public.c() returns int language sql set search_path = public as $$ select 1 $$;`,
		`create function public.d() returns int language sql as $$ select 1 $$ security definer set search_path = '' , pg_temp;`,
	].join("\n");
	assert.deepEqual(securityDefinerWithoutPgTemp(ok), []);
});

test("the statement splitter ignores semicolons in bodies, strings and comments", () => {
	const statements = splitStatements(`select 'a;b'; -- x;y
	/* ; */ create function f() returns int language plpgsql as $q$ begin return 1; end $q$; select 2;`);
	assert.equal(statements.length, 3);
});

test("no migration after the hardening migration adds an unpinned SECURITY DEFINER function", () => {
	const dir = resolve(root, "supabase/migrations");
	const failures = [];
	for (const name of readdirSync(dir).filter((file) => file.endsWith(".sql")).sort()) {
		if (name.slice(0, 14) <= SEARCH_PATH_HARDENING_VERSION) continue;
		for (const finding of securityDefinerWithoutPgTemp(readFileSync(resolve(dir, name), "utf8"))) {
			failures.push(`${name}:${finding.line} ${finding.name}`);
		}
	}
	assert.deepEqual(failures, []);
});

test("the backfill migration is idempotent by construction and skips already pinned functions", () => {
	const sql = readFileSync(resolve(root, "supabase/migrations", `${SEARCH_PATH_HARDENING_VERSION}_security_definer_search_path_pg_temp.sql`), "utf8");
	assert.match(sql, /search_path=\.\*pg_temp/);
	assert.match(sql, /alter table app\.tenant_admission_config enable row level security/i);
	assert.doesNotMatch(sql, /force row level security/i);
});
