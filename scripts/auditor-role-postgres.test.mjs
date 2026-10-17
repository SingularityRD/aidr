// Real-PostgreSQL contract for
//   supabase/migrations/20261016000400_auditor_role.sql
// replayed on top of the COMPLETE canonical migration chain.
//
// Runs against AIDR_POSTGRES_TEST_URL=postgres://user@host:port/db (a
// disposable database is created next to it and dropped afterwards) and is
// skipped, visibly, when it is not set.
//
// It proves that `auditor` is a read-only tenant role:
//   * an auditor reads events, policies, the tenant audit trail, the
//     administrative audit trail, compliance evidence, executive/usage
//     reports, the governance scorecard and the member list;
//   * every write path rejects it: direct table writes under RLS (members,
//     tenants, policies, agents, events, audit rows, API keys) and EVERY
//     service-role write RPC that takes (p_tenant_id, p_actor_user_id),
//     swept from the live catalog so a new RPC is covered automatically;
//   * viewers and members still cannot read the administrative trail;
//   * owners/admins can invite or assign `auditor`, the assignment syncs to
//     tenant_members and is audited, and directory mappings cannot grant it.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const admin = process.env.AIDR_POSTGRES_TEST_URL;
const MIGRATION = "20261016000400_auditor_role.sql";

const PLATFORM = `
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
  if not exists (select 1 from pg_roles where rolname = 'supabase_auth_admin') then create role supabase_auth_admin nologin; end if;
end $$;
create schema if not exists auth;
create schema if not exists extensions;
create schema if not exists storage;
create extension if not exists pgcrypto with schema extensions;
create table auth.users (id uuid primary key, email text, raw_user_meta_data jsonb default '{}'::jsonb,
  raw_app_meta_data jsonb default '{}'::jsonb, created_at timestamptz default now(), updated_at timestamptz default now(),
  email_confirmed_at timestamptz, last_sign_in_at timestamptz, is_sso_user boolean default false,
  deleted_at timestamptz, banned_until timestamptz, phone text, is_anonymous boolean default false);
create table auth.sessions (id uuid primary key default gen_random_uuid(), user_id uuid, created_at timestamptz default now(),
  updated_at timestamptz, aal text, not_after timestamptz);
create table auth.identities (id uuid primary key default gen_random_uuid(), user_id uuid, provider text, provider_id text,
  identity_data jsonb, created_at timestamptz default now());
create table auth.mfa_factors (id uuid primary key default gen_random_uuid(), user_id uuid, status text, factor_type text,
  created_at timestamptz default now());
create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
create function auth.role() returns text language sql stable as $$ select nullif(current_setting('request.jwt.claim.role', true), '') $$;
create function auth.jwt() returns jsonb language sql stable as $$ select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;
create table storage.buckets(id text primary key, name text, public boolean, file_size_limit bigint, allowed_mime_types text[]);
create table storage.objects(id uuid primary key default gen_random_uuid(), bucket_id text, name text, owner uuid,
  metadata jsonb, created_at timestamptz default now());
create function storage.foldername(name text) returns text[] language sql immutable as $$ select string_to_array(name, '/') $$;
alter table storage.objects enable row level security;
grant usage on schema auth, extensions, storage to anon, authenticated, service_role;
`;

// Audit-reader RPCs an auditor may call (reads, plus the receipts those reads
// write). Every other (p_tenant_id, p_actor_user_id) RPC must refuse it.
const AUDITOR_ALLOWED_RPCS = new Set([
	"compliance_report_evidence",
	"record_compliance_report",
	"register_audit_export_object",
	"finalize_audit_export_object",
	"abandon_audit_export_object",
]);

// A refused call: an SQL error, or a call that returned without changing any
// tenant state (for example `{"status":"forbidden"}`). Audit and rate-limit
// ledgers are left out of the fingerprint: recording a refusal is allowed.
const REFUSAL = /^([0-9A-Z]{5}: |unchanged: )/;
const FINGERPRINT = `
create function pg_temp.fingerprint() returns text language plpgsql security definer as $fp$
declare v_table regclass; v_digest text; v_out text := '';
begin
  for v_table in
    select c.oid::regclass from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname in ('public', 'app') and c.relkind in ('r', 'p')
       and c.relname !~ '(audit|rate_limit|request_counter)'
     order by 1
  loop
    execute format('select md5(coalesce(string_agg(t::text, %L order by t::text), %L)) from %s t', ',', '', v_table) into v_digest;
    v_out := v_out || v_table::text || '=' || v_digest || ';';
  end loop;
  return md5(v_out);
end $fp$;
grant execute on function pg_temp.fingerprint() to service_role;`;

function psql(url, sql) {
	const result = spawnSync("psql", [url, "-X", "-qAt", "-v", "ON_ERROR_STOP=1"], {
		input: sql, encoding: "utf8", timeout: 120_000, maxBuffer: 1 << 26,
	});
	return { code: result.status ?? 1, stdout: (result.stdout ?? "").trim(), stderr: result.stderr ?? "" };
}

const hash = () => randomBytes(32).toString("hex");

test("auditor is a read-only tenant role on real PostgreSQL", {
	skip: admin ? false : "AIDR_POSTGRES_TEST_URL is not set",
}, async (t) => {
	const name = `aidr_auditor_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
	assert.equal(psql(admin, `create database ${name}`).code, 0);
	const url = new URL(admin);
	url.pathname = `/${name}`;
	const db = url.toString();
	const sql = (text) => {
		const result = psql(db, text);
		assert.equal(result.code, 0, result.stderr);
		return result.stdout;
	};
	const fails = (text, pattern) => {
		const result = psql(db, text);
		assert.notEqual(result.code, 0, `must be refused: ${text.slice(0, 200)}`);
		if (pattern) assert.match(result.stderr, pattern);
	};
	const [T, OWNER, ADMIN, MEMBER, VIEWER, AUDITOR, NEWBIE] = Array.from({ length: 7 }, () => randomUUID());
	const AGENT = randomUUID();
	const marker = randomUUID().slice(0, 8);
	// An authenticated PostgREST session of `user` (aal2, fresh iat).
	const session = (user) => {
		const claims = JSON.stringify({ sub: user, role: "authenticated", aal: "aal2", iat: Math.floor(Date.now() / 1000) });
		return `set role authenticated; set request.jwt.claim.sub = '${user}'; set request.jwt.claim.role = 'authenticated';
			set request.jwt.claims = '${claims}';`;
	};
	const as = (user, text) => sql(`${session(user)} ${text}`);
	const asFails = (user, text, pattern) => fails(`${session(user)} ${text}`, pattern);
	// Rows a DML statement touched, run in a rolled-back transaction.
	const touched = (user, statement) => {
		const result = psql(db, `begin; ${session(user)} with x as (${statement} returning 1) select count(*) from x; rollback;`);
		return result.code === 0 ? Number(result.stdout.split("\n").pop()) : `error: ${result.stderr.split("\n")[0]}`;
	};
	const service = (text) => sql(`set role service_role; ${text}`);
	const serviceFails = (text, pattern) => fails(`set role service_role; ${text}`, pattern);

	try {
		sql(PLATFORM);
		const all = readdirSync(resolve(root, "supabase/migrations")).filter((f) => f.endsWith(".sql")).sort();
		assert.ok(all.includes(MIGRATION), `${MIGRATION} is part of the canonical chain`);
		for (const file of all) {
			const result = psql(db, `begin;\n${readFileSync(resolve(root, "supabase/migrations", file), "utf8")}\ncommit;`);
			assert.equal(result.code, 0, `${file}: ${result.stderr}`);
		}

		const people = [[OWNER, "owner"], [ADMIN, "admin"], [MEMBER, "member"], [VIEWER, "viewer"], [AUDITOR, "auditor"], [NEWBIE, "member"]];
		sql(`
			insert into auth.users(id, email) values ${people.map(([id, role]) => `('${id}', '${role}-${id.slice(0, 6)}-${marker}@example.invalid')`).join(", ")};
			insert into public.tenants(id, name, kind, created_by) values ('${T}', 'Audit ${marker}', 'team', '${OWNER}');
			insert into public.teams(id, tenant_id, name, plan) values ('${T}', '${T}', 'Audit ${marker}', 'free') on conflict (id) do nothing;
			insert into public.team_members(team_id, tenant_id, user_id, role) values
			  ${people.map(([id, role]) => `('${T}', '${T}', '${id}', '${role}')`).join(", ")}
			  on conflict (team_id, user_id) do update set role = excluded.role;
			update app.tenant_admission_config set mode = 'pilot', configured_at = now() where singleton;
			insert into public.entitlements(user_id, tenant_id, included_agents, extra_agents) values ('${OWNER}', '${T}', 10, 0)
			  on conflict do nothing;
			update public.entitlements set included_agents = 10 where tenant_id = '${T}';
			insert into public.pilot_applications(user_id, tenant_id, status) values ('${OWNER}', '${T}', 'approved');
			insert into public.agents(id, user_id, tenant_id, iid) values ('${AGENT}', '${OWNER}', '${T}', 'iid-${marker}');
			insert into public.events(tenant_id, user_id, agent_id, type, event_id, payload)
			  values ('${T}', '${OWNER}', '${AGENT}', 'verdict', 'evt-${marker}', '{"decision":"deny"}');
			insert into public.audit_logs(team_id, tenant_id, user_id, action) values ('${T}', '${T}', '${OWNER}', 'policy.updated');
			insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail) values ('${OWNER}', '${T}', 'scim.token_created', '{}');
			insert into public.team_policies(team_id, tenant_id, content, updated_by, source_sha256)
			  values ('${T}', '${T}', 'policy', '${OWNER}', repeat('a', 64)) on conflict do nothing;`);
		assert.equal(sql(`select role from public.tenant_members where tenant_id = '${T}' and user_id = '${AUDITOR}';`), "auditor",
			"team_members sync carries the auditor role into tenant_members");

		await t.test("role helper: auditor is lateral, read-only", () => {
			const level = (user, min) => as(user, `select app.is_tenant_member_with_role('${T}', '${min}');`);
			assert.equal(level(AUDITOR, "viewer"), "t");
			assert.equal(level(AUDITOR, "auditor"), "t");
			for (const min of ["member", "admin", "owner"]) assert.equal(level(AUDITOR, min), "f", `auditor is not ${min}`);
			assert.equal(level(OWNER, "auditor"), "t");
			assert.equal(level(ADMIN, "auditor"), "t");
			assert.equal(level(MEMBER, "auditor"), "f");
			assert.equal(level(VIEWER, "auditor"), "f");
			assert.equal(as(AUDITOR, `select app.is_tenant_member('${T}');`), "t");
		});

		await t.test("auditor reads events, policies, members and both audit trails", () => {
			const count = (user, table) => Number(as(user, `select count(*) from public.${table} where tenant_id = '${T}';`));
			for (const table of ["events", "audit_logs", "team_policies", "tenant_members"]) {
				assert.equal(count(AUDITOR, table), count(OWNER, table), `${table}: auditor sees what the owner sees`);
			}
			assert.ok(count(AUDITOR, "events") >= 1);
			assert.ok(count(AUDITOR, "audit_logs") >= 1);
			const adminTrail = as(AUDITOR, `select count(*) from public.list_tenant_admin_audit_logs('${T}', 200);`);
			assert.ok(Number(adminTrail) >= 1, "administrative trail is readable");
			for (const user of [MEMBER, VIEWER]) {
				asFails(user, `select * from public.list_tenant_admin_audit_logs('${T}', 50);`, /admin_audit_access_denied/);
			}
			assert.equal(Number(as(AUDITOR, `select count(*) from public.list_team_members_with_email('${T}');`)), people.length);
			asFails(VIEWER, `select * from public.list_team_members_with_email('${T}');`, /team_member_email_access_denied/);
			assert.match(as(AUDITOR, `select public.tenant_usage_report('${T}')::text;`), /^\{/);
			asFails(VIEWER, `select public.tenant_usage_report('${T}');`, /usage_report_access_denied/);
			assert.match(as(AUDITOR, `select public.governance_scorecard('${T}', 30)::text;`), /"window_days": 30/);
			asFails(MEMBER, `select public.governance_scorecard('${T}', 30);`, /governance_forbidden/);
		});

		await t.test("auditor generates compliance evidence and executive reports", () => {
			const evidence = JSON.parse(service(`select public.compliance_report_evidence('${T}', '${AUDITOR}', now() - interval '30 days', now())::text;`));
			assert.equal(evidence.actor_role, "auditor");
			const roles = Object.fromEntries(evidence.access_identity.members_by_role.map((row) => [row.role, row.members]));
			assert.equal(roles.auditor, 1);
			assert.ok(evidence.access_identity.admins.every((row) => ["owner", "admin"].includes(row.role)), "admin list excludes the auditor");
			serviceFails(`select public.compliance_report_evidence('${T}', '${VIEWER}', now() - interval '30 days', now());`, /compliance_report_forbidden/);
			service(`select public.record_compliance_report('${T}', '${AUDITOR}', '${randomUUID()}', now() - interval '30 days', now(), '${hash()}', null);`);
			const teams = JSON.parse(service(`select public.executive_report_teams('${AUDITOR}')::text;`));
			assert.deepEqual(teams.filter((row) => row.tenant_id === T).map((row) => row.role), ["auditor"]);
			const viewerTeams = JSON.parse(service(`select public.executive_report_teams('${VIEWER}')::text;`));
			assert.equal(viewerTeams.some((row) => row.tenant_id === T), false, "a viewer gets no report rollup");
		});

		await t.test("direct table writes reject the auditor under RLS", () => {
			const writes = {
				"promote self in team_members": `update public.team_members set role = 'admin' where team_id = '${T}' and user_id = '${AUDITOR}'`,
				"promote self in tenant_members": `update public.tenant_members set role = 'owner' where tenant_id = '${T}' and user_id = '${AUDITOR}'`,
				"demote another member": `update public.team_members set role = 'viewer' where team_id = '${T}' and user_id = '${MEMBER}'`,
				"remove a member": `delete from public.team_members where team_id = '${T}' and user_id = '${MEMBER}'`,
				"add a member": `insert into public.team_members(team_id, tenant_id, user_id, role) values ('${T}', '${T}', '${randomUUID()}', 'viewer')`,
				"rename the tenant": `update public.tenants set name = 'pwned' where id = '${T}'`,
				"edit the team policy": `update public.team_policies set content = 'pwned' where tenant_id = '${T}'`,
				"add a team policy": `insert into public.team_policies(team_id, tenant_id, content, updated_by, source_sha256) values ('${T}', '${T}', 'x', '${AUDITOR}', repeat('b', 64))`,
				"delete the team policy": `delete from public.team_policies where tenant_id = '${T}'`,
				"rename an agent": `update public.agents set iid = 'pwned' where tenant_id = '${T}'`,
				"insert an event": `insert into public.events(tenant_id, user_id, agent_id, type, event_id, payload) values ('${T}', '${AUDITOR}', '${AGENT}', 'verdict', 'forged', '{}')`,
				"delete events": `delete from public.events where tenant_id = '${T}'`,
				"forge an audit row": `insert into public.audit_logs(team_id, tenant_id, user_id, action) values ('${T}', '${T}', '${AUDITOR}', 'forged')`,
				"erase the audit trail": `delete from public.audit_logs where tenant_id = '${T}'`,
				"forge an admin audit row": `insert into public.admin_audit_logs(actor_user_id, tenant_id, action) values ('${AUDITOR}', '${T}', 'forged')`,
				"mint an API key": `insert into public.api_keys(user_id, tenant_id, key_hash, label) values ('${AUDITOR}', '${T}', '${hash()}', 'x')`,
				"invite directly": `insert into public.team_invitations(tenant_id, email, role, token_hash, created_by, expires_at) values ('${T}', 'x@example.invalid', 'admin', '${hash()}', '${AUDITOR}', now() + interval '1 day')`,
				"change governance settings": `update public.tenant_governance_settings set digest_enabled = true where tenant_id = '${T}'`,
			};
			for (const [label, statement] of Object.entries(writes)) {
				const result = touched(AUDITOR, statement);
				assert.ok(result === 0 || typeof result === "string", `${label}: auditor changed ${result} row(s)`);
			}
			asFails(AUDITOR, `select public.set_governance_settings('${T}', true, 'weekly', 'en', 60, 5, 0.5);`);
			assert.equal(sql(`select role from public.tenant_members where tenant_id = '${T}' and user_id = '${AUDITOR}';`), "auditor");
		});

		await t.test("every service write RPC refuses an auditor actor", () => {
			const rpcs = sql(`
				select p.proname || '|' || p.oid::regprocedure::text || '|' || array_to_string(p.proargnames[1:p.pronargs], ',') || '|'
				       || array_to_string(array(select format_type(x, null) from unnest(p.proargtypes::oid[]) x), ',')
				  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
				 where n.nspname = 'public' and p.prokind = 'f' and p.provolatile = 'v'
				   and p.proargnames[1:p.pronargs] @> array['p_tenant_id', 'p_actor_user_id']
				 order by p.oid::regprocedure::text;`).split("\n").filter(Boolean);
			assert.ok(rpcs.length >= 60, `the sweep covers the write surface (${rpcs.length} RPCs)`);
			const value = (arg, type) => {
				if (arg === "p_tenant_id") return `'${T}'::uuid`;
				if (arg === "p_actor_user_id") return `'${AUDITOR}'::uuid`;
				if (arg === "p_action") return "'create'";
				if (arg === "p_role" || arg === "p_default_role") return "'viewer'";
				if (arg === "p_email") return "'new@example.invalid'";
				if (arg === "p_language") return "'en'";
				if (arg === "p_decision") return "'approve'";
				if (/hash|sha256/.test(arg) && type === "text") return `'${hash()}'`;
				switch (type) {
					case "uuid": return `'${randomUUID()}'::uuid`;
					case "uuid[]": return "array[]::uuid[]";
					case "text[]": return "array[]::text[]";
					case "text": return "'x'";
					case "integer": case "bigint": case "smallint": return "1";
					case "numeric": return "0.5";
					case "boolean": return "true";
					case "jsonb": case "json": return "'{}'::jsonb";
					case "timestamp with time zone": return "now() + interval '1 hour'";
					case "date": return "current_date + 30";
					default: return `null::${type}`;
				}
			};
			// Runs `call` as the service role in a rolled-back transaction and
			// reports an SQL error, or whether tenant state changed.
			const attempt = (call) => {
				const result = psql(db, `begin; ${FINGERPRINT} set role service_role;
					create function pg_temp.try(q text) returns text language plpgsql as $f$
					declare v_result text; v_before text;
					begin
					  v_before := pg_temp.fingerprint();
					  execute q into v_result;
					  return case when pg_temp.fingerprint() = v_before then 'unchanged: ' else 'CHANGED: ' end || coalesce(v_result, 'null');
					exception when others then return sqlstate || ': ' || sqlerrm; end $f$;
					select pg_temp.try($q$${call}$q$); rollback;`);
				assert.equal(result.code, 0, `${call}: ${result.stderr}`);
				return result.stdout.split("\n").pop();
			};
			// The harness itself must see an accepted write, or the sweep is vacuous.
			assert.match(attempt(`select public.set_governance_report_options('${T}', '${OWNER}', 'tr', false)`), /^CHANGED: /);
			const accepted = [];
			let swept = 0;
			let authorization = 0;
			for (const row of rpcs) {
				const [proname, signature, names, types] = row.split("|");
				if (AUDITOR_ALLOWED_RPCS.has(proname)) continue;
				const argNames = names.split(",");
				const argTypes = types.split(",");
				const outcome = attempt(`select public.${proname}(${argNames.map((arg, i) => `${arg} => ${value(arg, argTypes[i])}`).join(", ")})`);
				swept += 1;
				if (process.env.AIDR_AUDITOR_DEBUG) console.log(`${proname}: ${outcome.slice(0, 140)}`);
				assert.doesNotMatch(outcome, /fingerprint/, `${signature}: harness failure`);
				if (/^42501: |"status": "forbidden"/.test(outcome)) authorization += 1;
				if (!REFUSAL.test(outcome)) accepted.push(`${signature} -> ${outcome}`);
			}
			assert.ok(swept >= 60);
			// Most refusals are the role check itself, not argument validation.
			assert.ok(authorization >= 60, `role refusals: ${authorization} of ${swept}`);
			assert.deepEqual(accepted, [], "no write RPC may accept an auditor actor");
		});

		await t.test("write RPCs keep refusing the auditor for authorization, not input", () => {
			// Valid input that an owner/admin would be allowed to commit.
			const refusals = [
				[`select public.set_governance_report_options('${T}', '${AUDITOR}', 'tr', false)`, /42501|forbidden/i],
				[`select public.mutate_team_invitation('create', '${T}', '${AUDITOR}', 'x-${marker}@example.invalid', 'admin', null, '${hash()}')`, /invitation_forbidden/],
				[`select public.set_tenant_identity_policy('${T}', '${AUDITOR}', true, false)`, /42501|forbidden|denied/i],
				[`select public.update_approval_settings('${T}', '${AUDITOR}', true)`, /42501|forbidden|denied/i],
				[`select public.update_tenant_workspace_settings('${T}', '${AUDITOR}', 'Renamed', 30, false)`, /42501|forbidden|denied/i],
				[`select public.update_incident_triage('${T}', '${AUDITOR}', (select id from public.events where tenant_id = '${T}' limit 1), 0, '{"status":"acknowledged"}')`, /incident_triage_forbidden/],
				[`select public.request_workspace_closure('${T}', '${AUDITOR}', 'Audit ${marker}')`, /42501|forbidden|denied/i],
			];
			for (const [statement, pattern] of refusals) serviceFails(`${statement};`, pattern);
			assert.equal(JSON.parse(service(`select public.issue_api_key_with_audit('${AUDITOR}', '${T}', 'auditor key', '${hash()}', null)::text;`)).status, "forbidden");
			assert.equal(JSON.parse(service(`select public.issue_fleet_enrollment_key_with_audit('${AUDITOR}', '${T}', 'fleet', 10, 90, '${hash()}', 'abcd')::text;`)).status, "forbidden");
			assert.equal(sql(`select count(*) from public.api_keys where user_id = '${AUDITOR}';`), "0");
			assert.equal(sql(`select count(*) from public.fleet_enrollment_keys where tenant_id = '${T}';`), "0");
			// The same governance-report write is accepted for an owner, so the
			// refusal above is the role, not the arguments.
			service(`select public.set_governance_report_options('${T}', '${OWNER}', 'tr', false);`);
		});

		await t.test("owners and admins invite or assign auditor; directories cannot", () => {
			const invite = JSON.parse(service(`select public.mutate_team_invitation('create', '${T}', '${ADMIN}', 'auditor-${marker}@example.invalid', 'auditor', null, '${hash()}')::text;`));
			assert.equal(sql(`select role from public.team_invitations where id = '${invite.id}';`), "auditor");
			assert.equal(touched(ADMIN, `update public.team_members set role = 'auditor' where team_id = '${T}' and user_id = '${NEWBIE}'`), 1);
			as(ADMIN, `update public.team_members set role = 'auditor' where team_id = '${T}' and user_id = '${NEWBIE}';`);
			assert.equal(sql(`select role from public.tenant_members where tenant_id = '${T}' and user_id = '${NEWBIE}';`), "auditor");
			assert.equal(sql(`select count(*) from public.admin_audit_logs where tenant_id = '${T}' and target_user_id = '${NEWBIE}'
				and detail->>'new_role' = 'auditor';`), "1", "the grant is in the administrative trail");
			// A member cannot assign it; an auditor cannot hand it out either.
			assert.equal(touched(MEMBER, `update public.team_members set role = 'auditor' where team_id = '${T}' and user_id = '${VIEWER}'`), 0);
			assert.equal(touched(AUDITOR, `update public.team_members set role = 'auditor' where team_id = '${T}' and user_id = '${VIEWER}'`), 0);
			fails(`insert into public.scim_group_role_mappings(tenant_id, external_group_id, role) values ('${T}', 'g-${marker}', 'auditor');`, /check constraint|violates/);
			fails(`insert into public.tenant_members(tenant_id, user_id, role) values ('${T}', '${randomUUID()}', 'superuser');`, /check constraint|violates/);
		});
	} finally {
		psql(admin, `drop database if exists ${name} with (force)`);
	}
});
