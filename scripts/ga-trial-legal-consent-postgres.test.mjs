// Disposable PostgreSQL only. Migration 41 (if absent) and all fixtures are
// applied inside one transaction that must roll back before this test passes.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const container = process.env.AIDR_POSTGRES_DOCKER_CONTAINER;
assert.ok(container, "AIDR_POSTGRES_DOCKER_CONTAINER must name a disposable PostgreSQL container");
assert.match(container, /^[A-Za-z0-9_.-]+$/, "invalid Docker container name");
const dockerDesktop = process.env.LOCALAPPDATA
	? resolve(process.env.LOCALAPPDATA, "Programs/DockerDesktop/resources/bin/docker.exe")
	: null;
const docker = process.env.AIDR_DOCKER_BIN ?? (dockerDesktop && existsSync(dockerDesktop) ? dockerDesktop : "docker");
const dbUser = process.env.AIDR_POSTGRES_DB_USER ?? "postgres";
assert.match(dbUser, /^[A-Za-z_][A-Za-z0-9_]*$/, "invalid PostgreSQL role");
const migration = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)),
	"../supabase/migrations/20260923000041_ga_trial_legal_consent.sql"), "utf8");

function psql(sql, interactive = false) {
	const args = ["exec", ...(interactive ? ["-i"] : []), container, "psql", "-X", "-w",
		"-v", "ON_ERROR_STOP=1", "-U", dbUser, "-d", "postgres", "-q", "-At"];
	if (!interactive) args.push("-c", sql);
	const result = spawnSync(docker, args, { input: interactive ? sql : undefined,
		encoding: "utf8", maxBuffer: 12 * 1024 * 1024, timeout: 120_000 });
	if (result.error) throw result.error;
	assert.equal(result.status, 0, `PostgreSQL legal-consent test failed:\n${result.stdout}\n${result.stderr}`);
	return result.stdout.trim();
}

const installed = psql("select to_regclass('app.ga_legal_documents') is not null, " +
	"to_regprocedure('public.start_verified_trial(uuid,uuid,jsonb,jsonb)') is not null");
assert.match(installed, /^(f\|f|t\|t)$/, `unsupported legal-consent schema state: ${installed}`);
const owner = randomUUID();
const freshOwner = randomUUID();
const atomicOwner = randomUUID();
const team = randomUUID();
const freshTeam = randomUUID();
const atomicTeam = randomUUID();
const marker = randomUUID().replaceAll("-", "");
const hash = (letter) => letter.repeat(64);
const docs = (version, termHash, privacyHash) => ({
	terms: `jsonb_build_object('version','${version}','sha256','${termHash}')`,
	privacy: `jsonb_build_object('version','${version}','sha256','${privacyHash}')`,
});
const v1 = docs("v1", hash("a"), hash("b"));
const v2 = docs("v2", hash("c"), hash("d"));
const staleTerms = `jsonb_build_object('version','v0','sha256','${hash("a")}')`;
const extraTerms = `jsonb_build_object('version','v1','sha256','${hash("a")}','extra',true)`;
const call = (user, tenant, terms, privacy) =>
	`public.start_verified_trial('${user}','${tenant}',${terms},${privacy})`;
const config = (version, termsHash, termsUrl, privacyHash, privacyUrl, approval) =>
	`public.configure_ga_legal_documents('${version}','${termsHash}','${termsUrl}',` +
	`'${version}','${privacyHash}','${privacyUrl}','${approval}')`;
const configureV1 = config("v1", hash("a"), "https://example.invalid/terms/v1",
	hash("b"), "https://example.invalid/privacy/v1", `approved-v1-${marker}`);
const configureV2 = config("v2", hash("c"), "https://example.invalid/terms/v2",
	hash("d"), "https://example.invalid/privacy/v2", `approved-v2-${marker}`);

const fixture = [
	[owner, team], [freshOwner, freshTeam], [atomicOwner, atomicTeam],
].map(([user, tenant]) => `
insert into auth.users(id,email,aud,role,instance_id,email_confirmed_at,
  raw_app_meta_data,raw_user_meta_data)
values ('${user}','legal-${user}@example.invalid','authenticated','authenticated',
  '00000000-0000-0000-0000-000000000000',clock_timestamp(),'{}'::jsonb,'{}'::jsonb);
insert into public.tenants(id,name,kind,created_by)
values ('${tenant}','Legal ${marker}','team','${user}');
insert into public.teams(id,tenant_id,name,plan)
values ('${tenant}','${tenant}','Legal ${marker}','free');
insert into public.tenant_members(tenant_id,user_id,role)
values ('${tenant}','${user}','owner');
insert into public.team_members(team_id,tenant_id,user_id,role)
values ('${tenant}','${tenant}','${user}','owner');`).join("\n");

const helpers = String.raw`
create function pg_temp.expect_status(actual jsonb, expected text, label text)
returns void language plpgsql as $fn$
begin
  if actual ->> 'status' is distinct from expected then
    raise exception '%: expected %, got %', label, expected, actual;
  end if;
end $fn$;
create function pg_temp.expect_state(statement text, expected text)
returns void language plpgsql as $fn$
declare actual text;
begin
  begin
    execute statement;
  exception when others then
    get stacked diagnostics actual = returned_sqlstate;
    if actual = expected then return; end if;
    raise exception 'expected SQLSTATE %, got %', expected, actual;
  end;
  raise exception 'expected SQLSTATE % but statement succeeded', expected;
end $fn$;
`;

const testSql = `\\set ON_ERROR_STOP on
begin;
${fixture}
${installed === "f|f" ? migration : ""}
${helpers}
select public.configure_tenant_admission_mode('cloud');
select pg_temp.expect_status(${call(owner, team, v1.terms, v1.privacy)},
  'legal_not_configured','empty legal config');
do $check$ begin
  if to_regprocedure('public.start_verified_trial(uuid,uuid)') is not null
     or has_function_privilege('service_role',
       'app.start_verified_trial_core(uuid,uuid)','EXECUTE')
     or has_function_privilege('authenticated',
       'app.start_verified_trial_core(uuid,uuid)','EXECUTE')
     or has_function_privilege('authenticated',
       'public.start_verified_trial(uuid,uuid,jsonb,jsonb)','EXECUTE') then
    raise exception 'unguarded trial RPC remains executable'; end if;
  if exists (select 1 from public.tenant_admissions where tenant_id='${team}') then
    raise exception 'empty legal config started a trial'; end if;
end $check$;
select pg_temp.expect_state($stmt$select ${config("v1", hash("a"), "http://example.invalid/terms",
	hash("b"), "https://example.invalid/privacy", "invalid-url")}$stmt$,'23514');
select pg_temp.expect_state($stmt$select ${config("v1", "ABC", "https://example.invalid/terms",
	hash("b"), "https://example.invalid/privacy", "invalid-hash")}$stmt$,'23514');
select pg_temp.expect_state($stmt$select ${config("bad/version", hash("a"), "https://example.invalid/terms",
	hash("b"), "https://example.invalid/privacy", "invalid-version")}$stmt$,'23514');
do $check$ begin
  if exists (select 1 from app.ga_legal_documents)
     or exists (select 1 from public.admin_audit_logs
       where action='admission.ga_legal_configured') then
    raise exception 'invalid legal config was persisted'; end if;
end $check$;
select pg_temp.expect_status(${configureV1},'configured','valid documents');
do $check$ declare view jsonb; begin
  view := public.get_ga_legal_documents();
  if view ->> 'configured' <> 'true'
     or view #>> '{terms,sha256}' <> '${hash("a")}'
     or view #>> '{privacy,sha256}' <> '${hash("b")}' then
    raise exception 'configured legal documents not readable'; end if;
end $check$;
select pg_temp.expect_status(${call(owner, team, "null::jsonb", v1.privacy)},
  'legal_documents_changed','missing consent');
select pg_temp.expect_status(${call(owner, team, staleTerms, v1.privacy)},
  'legal_documents_changed','stale consent');
select pg_temp.expect_status(${call(owner, team, extraTerms, v1.privacy)},
  'legal_documents_changed','extra consent field');
do $check$ begin
  if exists (select 1 from public.tenant_admissions where tenant_id='${team}')
     or exists (select 1 from auth.users where id='${owner}'
       and raw_app_meta_data ? 'aidr_trial') then
    raise exception 'invalid consent consumed trial entitlement'; end if;
end $check$;
select pg_temp.expect_status(${call(owner, team, v1.terms, v1.privacy)},
  'started','exact consent');
select pg_temp.expect_status(${call(owner, team, v1.terms, v1.privacy)},
  'existing','idempotent retry');
do $check$ declare receipt jsonb; begin
  select detail into receipt from public.admin_audit_logs
   where tenant_id='${team}' and action='admission.trial_legal_acceptance';
  if public.tenant_admission_capacity('${team}') <> 1
     or (select count(*) from public.admin_audit_logs
       where tenant_id='${team}' and action='admission.trial_legal_acceptance') <> 1
     or receipt #>> '{terms,sha256}' <> '${hash("a")}'
     or receipt #>> '{privacy,sha256}' <> '${hash("b")}'
     or receipt ->> 'approval_reference' <> 'approved-v1-${marker}' then
    raise exception 'trial acceptance was not recorded exactly once with admission'; end if;
end $check$;
select pg_temp.expect_status(${configureV2},'configured','rotate documents');
select pg_temp.expect_status(${call(freshOwner, freshTeam, v1.terms, v1.privacy)},
  'legal_documents_changed','stale after rotation');
select pg_temp.expect_status(${call(freshOwner, freshTeam, v2.terms, v2.privacy)},
  'started','current documents after rotation');
do $check$ declare receipt jsonb; begin
  select detail into receipt from public.admin_audit_logs
    where tenant_id='${freshTeam}' and action='admission.trial_legal_acceptance';
  if receipt #>> '{terms,sha256}' <> '${hash("c")}'
     or receipt #>> '{privacy,sha256}' <> '${hash("d")}'
     or receipt ->> 'approval_reference' <> 'approved-v2-${marker}' then
    raise exception 'rotated legal receipt did not bind current documents'; end if;
end $check$;
create function pg_temp.reject_trial_acceptance()
returns trigger language plpgsql as $fn$
begin
  if new.action='admission.trial_legal_acceptance' then
    raise exception 'simulated audit write failure';
  end if;
  return new;
end $fn$;
create trigger ga_trial_audit_failure before insert on public.admin_audit_logs
for each row execute function pg_temp.reject_trial_acceptance();
select pg_temp.expect_state($stmt$
  select ${call(atomicOwner, atomicTeam, v2.terms, v2.privacy)}
$stmt$,'P0001');
drop trigger ga_trial_audit_failure on public.admin_audit_logs;
do $check$ begin
  if exists (select 1 from public.tenant_admissions where tenant_id='${atomicTeam}')
     or exists (select 1 from auth.users where id='${atomicOwner}'
       and raw_app_meta_data ? 'aidr_trial')
     or exists (select 1 from public.admin_audit_logs where tenant_id='${atomicTeam}'
       and action in ('admission.trial_started','admission.trial_legal_acceptance')) then
    raise exception 'failed audit did not roll back trial atomically'; end if;
end $check$;
select pg_temp.expect_status(${call(atomicOwner, atomicTeam, v2.terms, v2.privacy)},
  'started','retry after atomic rollback');
rollback;
select 'GA_TRIAL_LEGAL_ROLLED_BACK';
`;

const output = psql(testSql, true);
assert.match(output, /GA_TRIAL_LEGAL_ROLLED_BACK/);
const remaining = psql("select " +
	`(select count(*) from auth.users where email like 'legal-%@example.invalid'),` +
	`(select count(*) from public.admin_audit_logs where action='admission.trial_legal_acceptance')` +
	(installed === "f|f" ? ",to_regclass('app.ga_legal_documents')" : ""));
assert.match(remaining, installed === "f|f" ? /^0\|0\|$/ : /^0\|0$/,
	`legal-consent fixtures survived rollback: ${remaining}`);
console.log("GA trial legal-consent PostgreSQL passed: unconfigured/invalid/stale consent denied, exact current consent audited once, atomic rollback and rotation verified; all fixtures rolled back.");
