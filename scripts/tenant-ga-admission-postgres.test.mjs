// Run against an isolated Supabase PostgreSQL container with migrations through
// 33 applied, or use --installed after 34+. Every mode uses a rolled-back transaction.
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const container = process.env.AIDR_POSTGRES_DOCKER_CONTAINER;
const installed = process.argv.includes("--installed");
assert.ok(container, "AIDR_POSTGRES_DOCKER_CONTAINER must name a disposable PostgreSQL container");
assert.match(container, /^[A-Za-z0-9_.-]+$/, "invalid Docker container name");
const dockerDesktop = process.env.LOCALAPPDATA
	? resolve(process.env.LOCALAPPDATA, "Programs/DockerDesktop/resources/bin/docker.exe")
	: null;
const docker = process.env.AIDR_DOCKER_BIN ?? (dockerDesktop && existsSync(dockerDesktop) ? dockerDesktop : "docker");
const dbUser = process.env.AIDR_POSTGRES_DB_USER ?? "postgres";
assert.match(dbUser, /^[A-Za-z_][A-Za-z0-9_]*$/, "invalid PostgreSQL role");
const migration = readFileSync(
	resolve(dirname(fileURLToPath(import.meta.url)), "../supabase/migrations/20260923000034_tenant_ga_admission.sql"),
	"utf8",
);
const hex = () => randomBytes(32).toString("hex");
const id = () => randomUUID();
const legalVersion = "ga-test-1";
const termsDigest = "a".repeat(64);
const privacyDigest = "b".repeat(64);
const legal = installed && (() => {
	const result = spawnSync(docker, [
		"exec", container, "psql", "-X", "-w", "-v", "ON_ERROR_STOP=1",
		"-U", dbUser, "-d", "postgres", "-q", "-At", "-c",
		"select to_regprocedure('public.start_verified_trial(uuid,uuid,jsonb,jsonb)') is not null",
	], { encoding: "utf8", timeout: 30_000 });
	if (result.error) throw result.error;
	assert.equal(result.status, 0, `trial RPC probe failed:\n${result.stderr}`);
	return result.stdout.trim() === "t";
})();
const trial = (userId, tenantId) => legal
	? `public.start_verified_trial('${userId}','${tenantId}',
    jsonb_build_object('version','${legalVersion}','sha256','${termsDigest}'),
    jsonb_build_object('version','${legalVersion}','sha256','${privacyDigest}'))`
	: `public.start_verified_trial('${userId}','${tenantId}')`;
const legalSetup = legal ? `select pg_temp.expect_status(public.configure_ga_legal_documents(
  '${legalVersion}','${termsDigest}','https://aidr-test.invalid/terms',
  '${legalVersion}','${privacyDigest}','https://aidr-test.invalid/privacy',
  'postgres-rollback-test'),'configured','legal setup');` : "";
const marker = randomUUID().replaceAll("-", "");

function user(userId, verified = true) {
	return `insert into auth.users(id,email,aud,role,instance_id,email_confirmed_at,raw_app_meta_data,raw_user_meta_data)
values ('${userId}','admission-${userId}@example.invalid','authenticated','authenticated',
  '00000000-0000-0000-0000-000000000000',${verified ? "clock_timestamp()" : "null"},
  '{}'::jsonb,'{}'::jsonb);`;
}

function team(tenantId, ownerId) {
	return `insert into public.tenants(id,name,kind,created_by)
values ('${tenantId}','GA ${marker}','team','${ownerId}');
insert into public.teams(id,tenant_id,name,plan)
values ('${tenantId}','${tenantId}','GA ${marker}','free');
insert into public.tenant_members(tenant_id,user_id,role)
values ('${tenantId}','${ownerId}','owner');
insert into public.team_members(team_id,tenant_id,user_id,role)
values ('${tenantId}','${tenantId}','${ownerId}','owner');`;
}

const helpers = String.raw`
create function pg_temp.expect_status(actual jsonb, expected text, label text)
returns void language plpgsql as $fn$
begin
  if actual ->> 'status' is distinct from expected then
    raise exception '%: expected %, got %', label, expected, actual;
  end if;
end $fn$;
create function pg_temp.expect_capacity(tenant uuid, expected integer, label text)
returns void language plpgsql as $fn$
declare actual integer;
begin
  actual := public.tenant_admission_capacity(tenant);
  if actual is distinct from expected then
    raise exception '%: expected capacity %, got %', label, expected, actual;
  end if;
end $fn$;
create function pg_temp.expect_denied(statement text, expected_message text)
returns void language plpgsql as $fn$
declare actual text;
begin
  begin
    execute statement;
  exception when insufficient_privilege then
    get stacked diagnostics actual = message_text;
    if actual = expected_message then return; end if;
    raise;
  end;
  raise exception 'expected % denial: %', expected_message, statement;
end $fn$;
create function pg_temp.expect_invalid(statement text, expected_message text)
returns void language plpgsql as $fn$
declare actual text;
begin
  begin
    execute statement;
  exception when invalid_parameter_value then
    get stacked diagnostics actual = message_text;
    if actual = expected_message then return; end if;
    raise;
  end;
  raise exception 'expected % validation error: %', expected_message, statement;
end $fn$;
create function pg_temp.expect_sqlstate(statement text, expected_state text)
returns void language plpgsql as $fn$
declare actual text;
begin
  begin
    execute statement;
  exception when others then
    get stacked diagnostics actual = returned_sqlstate;
    if actual = expected_state then return; end if;
    raise;
  end;
  raise exception 'expected SQLSTATE %, statement succeeded: %', expected_state, statement;
end $fn$;
`;

function deniedCredential(tenantId, ownerId, label) {
	return `
select pg_temp.expect_denied($stmt$
  insert into public.api_keys(user_id,tenant_id,key_hash)
  values ('${ownerId}','${tenantId}','${hex()}')
$stmt$,'tenant_not_admitted');
select pg_temp.expect_denied($stmt$
  insert into public.enrollment_tokens(user_id,tenant_id,token_hash,expires_at)
  values ('${ownerId}','${tenantId}','${hex()}',now()+interval '1 hour')
$stmt$,'tenant_not_admitted');
select pg_temp.expect_denied($stmt$
  insert into public.agents(user_id,tenant_id,iid)
  values ('${ownerId}','${tenantId}','${label}-${marker}')
$stmt$,'tenant_not_admitted');
`;
}

function device(tenantId, ownerId, label) {
	const code = hex();
	const token = hex();
	return {
		setup: `insert into public.device_sessions(device_code_hash,user_code,status,user_id,tenant_id,authorized_at,expires_at)
values ('${code}','${label.slice(0, 8).toUpperCase()}','authorized','${ownerId}','${tenantId}',now(),now()+interval '10 minutes');`,
		issue: `public.issue_device_enrollment_token('${code}','${token}',now()+interval '1 hour')`,
		code,
		token,
	};
}

function runCase(label, fixture, body) {
	const sql = `\\set ON_ERROR_STOP on\nbegin;\n${fixture}\n${installed ? "" : migration}\n${helpers}\n${legalSetup}\n${body}\nrollback;\nselect 'GA_ADMISSION_${label}_ROLLED_BACK';\n`;
	const result = spawnSync(docker, [
		"exec", "-i", container, "psql", "-X", "-w", "-v", "ON_ERROR_STOP=1",
		"-U", dbUser, "-d", "postgres", "-q", "-At",
	], { input: sql, encoding: "utf8", maxBuffer: 12 * 1024 * 1024, timeout: 120_000 });
	if (result.error) throw result.error;
	assert.equal(result.status, 0, `${label} PostgreSQL admission regression failed:\n${result.stdout}\n${result.stderr}`);
	assert.match(result.stdout, new RegExp(`GA_ADMISSION_${label}_ROLLED_BACK`));
}

// Default is no access, even with pilot approval, seats and a valid operator.
// On-prem cannot self-start a cloud trial; only a separately authorized
// operator can grant a licensed tenant after the mode is fixed.
{
	const owner = id();
	const operator = id();
	const tenant = id();
	const firstAgent = `onprem-first-${marker}`;
	const denialDevice = device(tenant, owner, "ONPREM01");
	const licensedDevice = device(tenant, owner, "ONPREM02");
	const fixture = `${user(owner)}\n${user(operator)}\n${team(tenant, owner)}
insert into public.entitlements(user_id,tenant_id,included_agents,extra_agents)
values ('${owner}','${tenant}',2,5);
insert into public.subscriptions(user_id,tenant_id,provider,provider_subscription_id,status,
  extra_agents,current_period_end)
values ('${owner}','${tenant}','stripe','sub_${marker}','active',5,now()-interval '1 day');
insert into public.pilot_applications(user_id,tenant_id,status)
values ('${owner}','${tenant}','approved');
${denialDevice.setup}
${licensedDevice.setup}`;
	const body = `
select pg_temp.expect_capacity('${tenant}',0,'unconfigured');
select pg_temp.expect_status(public.get_tenant_admission('${tenant}','${owner}'),'unconfigured','default status');
select pg_temp.expect_status(${trial(owner, tenant)},'disabled','default trial');
${deniedCredential(tenant, owner, "unconfigured")}
select pg_temp.expect_status(${denialDevice.issue},'tenant_not_admitted','default device issue');
select pg_temp.expect_denied($stmt$
  select public.grant_licensed_tenant_admission('${operator}','${tenant}','${owner}',2,
    now()+interval '1 year','purchase-${marker}')
$stmt$,'admission_mode_not_licensed');
select pg_temp.expect_status(public.configure_tenant_admission_mode('onprem'),'configured','configure onprem');
select pg_temp.expect_denied($stmt$
  select public.configure_tenant_admission_mode('cloud')
$stmt$,'admission_mode_immutable');
select pg_temp.expect_capacity('${tenant}',0,'onprem without grant');
select pg_temp.expect_status(${trial(owner, tenant)},'disabled','onprem trial');
${deniedCredential(tenant, owner, "onprem-no-grant")}
select pg_temp.expect_denied($stmt$
  select public.grant_licensed_tenant_admission('${owner}','${tenant}','${owner}',2,
    now()+interval '1 year','owner-self-grant-${marker}')
$stmt$,'admission_operator_forbidden');
select pg_temp.expect_denied($stmt$
  select public.grant_licensed_tenant_admission('${operator}','${tenant}','${owner}',2,
    now()+interval '1 year','unlisted-operator-${marker}')
$stmt$,'admission_operator_forbidden');
select pg_temp.expect_sqlstate($stmt$
  insert into public.admission_operators(tenant_id,user_id,expires_at)
  values ('${tenant}','${operator}',null)
$stmt$,'23502');
select pg_temp.expect_sqlstate($stmt$
  insert into public.admission_operators(tenant_id,user_id,expires_at)
  values ('${tenant}','${operator}','infinity'::timestamptz)
$stmt$,'23514');
insert into public.admission_operators(tenant_id,user_id) values ('${tenant}','${operator}');
do $check$ begin
  if not exists(select 1 from public.admission_operators
    where tenant_id='${tenant}' and user_id='${operator}'
      and expires_at > now() and expires_at <= now()+interval '31 days') then
    raise exception 'operator default was not finite and short-lived'; end if;
end $check$;
update public.admission_operators set expires_at=now()-interval '1 second'
 where tenant_id='${tenant}' and user_id='${operator}';
select pg_temp.expect_denied($stmt$
  select public.grant_licensed_tenant_admission('${operator}','${tenant}','${owner}',2,
    now()+interval '1 year','expired-operator-${marker}')
$stmt$,'admission_operator_forbidden');
update public.admission_operators set expires_at=now()+interval '30 days'
 where tenant_id='${tenant}' and user_id='${operator}';
select pg_temp.expect_invalid($stmt$
  select public.grant_licensed_tenant_admission('${operator}','${tenant}','${owner}',2,
    'infinity'::timestamptz,'unbounded-${marker}')
$stmt$,'invalid_admission_grant');
do $check$ declare v_extra integer; begin
  select s.extra_agents into v_extra from public.effective_tenant_seats('${tenant}') s;
  if v_extra <> 0 then raise exception 'expired provider seats were counted'; end if;
end $check$;
select pg_temp.expect_status(public.grant_licensed_tenant_admission(
  '${operator}','${tenant}','${owner}',2,now()+interval '1 year','purchase-${marker}'
),'granted','licensed grant');
select pg_temp.expect_capacity('${tenant}',2,'licensed capacity');
do $check$ declare v_included integer; v_extra integer; begin
  select included_agents,extra_agents into v_included,v_extra
    from public.entitlements where tenant_id='${tenant}';
  if v_included <> 2 or v_extra <> 5 then
    raise exception 'licensed grant did not preserve stale extra but set explicit included seats'; end if;
end $check$;
select pg_temp.expect_status(${licensedDevice.issue},'issued','licensed device issue');
do $check$ begin
  if not exists (select 1 from public.device_sessions
      where device_code_hash='${licensedDevice.code}' and exchanged_at is not null)
    or not exists (select 1 from public.enrollment_tokens
      where tenant_id='${tenant}' and token_hash='${licensedDevice.token}') then
    raise exception 'licensed device issue did not persist one enrollment token'; end if;
end $check$;
insert into public.api_keys(user_id,tenant_id,key_hash) values ('${owner}','${tenant}','${hex()}');
insert into public.enrollment_tokens(user_id,tenant_id,token_hash,expires_at)
values ('${owner}','${tenant}','${hex()}',now()+interval '1 hour');
do $check$ declare row record; begin
  select * into row from public.register_agent_for_ingest('${owner}','${firstAgent}','test','1','${tenant}');
  if row.created is distinct from true or row.allowed_agents <> 2 then
    raise exception 'licensed first agent registration failed'; end if;
end $check$;
insert into public.events(user_id,tenant_id,agent_id,event_id,type,payload)
select '${owner}','${tenant}',id,'onprem-${marker}','ga_test','{}'::jsonb
from public.agents where tenant_id='${tenant}' and iid='${firstAgent}';
update public.entitlements set included_agents=0,extra_agents=0 where tenant_id='${tenant}';
select pg_temp.expect_capacity('${tenant}',0,'licensed zero entitlement');
${deniedCredential(tenant, owner, "onprem-zero-entitlement")}
select pg_temp.expect_status(${denialDevice.issue},'tenant_not_admitted','zero entitlement device issue');
select pg_temp.expect_denied($stmt$
  insert into public.events(user_id,tenant_id,agent_id,event_id,type,payload)
  select '${owner}','${tenant}',id,'zero-seats-${marker}','ga_test','{}'::jsonb
  from public.agents where tenant_id='${tenant}' and iid='${firstAgent}'
$stmt$,'agent_seat_not_authorized');
update public.entitlements set included_agents=2 where tenant_id='${tenant}';
select pg_temp.expect_capacity('${tenant}',2,'restored licensed entitlement');
do $check$ declare before_epoch bigint; after_epoch bigint; result jsonb; begin
  select revocation_epoch into before_epoch from public.entitlements where tenant_id='${tenant}';
  result := public.revoke_licensed_tenant_admission('${operator}','${tenant}','contract ended');
  perform pg_temp.expect_status(result,'revoked','licensed revocation');
  select revocation_epoch into after_epoch from public.entitlements where tenant_id='${tenant}';
  if after_epoch <> before_epoch + 1 then raise exception 'licensed revoke did not advance epoch'; end if;
end $check$;
select pg_temp.expect_capacity('${tenant}',0,'revoked capacity');
${deniedCredential(tenant, owner, "onprem-revoked")}
select pg_temp.expect_status(${denialDevice.issue},'tenant_not_admitted','revoked device issue');
select pg_temp.expect_denied($stmt$
  insert into public.events(user_id,tenant_id,agent_id,event_id,type,payload)
  select '${owner}','${tenant}',id,'revoked-${marker}','ga_test','{}'::jsonb
  from public.agents where tenant_id='${tenant}' and iid='${firstAgent}'
$stmt$,'agent_seat_not_authorized');
-- A future-start contract can be cancelled before its term begins.
update public.tenant_admissions
   set starts_at=clock_timestamp()+interval '1 day',
       expires_at=clock_timestamp()+interval '2 days', revoked_at=null
 where tenant_id='${tenant}';
select pg_temp.expect_status(public.revoke_licensed_tenant_admission(
  '${operator}','${tenant}','cancel future term'
),'revoked','future-start revocation');
do $check$ begin
  if not exists(select 1 from public.tenant_admissions
    where tenant_id='${tenant}' and revoked_at=starts_at) then
    raise exception 'future-start admission could not be revoked'; end if;
end $check$;
do $check$ begin
  if has_function_privilege('authenticated',
    'public.grant_licensed_tenant_admission(uuid,uuid,uuid,integer,timestamptz,text)','EXECUTE')
    or has_function_privilege('authenticated',
      'public.configure_tenant_admission_mode(text)','EXECUTE')
    or has_table_privilege('authenticated','public.admission_operators','INSERT') then
    raise exception 'browser role can mutate admission authority'; end if;
end $check$;`;
	runCase("ONPREM", fixture, body);
}

// A cloud trial belongs to one verified account and one owned team, never the
// personal tenant, someone else's team, or a second team after an upgrade.
{
	const owner = id();
	const unverified = id();
	const outsider = id();
	const operator = id();
	const teamA = id();
	const teamB = id();
	const unverifiedTeam = id();
	const outsiderTeam = id();
	const trialDevice = device(teamA, owner, "CLOUD001");
	const firstAgent = `trial-first-${marker}`;
	const fixture = `${user(owner)}\n${user(unverified, false)}\n${user(outsider)}\n${user(operator)}
${team(teamA, owner)}\n${team(teamB, owner)}\n${team(unverifiedTeam, unverified)}
${team(outsiderTeam, outsider)}\n${trialDevice.setup}`;
	const body = `
select pg_temp.expect_status(public.configure_tenant_admission_mode('cloud'),'configured','configure cloud');
select pg_temp.expect_capacity('${teamA}',0,'cloud pretrial');
select pg_temp.expect_status(${trial(unverified, unverifiedTeam)},'ineligible','unverified');
select pg_temp.expect_status(${trial(owner, owner)},'ineligible','personal');
select pg_temp.expect_status(${trial(owner, outsiderTeam)},'ineligible','foreign team');
select pg_temp.expect_status(${trial(outsider, teamA)},'ineligible','foreign owner');
select pg_temp.expect_status(public.get_tenant_admission('${teamA}','${outsider}'),'forbidden','cross tenant read');
${deniedCredential(teamA, owner, "cloud-pretrial")}
select pg_temp.expect_status(${trialDevice.issue},'tenant_not_admitted','pretrial device issue');
select pg_temp.expect_status(${trial(owner, teamA)},'started','first trial');
select pg_temp.expect_status(${trial(owner, teamA)},'existing','idempotent trial');
select pg_temp.expect_capacity('${teamA}',1,'trial one seat');
select pg_temp.expect_status(public.get_tenant_admission('${teamA}','${owner}'),'active','trial status');
do $check$ declare v_row public.tenant_admissions%rowtype; begin
  select * into v_row from public.tenant_admissions where tenant_id='${teamA}';
  if v_row.kind <> 'trial' or v_row.seats <> 1
     or v_row.expires_at <> v_row.starts_at + interval '14 days' then
    raise exception 'trial duration or seat allocation was not exactly 14 days/1 seat'; end if;
  if (select count(*) from public.entitlements where tenant_id='${teamA}'
      and included_agents >= 1) <> 1 then raise exception 'trial has no allocated seat'; end if;
end $check$;
select pg_temp.expect_status(${trial(owner, teamB)},'ineligible','second owned team');
insert into public.api_keys(user_id,tenant_id,key_hash) values ('${owner}','${teamA}','${hex()}');
insert into public.enrollment_tokens(user_id,tenant_id,token_hash,expires_at)
values ('${owner}','${teamA}','${hex()}',now()+interval '1 hour');
do $check$ declare first_row record; second_row record; begin
  select * into first_row from public.register_agent_for_ingest('${owner}','${firstAgent}','test','1','${teamA}');
  select * into second_row from public.register_agent_for_ingest('${owner}','trial-second-${marker}','test','1','${teamA}');
  if first_row.created is distinct from true or first_row.allowed_agents <> 1
     or second_row.seat_exceeded is distinct from true or second_row.agent_id is not null then
    raise exception 'trial agent quota was not enforced'; end if;
end $check$;
insert into public.events(user_id,tenant_id,agent_id,event_id,type,payload)
select '${owner}','${teamA}',id,'trial-${marker}','ga_test','{}'::jsonb
from public.agents where tenant_id='${teamA}' and iid='${firstAgent}';

-- Expiry cannot be extended by retrying trial, and existing agents/events stop.
with deadline as (select clock_timestamp()-interval '15 days' as started)
update public.tenant_admissions admission
set starts_at=deadline.started, expires_at=deadline.started+interval '14 days'
from deadline where admission.tenant_id='${teamA}';
select pg_temp.expect_capacity('${teamA}',0,'expired trial');
select pg_temp.expect_status(${trial(owner, teamA)},'existing','expired retry');
${deniedCredential(teamA, owner, "expired-trial")}
select pg_temp.expect_status(${trialDevice.issue},'tenant_not_admitted','expired device issue');
do $check$ declare row record; begin
  select * into row from public.register_agent_for_ingest('${owner}','${firstAgent}','test','1','${teamA}');
  if row.seat_exceeded is distinct from true then
    raise exception 'expired trial accepted existing-agent registration'; end if;
end $check$;
select pg_temp.expect_denied($stmt$
  insert into public.events(user_id,tenant_id,agent_id,event_id,type,payload)
  select '${owner}','${teamA}',id,'expired-${marker}','ga_test','{}'::jsonb
  from public.agents where tenant_id='${teamA}' and iid='${firstAgent}'
$stmt$,'agent_seat_not_authorized');
select pg_temp.expect_denied($stmt$
  update auth.users set raw_app_meta_data=raw_app_meta_data - 'aidr_trial'
  where id='${owner}'
$stmt$,'trial_claim_immutable');
select pg_temp.expect_denied($stmt$
  update auth.users set raw_app_meta_data=jsonb_set(raw_app_meta_data,
    '{aidr_trial,expires_at}',to_jsonb((now()+interval '1 year')::text),true)
  where id='${owner}'
$stmt$,'trial_claim_immutable');

-- An operator can terminate a separate trial immediately without resetting its claim.
select pg_temp.expect_status(${trial(outsider, outsiderTeam)},
  'started','second account independent trial');
insert into public.admission_operators(tenant_id,user_id)
values ('${outsiderTeam}','${operator}');
do $check$ declare before_epoch bigint; after_epoch bigint; result jsonb; begin
  select revocation_epoch into before_epoch from public.entitlements
    where tenant_id='${outsiderTeam}';
  result := public.revoke_trial_tenant_admission(
    '${operator}','${outsiderTeam}','test abuse revocation');
  perform pg_temp.expect_status(result,'revoked','trial admin revocation');
  select revocation_epoch into after_epoch from public.entitlements
    where tenant_id='${outsiderTeam}';
  if after_epoch <> before_epoch + 1 then raise exception 'trial revoke did not advance epoch'; end if;
end $check$;
select pg_temp.expect_capacity('${outsiderTeam}',0,'trial revoked capacity');
select pg_temp.expect_status(${trial(outsider, outsiderTeam)},
  'existing','revoked trial cannot restart');

-- A separately authorized paid upgrade does not reset the one-trial claim.
insert into public.admission_operators(tenant_id,user_id) values ('${teamA}','${operator}');
select pg_temp.expect_status(public.grant_licensed_tenant_admission(
  '${operator}','${teamA}','${owner}',3,now()+interval '1 year','upgrade-${marker}'
),'granted','upgrade');
select pg_temp.expect_capacity('${teamA}',3,'licensed upgrade');
select pg_temp.expect_status(${trial(owner, teamB)},'ineligible','post-upgrade second trial');
update public.tenant_admissions set starts_at=now()-interval '2 years',
  expires_at=now()-interval '1 year' where tenant_id='${teamA}';
select pg_temp.expect_capacity('${teamA}',0,'expired license');
update public.tenant_admissions set starts_at=now()-interval '1 second',
  expires_at=now()+interval '1 year' where tenant_id='${teamA}';
select pg_temp.expect_capacity('${teamA}',3,'license reactivated for revoke test');
select pg_temp.expect_status(public.revoke_licensed_tenant_admission(
  '${operator}','${teamA}','trial and license complete'
),'revoked','cloud license revoke');
select pg_temp.expect_capacity('${teamA}',0,'cloud license revoked');`;
	runCase("CLOUD", fixture, body);
}

// Pilot is a separate installation mode: an approved application and positive
// allocation are both required; cloud trial and licensed grant are disabled.
{
	const owner = id();
	const other = id();
	const tenant = id();
	const otherTenant = id();
	const agent = `pilot-${marker}`;
	const fixture = `${user(owner)}\n${user(other)}\n${team(tenant, owner)}\n${team(otherTenant, other)}
insert into public.entitlements(user_id,tenant_id,included_agents,extra_agents)
values ('${owner}','${tenant}',1,0),('${other}','${otherTenant}',1,0);`;
	const body = `
select pg_temp.expect_status(public.configure_tenant_admission_mode('pilot'),'configured','configure pilot');
select pg_temp.expect_status(${trial(owner, tenant)},'disabled','pilot trial');
select pg_temp.expect_capacity('${tenant}',0,'pilot pending');
${deniedCredential(tenant, owner, "pilot-pending")}
insert into public.pilot_applications(user_id,tenant_id,status)
values ('${owner}','${tenant}','approved');
select pg_temp.expect_capacity('${tenant}',1,'approved pilot');
select pg_temp.expect_capacity('${otherTenant}',0,'unapproved other tenant');
select pg_temp.expect_status(public.get_tenant_admission('${tenant}','${other}'),'forbidden','pilot cross tenant');
insert into public.api_keys(user_id,tenant_id,key_hash) values ('${owner}','${tenant}','${hex()}');
do $check$ declare row record; begin
  select * into row from public.register_agent_for_ingest('${owner}','${agent}','test','1','${tenant}');
  if row.created is distinct from true or row.allowed_agents <> 1 then
    raise exception 'approved pilot failed to register'; end if;
end $check$;
insert into public.events(user_id,tenant_id,agent_id,event_id,type,payload)
select '${owner}','${tenant}',id,'pilot-${marker}','ga_test','{}'::jsonb
from public.agents where tenant_id='${tenant}' and iid='${agent}';
update public.pilot_applications set status='denied'
where user_id='${owner}' and tenant_id='${tenant}';
select pg_temp.expect_capacity('${tenant}',0,'pilot revoked');
${deniedCredential(tenant, owner, "pilot-revoked")}
select pg_temp.expect_denied($stmt$
  insert into public.events(user_id,tenant_id,agent_id,event_id,type,payload)
  select '${owner}','${tenant}',id,'pilot-revoked-${marker}','ga_test','{}'::jsonb
  from public.agents where tenant_id='${tenant}' and iid='${agent}'
$stmt$,'agent_seat_not_authorized');`;
	runCase("PILOT", fixture, body);
}

console.log(`Tenant GA admission PostgreSQL passed (${installed ? "installed" : "migration 34"}): default/onprem/cloud/pilot, operator authority, one-trial claim, seats, expiry, revocation, credentials, device and events; all transactions rolled back.`);
