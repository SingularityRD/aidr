// Run only against an isolated Supabase PostgreSQL: migration-under-test on a
// through-44 database, or --installed after the exact chain includes 45.
// Every synthetic Auth user and optional migration are inside one rollback.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const container = process.env.AIDR_POSTGRES_DOCKER_CONTAINER;
assert.match(container ?? "", /^[A-Za-z0-9_.-]+$/, "set a disposable AIDR_POSTGRES_DOCKER_CONTAINER");
const dockerDesktop = process.env.LOCALAPPDATA
	? resolve(process.env.LOCALAPPDATA, "Programs/DockerDesktop/resources/bin/docker.exe") : null;
const docker = process.env.AIDR_DOCKER_BIN ?? (dockerDesktop && existsSync(dockerDesktop) ? dockerDesktop : "docker");
const migration = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)),
	"../supabase/migrations/20260923000045_trial_subject_erasure.sql"), "utf8");
const installed = process.argv.includes("--installed");
const first = randomUUID(), second = randomUUID(), third = randomUUID(), spare = randomUUID();
const firstTeam = randomUUID(), secondTeam = randomUUID(), thirdTeam = randomUUID();
const marker = randomUUID().replaceAll("-", "");
const email = `trial-delete-${marker}@example.invalid`;
const changedEmail = `trial-changed-${marker}@example.invalid`;
const user = (id, address) => `insert into auth.users(id,email,aud,role,instance_id,
  email_confirmed_at,raw_app_meta_data,raw_user_meta_data)
values ('${id}','${address}','authenticated','authenticated',
  '00000000-0000-0000-0000-000000000000',clock_timestamp(),'{}'::jsonb,'{}'::jsonb);`;
const team = (id, owner) => `insert into public.tenants(id,name,kind,created_by)
values ('${id}','Trial delete ${marker}','team','${owner}');
insert into public.teams(id,tenant_id,name,plan)
values ('${id}','${id}','Trial delete ${marker}','free');
insert into public.tenant_members(tenant_id,user_id,role) values ('${id}','${owner}','owner');
insert into public.team_members(team_id,tenant_id,user_id,role)
values ('${id}','${id}','${owner}','owner');`;
const trial = (id, tenant) => `public.start_verified_trial('${id}','${tenant}',
  '{"version":"test","sha256":"${"a".repeat(64)}"}'::jsonb,
  '{"version":"test","sha256":"${"b".repeat(64)}"}'::jsonb)`;
const sql = `begin;
create function pg_temp.expect_status(actual jsonb, expected text)
returns void language plpgsql as $$ begin
  if actual->>'status' is distinct from expected then
    raise exception 'expected %, got %', expected, actual;
  end if;
end $$;
grant execute on function pg_temp.expect_status(jsonb,text) to anon, authenticated, service_role;
create function pg_temp.expect_old_soft_delete_denied()
returns void language plpgsql as $$ begin
  begin
    update auth.users set deleted_at=clock_timestamp(), raw_app_meta_data='{}'::jsonb
      where id='${first}';
    raise exception 'old trigger allowed soft delete';
  exception when insufficient_privilege then
    if sqlerrm <> 'trial_claim_immutable' then raise; end if;
  end;
end $$;
grant execute on function pg_temp.expect_old_soft_delete_denied() to anon, authenticated, service_role;
select public.configure_tenant_admission_mode('cloud');
select public.configure_ga_legal_documents('test','${"a".repeat(64)}',
  'https://example.invalid/terms','test','${"b".repeat(64)}',
  'https://example.invalid/privacy','rollback-only');
${user(first, email)}
${user(spare, `spare-${marker}@example.invalid`)}
${team(firstTeam, first)}
select pg_temp.expect_status(${trial(first, firstTeam)}, 'started');
select pg_temp.expect_status(${trial(first, firstTeam)}, 'existing');
${installed ? "" : "select pg_temp.expect_old_soft_delete_denied();"}
${installed ? "" : migration}
select pg_temp.expect_status(${trial(first, firstTeam)}, 'existing');
do $$ begin
  begin
    update auth.users set raw_app_meta_data='{}'::jsonb where id='${first}';
    raise exception 'active account changed immutable claim';
  exception when insufficient_privilege then
    if sqlerrm <> 'trial_claim_immutable' then raise; end if;
  end;
end $$;
update auth.users set email='${changedEmail}' where id='${first}';
update auth.users set deleted_at=clock_timestamp() where id='${first}';
do $$ begin
  begin
    update auth.users set deleted_at=null,raw_app_meta_data='{}'::jsonb
      where id='${first}';
    raise exception 'reactivation cleared immutable claim';
  exception when insufficient_privilege then
    if sqlerrm <> 'trial_claim_immutable' then raise; end if;
  end;
end $$;
update auth.users set email='deleted-${marker}@example.invalid',
  raw_app_meta_data='{}'::jsonb where id='${first}';
insert into public.tenant_members(tenant_id,user_id,role)
  values ('${firstTeam}','${spare}','owner');
insert into public.team_members(team_id,tenant_id,user_id,role)
  values ('${firstTeam}','${firstTeam}','${spare}','owner');
-- The fixture's personal tenant must be in the normal closing state before
-- its only owner can be removed; the product's offboarding test covers that path.
update public.tenants set status='closing'
where id in (select tenant_id from public.tenant_members where user_id='${first}')
  and id <> '${firstTeam}';
delete from auth.users where id='${first}';
${user(second, email)}
${team(secondTeam, second)}
${user(third, changedEmail)}
${team(thirdTeam, third)}
do $$ begin
  if (public.get_tenant_admission('${secondTeam}','${second}')->>'trial_available')::boolean
     or (public.get_tenant_admission('${thirdTeam}','${third}')->>'trial_available')::boolean
    then raise exception 'new account advertised repeat trial'; end if;
end $$;
select pg_temp.expect_status(${trial(second, secondTeam)}, 'ineligible');
select pg_temp.expect_status(${trial(third, thirdTeam)}, 'ineligible');
do $$ begin
  if (select count(*) from app.ga_trial_subjects) <> 2 then
    raise exception 'original or changed-email anti-stacking digest missing'; end if;
  if exists(select 1 from app.ga_trial_subjects where octet_length(digest) <> 32) then
    raise exception 'invalid digest length'; end if;
  if exists(select 1 from information_schema.columns
      where table_schema='app' and table_name='ga_trial_subjects'
      and column_name in ('email','ip_address')) then
    raise exception 'raw identity stored in anti-stacking table'; end if;
end $$;
update app.ga_trial_subjects set expires_at=clock_timestamp()-interval '1 second';
do $$ begin
  if (public.purge_expired_ga_trial_subjects(10,false)->>'eligible')::int <> 2
    then raise exception 'expired digest not selected'; end if;
  if (public.purge_expired_ga_trial_subjects(10,false)->>'deleted')::int <> 0
    then raise exception 'dry run deleted digest'; end if;
  if (public.purge_expired_ga_trial_subjects(10,true)->>'remaining')::int <> 0
    then raise exception 'expired digest not purged'; end if;
end $$;
select pg_temp.expect_status(${trial(second, secondTeam)}, 'started');
delete from app.ga_trial_subject_key;
do $$ begin
  begin
    perform app.ga_trial_subject_available('fresh-${marker}@example.invalid');
    raise exception 'missing HMAC key was accepted';
  exception when object_not_in_prerequisite_state then
    if sqlerrm <> 'trial_subject_key_unavailable' then raise; end if;
  end;
end $$;
select 'GA_TRIAL_AUTH_DELETE_ROLLBACK_OK';
rollback;`;
const result = spawnSync(docker, ["exec", "-i", container, "psql", "-X", "-w", "-v",
	"ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres", "-q", "-At"],
{ input: sql, encoding: "utf8", maxBuffer: 4 * 1024 * 1024, timeout: 120_000 });
if (result.error) throw result.error;
assert.equal(result.status, 0, `trial/Auth delete rollback failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /GA_TRIAL_AUTH_DELETE_ROLLBACK_OK/);
console.log(`GA trial Auth delete passed (${installed ? "installed" : "migration-under-test"}): soft/hard delete, 14-day digests, no repeat trial, purge and missing-key fail-closed; all rolled back.`);
