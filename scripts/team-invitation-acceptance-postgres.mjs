// Run only against a disposable local Supabase DB. --installed skips migration
// reapplication; fixtures always run in one transaction and roll back.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.equal(process.env.AIDR_TEST_DISPOSABLE_DB, "1", "confirm disposable DB with AIDR_TEST_DISPOSABLE_DB=1");
assert.match(container ?? "", /^supabase_db_[A-Za-z0-9_.-]+$/, "refusing a non-Supabase DB container");
const migration = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../supabase/migrations/20260923000046_team_invitation_acceptance_lock.sql"), "utf8");
const installed = process.argv.includes("--installed");
const owner = randomUUID();
const steward = randomUUID();
const recipient = randomUUID();
const auditRecipient = randomUUID();
const tenant = randomUUID();
const email = `invite-accept-${recipient}@example.invalid`;
const auditEmail = `invite-audit-${auditRecipient}@example.invalid`;
const token1 = "a".repeat(64);
const token2 = "b".repeat(64);
const token3 = "c".repeat(64);
const token4 = "d".repeat(64);
const token5 = "e".repeat(64);
const sql = String.raw`
\set ON_ERROR_STOP on
begin;
${installed ? "" : migration}

insert into auth.users(id,email,aud,role,instance_id,email_confirmed_at,raw_app_meta_data,raw_user_meta_data)
values ('${owner}','invite-owner-${owner}@example.invalid','authenticated','authenticated',
        '00000000-0000-0000-0000-000000000000',clock_timestamp(),'{}'::jsonb,'{}'::jsonb),
       ('${steward}','invite-steward-${steward}@example.invalid','authenticated','authenticated',
        '00000000-0000-0000-0000-000000000000',clock_timestamp(),'{}'::jsonb,'{}'::jsonb),
       ('${recipient}','${email}','authenticated','authenticated',
        '00000000-0000-0000-0000-000000000000',clock_timestamp(),'{}'::jsonb,'{}'::jsonb),
       ('${auditRecipient}','${auditEmail}','authenticated','authenticated',
        '00000000-0000-0000-0000-000000000000',clock_timestamp(),'{}'::jsonb,'{}'::jsonb);
insert into public.tenants(id,name,kind,created_by)
values ('${tenant}','Invitation acceptance ${tenant}','team','${steward}');
insert into public.teams(id,tenant_id,name,plan)
values ('${tenant}','${tenant}','Invitation acceptance ${tenant}','free');
insert into public.team_members(team_id,tenant_id,user_id,role)
values ('${tenant}','${tenant}','${steward}','owner'),
       ('${tenant}','${tenant}','${owner}','admin');

create function pg_temp.expect_denied(p_hash text, p_user uuid, p_label text)
returns void language plpgsql as $fn$
begin
  begin
    perform public.accept_team_invitation(p_hash, p_user);
  exception when insufficient_privilege then return;
  end;
  raise exception '% unexpectedly accepted', p_label;
end $fn$;

set role service_role;
do $$
declare v_tenant uuid;
begin
  perform public.mutate_team_invitation('create','${tenant}','${owner}','${email}','member',null,'${token1}');
  perform pg_temp.expect_denied('${token1}','${owner}','wrong verified email');
  v_tenant := public.accept_team_invitation('${token1}','${recipient}');
  if v_tenant is distinct from '${tenant}'::uuid
     or not exists (select 1 from public.team_members
                    where team_id = '${tenant}' and user_id = '${recipient}' and role = 'member')
     or not exists (select 1 from public.tenant_members
                    where tenant_id = '${tenant}' and user_id = '${recipient}' and role = 'member') then
    raise exception 'valid invitation did not create tenant membership';
  end if;
  perform pg_temp.expect_denied('${token1}','${recipient}','replayed link');

  perform public.mutate_team_invitation('create','${tenant}','${owner}','${email}','admin',null,'${token2}');
  perform public.accept_team_invitation('${token2}','${recipient}');
  if not exists (select 1 from public.team_members
                 where team_id = '${tenant}' and user_id = '${recipient}' and role = 'member') then
    raise exception 'second invitation escalated existing membership';
  end if;
end $$;
reset role;

-- A failed acceptance audit must roll back both the membership grant and the
-- single-use marker; a retry after the audit sink recovers should succeed once.
create function pg_temp.reject_invitation_acceptance_audit()
returns trigger language plpgsql as $$
begin
  if new.action = 'member.invitation_accepted' then
    raise exception 'aidr_test_invitation_acceptance_audit_blocked';
  end if;
  return new;
end $$;
create trigger reject_invitation_acceptance_audit_test
before insert on public.audit_logs
for each row execute function pg_temp.reject_invitation_acceptance_audit();
set role service_role;
do $$
begin
  perform public.mutate_team_invitation('create','${tenant}','${owner}','${auditEmail}','member',null,'${token5}');
  begin
    perform public.accept_team_invitation('${token5}','${auditRecipient}');
    raise exception 'acceptance succeeded despite blocked audit';
  exception when others then
    if sqlerrm <> 'aidr_test_invitation_acceptance_audit_blocked' then raise; end if;
  end;
  if exists(select 1 from public.team_invitations where token_hash='${token5}' and accepted_at is not null)
     or exists(select 1 from public.team_members where team_id='${tenant}' and user_id='${auditRecipient}')
     or exists(select 1 from public.tenant_members where tenant_id='${tenant}' and user_id='${auditRecipient}') then
    raise exception 'failed acceptance audit left a membership or consumed link';
  end if;
end $$;
reset role;
drop trigger reject_invitation_acceptance_audit_test on public.audit_logs;
set role service_role;
do $$
begin
  perform public.accept_team_invitation('${token5}','${auditRecipient}');
  if not exists(select 1 from public.team_invitations where token_hash='${token5}' and accepted_at is not null)
     or not exists(select 1 from public.team_members where team_id='${tenant}' and user_id='${auditRecipient}')
     or not exists(select 1 from public.audit_logs where tenant_id='${tenant}' and user_id='${auditRecipient}'
                   and action='member.invitation_accepted') then
    raise exception 'acceptance retry did not atomically grant and audit membership';
  end if;
end $$;
reset role;

-- The transaction began before this link existed. A now()-based redemption
-- would accept it after its real wall-clock deadline.
set role service_role;
select public.mutate_team_invitation('create','${tenant}','${owner}','${email}','member',null,'${token3}');
reset role;
update public.team_invitations set expires_at = clock_timestamp() + interval '100 milliseconds'
where token_hash = '${token3}';
select pg_sleep(0.2);
set role service_role;
select pg_temp.expect_denied('${token3}','${recipient}','wall-clock expired link');
reset role;

-- An invite is invalid once its issuer loses the authorizing role.
set role service_role;
select public.mutate_team_invitation('create','${tenant}','${owner}','${email}','member',null,'${token4}');
reset role;
update public.tenant_members set expires_at = clock_timestamp() + interval '100 milliseconds'
where tenant_id = '${tenant}' and user_id = '${owner}';
select pg_sleep(0.2);
set role service_role;
select pg_temp.expect_denied('${token4}','${recipient}','expired inviter membership');
reset role;
update public.tenant_members set expires_at = null
where tenant_id = '${tenant}' and user_id = '${owner}';
update public.team_members set role = 'viewer'
where team_id = '${tenant}' and user_id = '${owner}';
set role service_role;
select pg_temp.expect_denied('${token4}','${recipient}','demoted inviter');
reset role;

rollback;
select 'TEAM_INVITATION_ACCEPTANCE_ROLLBACK';
`;

const result = spawnSync("docker", ["exec", "-i", container, "psql", "-X", "-w", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres", "-q", "-At"], {
  input: sql, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 120_000,
});
if (result.error) throw result.error;
assert.equal(result.status, 0, `invitation acceptance regression failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /TEAM_INVITATION_ACCEPTANCE_ROLLBACK/);
console.log("Invitation acceptance PostgreSQL test passed: verified recipient, single use, no role escalation, atomic audit rollback/retry, wall-clock expiry and issuer expiry/revocation; fixtures rolled back.");
