// Run only after resetting a disposable local Supabase database:
//   supabase start && supabase db reset --local --no-seed
//   AIDR_RLS_TEST_DB_CONTAINER=supabase_db_aidr AIDR_TEST_DISPOSABLE_DB=1 node scripts/team-invitation-atomic-audit-postgres.mjs
// The test injects audit failures and rolls back every fixture and trigger.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.equal(process.env.AIDR_TEST_DISPOSABLE_DB, "1", "confirm the database is disposable with AIDR_TEST_DISPOSABLE_DB=1");
assert.ok(container, "AIDR_RLS_TEST_DB_CONTAINER must name a disposable local Supabase db container");
assert.match(container, /^supabase_db_[A-Za-z0-9_.-]+$/, "refusing a non-Supabase database container");

const owner = randomUUID();
const tenant = randomUUID();
const invitationEmail = `invitation-audit-${randomUUID()}@example.invalid`;
const token1 = "a".repeat(64);
const token2 = "b".repeat(64);
const rpc = "public.mutate_team_invitation(text,uuid,uuid,text,text,uuid,text)";
const sql = String.raw`
\set ON_ERROR_STOP on
begin;

do $$ begin
  if not has_function_privilege('service_role', '${rpc}', 'EXECUTE')
     or has_function_privilege('authenticated', '${rpc}', 'EXECUTE')
     or has_function_privilege('anon', '${rpc}', 'EXECUTE')
     or not has_table_privilege('service_role', 'public.team_invitations', 'SELECT')
     or has_table_privilege('service_role', 'public.team_invitations', 'INSERT')
     or has_table_privilege('service_role', 'public.team_invitations', 'UPDATE')
     or has_table_privilege('service_role', 'public.team_invitations', 'DELETE')
     or has_table_privilege('service_role', 'public.team_invitations', 'TRUNCATE') then
    raise exception 'invitation RPC or direct-DML privilege boundary is incorrect';
  end if;
end $$;

insert into auth.users(id, email, aud, role, instance_id, raw_app_meta_data, raw_user_meta_data)
values ('${owner}', 'invitation-owner-${owner}@example.invalid', 'authenticated', 'authenticated',
        '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb);
insert into public.tenants(id, name, kind, created_by)
values ('${tenant}', 'Invitation audit ${tenant}', 'team', '${owner}');
insert into public.teams(id, tenant_id, name, plan)
values ('${tenant}', '${tenant}', 'Invitation audit ${tenant}', 'free');
insert into public.tenant_members(tenant_id, user_id, role)
values ('${tenant}', '${owner}', 'owner');

create function pg_temp.reject_invitation_audit()
returns trigger language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
begin
  if (tg_table_name = 'admin_audit_logs'
      and current_setting('aidr.test.reject_admin_audit', true) = 'on')
     or (tg_table_name = 'audit_logs'
      and current_setting('aidr.test.reject_tenant_audit', true) = 'on') then
    raise exception 'aidr_test_audit_insert_blocked';
  end if;
  return new;
end $$;
create trigger reject_invitation_audit_test
before insert on public.admin_audit_logs
for each row execute function pg_temp.reject_invitation_audit();
create trigger reject_invitation_tenant_audit_test
before insert on public.audit_logs
for each row execute function pg_temp.reject_invitation_audit();

set role service_role;
do $$
declare
  v_admin_audits bigint;
  v_tenant_audits bigint;
  v_result jsonb;
  v_id uuid;
  v_expiry timestamptz;
  v_stream text;
  v_action text;
  v_admin_event_id text;
  v_tenant_event_id text;
begin
  select count(*) into v_admin_audits from public.admin_audit_logs where tenant_id = '${tenant}';
  select count(*) into v_tenant_audits from public.audit_logs where tenant_id = '${tenant}';

  -- Either failed audit insert must undo the preceding invitation insert.
  foreach v_stream in array array['admin', 'tenant'] loop
    perform set_config('aidr.test.reject_' || v_stream || '_audit', 'on', true);
    begin
      perform public.mutate_team_invitation('create', '${tenant}', '${owner}',
        '${invitationEmail}', 'member', null, '${token1}');
      raise exception 'create succeeded despite blocked % audit', v_stream;
    exception when others then
      if sqlerrm <> 'aidr_test_audit_insert_blocked' then raise; end if;
    end;
    perform set_config('aidr.test.reject_' || v_stream || '_audit', 'off', true);
  end loop;
  if exists (select 1 from public.team_invitations
             where tenant_id = '${tenant}' and email = '${invitationEmail}')
     or (select count(*) from public.admin_audit_logs where tenant_id = '${tenant}') <> v_admin_audits
     or (select count(*) from public.audit_logs where tenant_id = '${tenant}') <> v_tenant_audits then
    raise exception 'failed create left an invitation or audit row';
  end if;

  v_result := public.mutate_team_invitation('create', '${tenant}', '${owner}',
    '${invitationEmail}', 'member', null, '${token1}');
  v_id := (v_result ->> 'id')::uuid;
  if v_id is null
     or not exists (select 1 from public.team_invitations
                    where id = v_id and tenant_id = '${tenant}'
                      and token_hash = '${token1}' and live_slot)
     or (select count(*) from public.admin_audit_logs
         where tenant_id = '${tenant}' and action = 'team.invitation_created'
           and detail ->> 'invitation_id' = v_id::text) <> 1 then
    raise exception 'successful create lacked invitation or atomic audit';
  end if;
  select expires_at into v_expiry from public.team_invitations where id = v_id;

  -- A failure in either stream must leave the original link and expiry usable.
  foreach v_stream in array array['admin', 'tenant'] loop
    perform set_config('aidr.test.reject_' || v_stream || '_audit', 'on', true);
    begin
      perform public.mutate_team_invitation('resend', '${tenant}', '${owner}',
        null, null, v_id, '${token2}');
      raise exception 'resend succeeded despite blocked % audit', v_stream;
    exception when others then
      if sqlerrm <> 'aidr_test_audit_insert_blocked' then raise; end if;
    end;
    perform set_config('aidr.test.reject_' || v_stream || '_audit', 'off', true);
  end loop;
  if not exists (select 1 from public.team_invitations
                 where id = v_id and token_hash = '${token1}'
                   and expires_at = v_expiry and live_slot)
     or (select count(*) from public.admin_audit_logs where tenant_id = '${tenant}') <> v_admin_audits + 1
     or (select count(*) from public.audit_logs where tenant_id = '${tenant}') <> v_tenant_audits + 1 then
    raise exception 'failed resend changed the live invitation or audit';
  end if;

  v_result := public.mutate_team_invitation('resend', '${tenant}', '${owner}',
    null, null, v_id, '${token2}');
  if (v_result ->> 'id')::uuid is distinct from v_id
     or not exists (select 1 from public.team_invitations
                    where id = v_id and token_hash = '${token2}' and live_slot)
     or (select count(*) from public.admin_audit_logs
         where tenant_id = '${tenant}' and action = 'team.invitation_link_replaced'
           and detail ->> 'invitation_id' = v_id::text) <> 1 then
    raise exception 'successful resend lacked replacement or atomic audit';
  end if;

  -- A failure in either stream must leave the replacement link valid.
  foreach v_stream in array array['admin', 'tenant'] loop
    perform set_config('aidr.test.reject_' || v_stream || '_audit', 'on', true);
    begin
      perform public.mutate_team_invitation('revoke', '${tenant}', '${owner}',
        null, null, v_id, null);
      raise exception 'revoke succeeded despite blocked % audit', v_stream;
    exception when others then
      if sqlerrm <> 'aidr_test_audit_insert_blocked' then raise; end if;
    end;
    perform set_config('aidr.test.reject_' || v_stream || '_audit', 'off', true);
  end loop;
  if not exists (select 1 from public.team_invitations
                 where id = v_id and token_hash = '${token2}'
                   and expires_at > clock_timestamp() and live_slot)
     or (select count(*) from public.admin_audit_logs where tenant_id = '${tenant}') <> v_admin_audits + 2
     or (select count(*) from public.audit_logs where tenant_id = '${tenant}') <> v_tenant_audits + 2 then
    raise exception 'failed revoke changed the live invitation or audit';
  end if;

  v_result := public.mutate_team_invitation('revoke', '${tenant}', '${owner}',
    null, null, v_id, null);
  if (v_result ->> 'id')::uuid is distinct from v_id
     or not exists (select 1 from public.team_invitations
                    where id = v_id and expires_at <= clock_timestamp() and not live_slot)
     or (select count(*) from public.admin_audit_logs
         where tenant_id = '${tenant}' and action = 'team.invitation_revoked'
           and detail ->> 'invitation_id' = v_id::text) <> 1
     or (select count(*) from public.admin_audit_logs where tenant_id = '${tenant}') <> v_admin_audits + 3
     or (select count(*) from public.audit_logs where tenant_id = '${tenant}') <> v_tenant_audits + 3 then
    raise exception 'successful revoke lacked expiry or atomic audit';
  end if;
  if public.mutate_team_invitation('revoke', '${tenant}', '${owner}',
       null, null, v_id, null) is not null
     or public.mutate_team_invitation('resend', '${tenant}', '${owner}',
       null, null, v_id, '${token1}') is not null
     or (select count(*) from public.admin_audit_logs where tenant_id = '${tenant}') <> v_admin_audits + 3
     or (select count(*) from public.audit_logs where tenant_id = '${tenant}') <> v_tenant_audits + 3 then
    raise exception 'revoked invitation was revived or audited twice';
  end if;

  foreach v_action in array array['team.invitation_created',
                                  'team.invitation_link_replaced',
                                  'team.invitation_revoked'] loop
    if (select count(*) from public.admin_audit_logs
        where tenant_id = '${tenant}' and action = v_action
          and detail ->> 'invitation_id' = v_id::text) <> 1
       or (select count(*) from public.audit_logs
           where team_id = '${tenant}' and tenant_id = '${tenant}'
             and user_id = '${owner}' and action = v_action
             and verdict ->> 'invitation_id' = v_id::text) <> 1 then
      raise exception 'dual audit row missing or duplicated for %', v_action;
    end if;
    select detail ->> 'event_id' into v_admin_event_id
      from public.admin_audit_logs
     where tenant_id = '${tenant}' and action = v_action;
    select verdict ->> 'event_id' into v_tenant_event_id
      from public.audit_logs
     where tenant_id = '${tenant}' and action = v_action;
    if v_admin_event_id is null
       or v_admin_event_id is distinct from v_tenant_event_id then
      raise exception 'audit stream correlation failed for %', v_action;
    end if;
  end loop;
  if (select count(distinct detail ->> 'event_id')
        from public.admin_audit_logs where tenant_id = '${tenant}') <> 3 then
    raise exception 'separate invitation mutations reused an audit event ID';
  end if;
  if exists (select 1 from public.admin_audit_logs
             where tenant_id = '${tenant}'
               and (detail ? 'email' or detail ? 'token' or detail ? 'token_hash'
                    or detail ? 'url' or position('${invitationEmail}' in detail::text) > 0
                    or position('${token1}' in detail::text) > 0
                    or position('${token2}' in detail::text) > 0))
     or exists (select 1 from public.audit_logs
                 where tenant_id = '${tenant}'
                   and (user_email is not null or verdict ? 'email' or verdict ? 'token'
                        or verdict ? 'token_hash' or verdict ? 'url'
                        or position('${invitationEmail}' in verdict::text) > 0
                        or position('${token1}' in verdict::text) > 0
                        or position('${token2}' in verdict::text) > 0)) then
    raise exception 'invitation audit leaked a recipient or link secret';
  end if;
end $$;

-- The API service role can use only the audited RPC, never raw invitation DML.
do $$ begin
  begin
    insert into public.team_invitations(tenant_id, email, role, token_hash, created_by)
    values ('${tenant}', 'raw-${invitationEmail}', 'member', '${token1}', '${owner}');
    raise exception 'service_role inserted invitation directly';
  exception when insufficient_privilege then null; end;
  begin
    update public.team_invitations set expires_at = now() where tenant_id = '${tenant}';
    raise exception 'service_role updated invitation directly';
  exception when insufficient_privilege then null; end;
  begin
    delete from public.team_invitations where tenant_id = '${tenant}';
    raise exception 'service_role deleted invitation directly';
  exception when insufficient_privilege then null; end;
  begin
    truncate public.team_invitations;
    raise exception 'service_role truncated invitations directly';
  exception when insufficient_privilege then null; end;
end $$;
reset role;

select set_config('request.jwt.claim.sub', '${owner}', true);
set role authenticated;
do $$ begin
  begin
    perform public.mutate_team_invitation('create', '${tenant}', '${owner}',
      'browser-${invitationEmail}', 'member', null, '${token1}');
    raise exception 'browser role executed privileged invitation RPC';
  exception when insufficient_privilege then null; end;
end $$;
reset role;

rollback;
select 'TEAM_INVITATION_ATOMIC_AUDIT_ROLLBACK';
`;

const result = spawnSync("docker", [
  "exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1",
  "-U", "postgres", "-d", "postgres", "-q", "-At",
], { input: sql, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 120_000 });
if (result.error) throw result.error;
assert.equal(result.status, 0, `invitation atomic-audit regression failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /TEAM_INVITATION_ATOMIC_AUDIT_ROLLBACK/);
console.log("Invitation atomic-audit PostgreSQL test passed: create, resend, revoke rollback on either audit failure; correlated dual audit, retry, direct-DML and browser-RPC boundaries; fixtures rolled back.");
