// Run only after a full reset of a disposable Supabase DB containing migration 47.
// AIDR_TEST_DISPOSABLE_DB=1 AIDR_RLS_TEST_DB_CONTAINER=supabase_db_aidr node scripts/member-api-key-revocation-postgres.mjs
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.equal(process.env.AIDR_TEST_DISPOSABLE_DB, "1", "confirm a disposable database");
assert.match(container ?? "", /^supabase_db_[A-Za-z0-9_.-]+$/, "name a disposable Supabase DB container");
const [owner, member, otherOwner, tenant, otherTenant] = Array.from({ length: 5 }, () => randomUUID());
const marker = randomUUID().replaceAll("-", "");
const [oldHash, retiredHash, newHash, otherHash] = Array.from({ length: 4 }, () => randomBytes(32).toString("hex"));

const sql = String.raw`
\set ON_ERROR_STOP on
begin;
do $$ begin
  if not exists (select 1 from pg_trigger where tgrelid = 'public.tenant_members'::regclass
    and tgname = 'tenant_members_revoke_api_keys' and not tgisinternal)
  then raise exception 'membership API-key revocation migration missing'; end if;
end $$;
update app.tenant_admission_config set mode = 'pilot' where singleton;
insert into auth.users(id,email,aud,role,instance_id,raw_app_meta_data,raw_user_meta_data)
values ('${owner}','key-owner-${marker}@example.invalid','authenticated','authenticated','00000000-0000-0000-0000-000000000000','{}','{}'),
       ('${member}','key-member-${marker}@example.invalid','authenticated','authenticated','00000000-0000-0000-0000-000000000000','{}','{}'),
       ('${otherOwner}','key-other-${marker}@example.invalid','authenticated','authenticated','00000000-0000-0000-0000-000000000000','{}','{}');
insert into public.tenants(id,name,kind,created_by)
values ('${tenant}','Key revocation ${marker}','team','${owner}'),
       ('${otherTenant}','Other key revocation ${marker}','team','${otherOwner}');
insert into public.teams(id,tenant_id,name)
values ('${tenant}','${tenant}','Key revocation ${marker}'),
       ('${otherTenant}','${otherTenant}','Other key revocation ${marker}');
insert into public.team_members(team_id,tenant_id,user_id,role)
values ('${tenant}','${tenant}','${owner}','owner'),
       ('${tenant}','${tenant}','${member}','member'),
       ('${otherTenant}','${otherTenant}','${otherOwner}','owner');
insert into public.entitlements(user_id,tenant_id,included_agents)
values ('${owner}','${tenant}',2),('${otherOwner}','${otherTenant}',1);
insert into public.pilot_applications(user_id,tenant_id,status)
values ('${owner}','${tenant}','approved'),('${otherOwner}','${otherTenant}','approved');
insert into public.api_keys(user_id,tenant_id,label,key_hash,previous_hash,previous_hash_expires_at,rotated_at)
values ('${member}','${tenant}','before-removal','${oldHash}',
        '${retiredHash}',clock_timestamp() + interval '1 hour',clock_timestamp()),
       ('${otherOwner}','${otherTenant}','unrelated','${otherHash}',null,null,null);

delete from public.team_members where team_id = '${tenant}' and user_id = '${member}';
do $$ begin
  if not exists (select 1 from public.api_keys where key_hash = '${oldHash}'
    and revoked and previous_hash is null and previous_hash_expires_at is null)
    or exists (select 1 from public.tenant_members where tenant_id = '${tenant}' and user_id = '${member}')
    or (select count(*) from public.admin_audit_logs where tenant_id = '${tenant}'
      and target_user_id = '${member}' and action = 'api_key.membership_revoked'
      and detail ->> 'reason' = 'removed' and detail ->> 'key_count' = '1') <> 1
    or not exists (select 1 from public.api_keys where key_hash = '${otherHash}' and not revoked)
  then raise exception 'member removal did not permanently revoke only its keys'; end if;
end $$;

insert into public.team_members(team_id,tenant_id,user_id,role)
values ('${tenant}','${tenant}','${member}','member');
do $$ begin
  if not exists (select 1 from public.api_keys where key_hash = '${oldHash}' and revoked)
  then raise exception 're-invitation resurrected an old key'; end if;
end $$;
insert into public.api_keys(user_id,tenant_id,label,key_hash)
values ('${member}','${tenant}','new-key','${newHash}');
update public.team_members set role = 'viewer'
where team_id = '${tenant}' and user_id = '${member}';
do $$ begin
  if not exists (select 1 from public.api_keys where key_hash = '${newHash}' and revoked)
    or (select count(*) from public.admin_audit_logs where tenant_id = '${tenant}'
      and target_user_id = '${member}' and action = 'api_key.membership_revoked'
      and detail ->> 'reason' = 'membership_changed' and detail ->> 'key_count' = '1') <> 1
  then raise exception 'role downgrade left a live key'; end if;
end $$;
update public.team_members set role = 'member'
where team_id = '${tenant}' and user_id = '${member}';
do $$ begin
  if not exists (select 1 from public.api_keys where key_hash = '${newHash}' and revoked)
  then raise exception 'role upgrade resurrected an old key'; end if;
end $$;

delete from public.team_members where team_id = '${tenant}' and user_id = '${member}';
do $$ begin
  begin
    insert into public.api_keys(user_id,tenant_id,label,key_hash)
    values ('${member}','${tenant}','must-fail','${randomBytes(32).toString("hex")}');
    raise exception 'removed member issued a key';
  exception when sqlstate '42501' then null; end;
end $$;
rollback;
select 'MEMBER_API_KEY_REVOCATION_ROLLBACK';
`;

const result = spawnSync("docker", ["exec", "-i", "-e", "PGPASSWORD=postgres", container,
  "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
  "-U", "supabase_admin", "-d", "postgres"],
  { input: sql, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 120_000 });
if (result.error) throw result.error;
assert.equal(result.status, 0, `membership API-key PostgreSQL regression failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /MEMBER_API_KEY_REVOCATION_ROLLBACK/);
console.log("Membership API-key revocation passed: removal, re-invite, role downgrade/re-upgrade, issuance denial and tenant isolation; fixture rolled back.");
