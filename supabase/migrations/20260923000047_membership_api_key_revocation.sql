-- A removed or downgraded member must not regain old bearer keys if re-added.
-- Lock the canonical membership during key issue/rotation so an in-flight
-- insert cannot land after the removal transaction's revocation sweep.
create function app.require_credential_member()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
begin
  perform 1 from public.tenant_members m
    where m.tenant_id = new.tenant_id and m.user_id = new.user_id
      and m.role in ('owner', 'admin', 'member')
      and (m.expires_at is null or m.expires_at > clock_timestamp())
    for share;
  if not found then
    raise exception 'api_key_member_inactive' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.require_credential_member()
  from public, anon, authenticated, service_role;
create trigger api_keys_owner_membership
before insert or update of key_hash on public.api_keys
for each row execute function app.require_credential_member();

create function app.revoke_member_api_keys()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
declare
  v_count integer;
begin
  if tg_op = 'UPDATE'
     and old.tenant_id is not distinct from new.tenant_id
     and old.user_id is not distinct from new.user_id
     and old.role in ('owner', 'admin', 'member')
     and new.role in ('owner', 'admin', 'member')
     and (old.expires_at is null or old.expires_at > clock_timestamp())
     and (new.expires_at is null or new.expires_at > clock_timestamp()) then
    return new;
  end if;

  update public.api_keys
    set revoked = true, previous_hash = null, previous_hash_expires_at = null
    where tenant_id = old.tenant_id and user_id = old.user_id and not revoked;
  get diagnostics v_count = row_count;
  if v_count > 0 and exists (
    select 1 from public.tenants t
    where t.id = old.tenant_id and t.status not in ('closing', 'closed')
  ) then
    insert into public.admin_audit_logs
      (actor_user_id, tenant_id, target_user_id, action, detail)
    values (auth.uid(), old.tenant_id, old.user_id,
      'api_key.membership_revoked',
      jsonb_build_object('key_count', v_count,
        'reason', case when tg_op = 'DELETE' then 'removed' else 'membership_changed' end));
  end if;
  if tg_op = 'DELETE' then return old; end if;
  return new;
end;
$$;
revoke all on function app.revoke_member_api_keys()
  from public, anon, authenticated, service_role;
create trigger tenant_members_revoke_api_keys
after update or delete on public.tenant_members
for each row execute function app.revoke_member_api_keys();

-- Existing orphaned/viewer/expired-owner keys predate the trigger. Revoke them
-- now so restoring membership after this migration cannot revive old secrets.
with revoked as (
  update public.api_keys k
    set revoked = true, previous_hash = null, previous_hash_expires_at = null
    where not k.revoked and not exists (
      select 1 from public.tenant_members m
      where m.tenant_id = k.tenant_id and m.user_id = k.user_id
        and m.role in ('owner', 'admin', 'member')
        and (m.expires_at is null or m.expires_at > clock_timestamp())
    )
    returning k.tenant_id, k.user_id
)
insert into public.admin_audit_logs(tenant_id, target_user_id, action, detail)
select r.tenant_id, r.user_id, 'api_key.membership_revoked',
  jsonb_build_object('reason', 'migration_backfill', 'key_count', count(*))
from revoked r
join public.tenants t on t.id = r.tenant_id
  and t.status not in ('closing', 'closed')
group by r.tenant_id, r.user_id;
