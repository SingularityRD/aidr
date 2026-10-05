-- Audited legal-hold management RPCs (service role only; called by the
-- `retention-admin` Edge Function after it authenticates a tenant owner).
--
-- The hold table, its tenant advisory lock (seed 2606), immutable history and the
-- retention/audit-export/offboarding hold checks are unchanged. This migration
-- adds:
--   * `case_id` and `hold_owner` columns (legacy holds keep NULLs; new holds made
--     through the RPC require both),
--   * the immutability trigger now also freezes those columns,
--   * `admin_place_tenant_legal_hold` / `admin_release_tenant_legal_hold`, which
--     verify an active owner, validate input, write the hold change and its
--     `admin_audit_logs` row in ONE transaction.
-- Applied migrations are not edited. Everything here is idempotent.

alter table public.tenant_legal_holds
  add column if not exists case_id text,
  add column if not exists hold_owner text;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'tenant_legal_holds_case_id_format'
                 and conrelid = 'public.tenant_legal_holds'::regclass) then
    alter table public.tenant_legal_holds add constraint tenant_legal_holds_case_id_format
      check (case_id is null or (length(case_id) between 1 and 100 and case_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/ #-]*$'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'tenant_legal_holds_hold_owner_format'
                 and conrelid = 'public.tenant_legal_holds'::regclass) then
    alter table public.tenant_legal_holds add constraint tenant_legal_holds_hold_owner_format
      check (hold_owner is null or (length(hold_owner) between 1 and 200 and hold_owner !~ '[[:cntrl:]]'
                                    and hold_owner = btrim(hold_owner)));
  end if;
end
$$;

-- Freeze the new columns in the single-release update rule. The trigger body has
-- been patched in place by earlier migrations, so extend the live definition
-- instead of copying a stale one.
do $migration$
declare
  v_definition text;
  v_old text := 'or new.placed_at is distinct from old.placed_at';
begin
  select pg_get_functiondef('app.protect_tenant_legal_hold()'::regprocedure) into v_definition;
  if position('new.case_id is distinct from old.case_id' in v_definition) > 0 then
    return;
  end if;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 then
    raise exception 'unexpected_legal_hold_trigger_definition';
  end if;
  execute replace(v_definition, v_old, v_old || '
      or new.case_id is distinct from old.case_id
      or new.hold_owner is distinct from old.hold_owner');
end
$migration$;

create or replace function app.retention_assert_tenant_owner(p_tenant_id uuid, p_actor_user_id uuid)
returns void
language plpgsql
security definer
set search_path = public, pg_catalog, pg_temp
as $$
begin
  if p_tenant_id is null or p_actor_user_id is null or not exists (
    select 1
      from public.tenants t
      join public.tenant_members tm on tm.tenant_id = t.id
     where t.id = p_tenant_id
       and t.status = 'active'
       and tm.user_id = p_actor_user_id
       and tm.role = 'owner'
       and (tm.expires_at is null or tm.expires_at > now())
  ) then
    raise exception 'retention_admin_owner_required' using errcode = '42501';
  end if;
end;
$$;

create or replace function public.admin_place_tenant_legal_hold(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_case_id text,
  p_hold_owner text,
  p_reason text,
  p_hold_reference text default null
) returns uuid
language plpgsql
security definer
set search_path = public, pg_catalog, pg_temp
as $$
declare
  v_id uuid;
  v_reference text := coalesce(p_hold_reference, p_case_id);
begin
  perform app.retention_assert_tenant_owner(p_tenant_id, p_actor_user_id);
  if p_case_id is null or p_case_id <> btrim(p_case_id) or length(p_case_id) not between 1 and 100
     or p_case_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/ #-]*$'
     or p_hold_owner is null or p_hold_owner <> btrim(p_hold_owner) or length(p_hold_owner) not between 1 and 200
     or p_hold_owner ~ '[[:cntrl:]]'
     or p_reason is null or p_reason <> btrim(p_reason) or length(p_reason) not between 1 and 2000
     or p_reason ~ '[[:cntrl:]]'
     or v_reference is null or v_reference <> btrim(v_reference) or length(v_reference) not between 1 and 200
     or v_reference ~ '[[:cntrl:]]' then
    raise exception 'legal_hold_invalid_request' using errcode = '22023';
  end if;
  -- The hold trigger takes this same lock; take it first so the active-hold check
  -- and the insert are one serialized step with retention and offboarding.
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  if exists (select 1 from public.tenant_legal_holds where tenant_id = p_tenant_id and released_at is null) then
    raise exception 'legal_hold_already_active' using errcode = '23505';
  end if;
  insert into public.tenant_legal_holds(tenant_id, hold_reference, reason, placed_by, case_id, hold_owner)
    values (p_tenant_id, v_reference, p_reason, p_actor_user_id, p_case_id, p_hold_owner)
    returning id into v_id;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values (p_actor_user_id, p_tenant_id, 'legal_hold.placed',
      jsonb_build_object('hold_id', v_id, 'case_id', p_case_id, 'hold_owner', p_hold_owner, 'hold_reference', v_reference));
  return v_id;
end;
$$;

create or replace function public.admin_release_tenant_legal_hold(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_hold_id uuid,
  p_release_reason text
) returns boolean
language plpgsql
security definer
set search_path = public, pg_catalog, pg_temp
as $$
declare
  v_hold public.tenant_legal_holds;
begin
  perform app.retention_assert_tenant_owner(p_tenant_id, p_actor_user_id);
  if p_hold_id is null or p_release_reason is null or p_release_reason <> btrim(p_release_reason)
     or length(p_release_reason) not between 1 and 2000 or p_release_reason ~ '[[:cntrl:]]' then
    raise exception 'legal_hold_invalid_request' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  update public.tenant_legal_holds
     set released_at = now(), released_by = p_actor_user_id, release_reason = p_release_reason
   where id = p_hold_id and tenant_id = p_tenant_id and released_at is null
   returning * into v_hold;
  if not found then
    return false;
  end if;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values (p_actor_user_id, p_tenant_id, 'legal_hold.released',
      jsonb_build_object('hold_id', v_hold.id, 'case_id', v_hold.case_id, 'hold_owner', v_hold.hold_owner,
                         'placed_at', v_hold.placed_at));
  return true;
end;
$$;

revoke all on function app.retention_assert_tenant_owner(uuid, uuid) from public, anon, authenticated;
revoke all on function public.admin_place_tenant_legal_hold(uuid, uuid, text, text, text, text) from public, anon, authenticated;
revoke all on function public.admin_release_tenant_legal_hold(uuid, uuid, uuid, text) from public, anon, authenticated;
grant execute on function app.retention_assert_tenant_owner(uuid, uuid) to service_role;
grant execute on function public.admin_place_tenant_legal_hold(uuid, uuid, text, text, text, text) to service_role;
grant execute on function public.admin_release_tenant_legal_hold(uuid, uuid, uuid, text) to service_role;
