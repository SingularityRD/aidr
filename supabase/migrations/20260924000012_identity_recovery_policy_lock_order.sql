-- Policy changes already take the tenant advisory lock before deleting unused
-- recovery codes. Issuance must take that same lock first, then its narrower
-- per-user lock, so disable and issue serialize in one canonical order.
create or replace function public.issue_identity_recovery_codes(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_target_user_id uuid,
  p_code_hashes text[],
  p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_batch_id uuid := gen_random_uuid();
begin
  if p_tenant_id is null or p_actor_user_id is null or p_target_user_id is null
    or coalesce(cardinality(p_code_hashes), 0) not between 4 and 16
    or p_expires_at <= now() + interval '1 day'
    or p_expires_at > now() + interval '180 days'
    or exists(select 1 from unnest(p_code_hashes) h where h !~ '^[0-9a-f]{64}$')
    or (select count(distinct h) from unnest(p_code_hashes) h) <> cardinality(p_code_hashes)
  then raise exception 'invalid_recovery_code_batch' using errcode = '22023'; end if;

  if p_actor_user_id <> p_target_user_id then
    raise exception 'recovery_code_issue_forbidden' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2607));
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':' || p_target_user_id::text, 2607));
  if not exists (
    select 1 from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
      and (m.expires_at is null or m.expires_at > now()) and t.status = 'active'
  ) then
    raise exception 'recovery_code_issue_forbidden' using errcode = '42501';
  end if;
  if not exists(select 1 from public.tenant_identity_policies where tenant_id = p_tenant_id and break_glass_enabled)
  then raise exception 'break_glass_disabled' using errcode = '42501'; end if;

  delete from public.identity_recovery_codes
    where tenant_id = p_tenant_id and user_id = p_target_user_id and used_at is null;
  insert into public.identity_recovery_codes(batch_id, tenant_id, user_id, code_hash, created_by, expires_at)
    select v_batch_id, p_tenant_id, p_target_user_id, h, p_actor_user_id, p_expires_at
    from unnest(p_code_hashes) h;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
    values(p_actor_user_id, p_tenant_id, p_target_user_id, 'identity.recovery_codes.rotated',
      jsonb_build_object('batch_id', v_batch_id, 'count', cardinality(p_code_hashes), 'expires_at', p_expires_at));
  return jsonb_build_object('batch_id', v_batch_id, 'count', cardinality(p_code_hashes), 'expires_at', p_expires_at);
end;
$$;
revoke all on function public.issue_identity_recovery_codes(uuid, uuid, uuid, text[], timestamptz)
  from public, anon, authenticated;
grant execute on function public.issue_identity_recovery_codes(uuid, uuid, uuid, text[], timestamptz)
  to service_role;
