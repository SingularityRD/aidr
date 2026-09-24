-- A dashboard pilot check is not an authorization boundary: service-only
-- credential RPCs and ingest can otherwise admit a newly created free team.
-- Apply the same tenant-scoped admission rule to every credential and new
-- agent insertion, including a token/key issued before this migration.
create or replace function public.require_enrollment_admission()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  -- Lock in a fixed order. A concurrent suspension, pilot revocation or seat
  -- reduction must serialize with the admission it is withdrawing.
  perform 1 from public.tenants t
    where t.id = new.tenant_id and t.status = 'active' for share;
  if not found then
    raise exception 'tenant_enrollment_not_approved' using errcode = '42501';
  end if;
  perform 1 from public.pilot_applications p
    where p.tenant_id = new.tenant_id and p.status = 'approved' for share;
  if not found then
    raise exception 'tenant_enrollment_not_approved' using errcode = '42501';
  end if;
  perform 1 from public.entitlements e
    where e.tenant_id = new.tenant_id
      and e.included_agents + e.extra_agents > 0 for share;
  if not found then
    raise exception 'tenant_enrollment_not_approved' using errcode = '42501';
  end if;
  return new;
end;
$$;

revoke all on function public.require_enrollment_admission()
  from public, anon, authenticated;

create trigger api_keys_enrollment_admission
before insert or update of key_hash on public.api_keys
for each row execute function public.require_enrollment_admission();

create trigger enrollment_tokens_admission
before insert or update of token_hash on public.enrollment_tokens
for each row execute function public.require_enrollment_admission();

-- Existing installations may keep sending telemetry after a later approval
-- change. New registrations cannot evade the credential gate using an old key.
create trigger agents_enrollment_admission
before insert on public.agents
for each row execute function public.require_enrollment_admission();
