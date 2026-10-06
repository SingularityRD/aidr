-- The callback validates a provider snapshot before doing network work. Its
-- first identity insert must not bind that old token to a replacement issuer.
create function public.oidc_insert_identity(
  p_provider_id uuid, p_tenant_id uuid, p_subject text, p_auth_user_id uuid,
  p_email_claim text, p_expected_issuer text, p_expected_client_id text, p_expected_subject_claim text
)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if p_provider_id is null or p_tenant_id is null or p_auth_user_id is null
     or p_subject is null or length(p_subject) not between 1 and 255 then
    raise exception 'oidc_identity_invalid_request' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2607));
  -- The configuration trigger shares 2607. No provider row lock is taken here:
  -- a concurrent UPDATE owns that row before entering its trigger.
  if not exists (
    select 1 from public.oidc_providers
    where id = p_provider_id and tenant_id = p_tenant_id and enabled
      and issuer = p_expected_issuer and client_id = p_expected_client_id
      and subject_claim = p_expected_subject_claim
  ) then
    raise exception 'oidc_provider_identity_namespace_changed' using errcode = '55000';
  end if;
  insert into public.oidc_identities(provider_id, tenant_id, subject, auth_user_id, email_claim, last_login_at)
    values (p_provider_id, p_tenant_id, p_subject, p_auth_user_id, p_email_claim, clock_timestamp());
end;
$$;
revoke all on function public.oidc_insert_identity(uuid, uuid, text, uuid, text, text, text, text)
  from public, anon, authenticated;
grant execute on function public.oidc_insert_identity(uuid, uuid, text, uuid, text, text, text, text) to service_role;
