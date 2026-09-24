-- Optional tenant SAML enforcement. NULL keeps existing tenants unchanged.
-- Activation requires a separate IdP/SCIM identity migration and field acceptance.
alter table public.tenant_identity_policies
  add column required_saml_provider_id uuid;

create or replace function public.tenant_identity_access_allowed(p_tenant_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select
    auth.uid() is not null
    and not exists (
      select 1 from public.identity_user_session_state s
      where s.user_id = auth.uid()
        and (
          s.global_revoke_pending_session_id is not null
          or (
            s.revoked_before is not null
            and (
              coalesce(auth.jwt()->>'iat', '') !~ '^[0-9]+(\.[0-9]+)?$'
              or to_timestamp((auth.jwt()->>'iat')::double precision) <= s.revoked_before
            )
          )
        )
    )
    and not exists (
      select 1 from public.tenant_identity_policies p
      where p.tenant_id = p_tenant_id
        and p.require_mfa
        and coalesce(auth.jwt()->>'aal', 'aal1') <> 'aal2'
    )
    and not exists (
      select 1 from public.tenant_identity_policies p
      where p.tenant_id = p_tenant_id
        and p.required_saml_provider_id is not null
        and not exists (
          select 1
          from jsonb_array_elements(
            case when jsonb_typeof(auth.jwt()->'amr') = 'array'
              then auth.jwt()->'amr' else '[]'::jsonb end
          ) as amr(entry)
          where amr.entry->>'method' = 'sso/saml'
            and amr.entry->>'provider' = p.required_saml_provider_id::text
        )
    );
$$;
revoke all on function public.tenant_identity_access_allowed(uuid) from public, anon;
grant execute on function public.tenant_identity_access_allowed(uuid) to authenticated, service_role;

-- Include tenant tables added after the original identity-policy migration.
do $$
declare v_table record;
begin
  for v_table in
    select distinct c.table_name
    from information_schema.columns c
    join pg_class pc on pc.relname = c.table_name
    join pg_namespace pn on pn.oid = pc.relnamespace and pn.nspname = c.table_schema
    where c.table_schema = 'public' and c.column_name = 'tenant_id'
      and pc.relkind in ('r', 'p') and pc.relrowsecurity
  loop
    execute format('drop policy if exists tenant_identity_access_restrict on public.%I', v_table.table_name);
    execute format(
      'create policy tenant_identity_access_restrict on public.%I as restrictive for all to authenticated using (public.tenant_identity_access_allowed(tenant_id)) with check (public.tenant_identity_access_allowed(tenant_id))',
      v_table.table_name
    );
  end loop;
end;
$$;
