-- Tenant OpenID Connect SSO (Entra ID, Okta, generic) alongside SAML.
--
-- Design (docs/production-readiness/oidc-sso-admin.md):
--   * One OIDC provider per tenant; per-tenant enforcement is optional and NULL
--     keeps every existing tenant unchanged, exactly like required_saml_provider_id.
--   * A tenant enforces SAML or OIDC, never both (check constraint).
--   * Identity is the provider-qualified subject (provider_id, sub). Email never
--     links accounts. Membership and roles still come from SCIM (same exact
--     external-group-id mapping, no owner grant), so OIDC adds sign-in, not a
--     second authorization model.
--   * Supabase Auth has no native generic OIDC SSO, so the Edge function mints a
--     one-time magic-link session after verifying the ID token. That session
--     carries no `sso/saml` AMR; proof of SSO is a server-side row keyed by the
--     JWT session_id (oidc_sso_sessions). The restrictive RLS predicate requires
--     a live row for the enforced provider.
--   * All OIDC tables are service-role only (RLS enabled, no policies, no grants).

create table public.oidc_providers (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null unique references public.tenants(id) on delete cascade,
  kind text not null check (kind in ('entra', 'okta', 'generic')),
  display_name text not null check (length(display_name) between 1 and 64),
  issuer text not null check (issuer ~ '^https://[^\s?#@]+$' and length(issuer) <= 512),
  client_id text not null check (length(client_id) between 1 and 256 and client_id !~ '[\s]'),
  -- Name of an Edge secret holding the client secret (AIDR_OIDC_CLIENT_SECRET_<ref>).
  -- The secret itself is never stored in the database.
  client_secret_ref text check (client_secret_ref is null or client_secret_ref ~ '^[A-Z0-9_]{1,40}$'),
  token_auth_method text not null default 'client_secret_basic'
    check (token_auth_method in ('client_secret_basic', 'client_secret_post', 'none')),
  allowed_algs text[] not null default array['RS256']
    check (allowed_algs <@ array['RS256', 'PS256', 'ES256'] and cardinality(allowed_algs) between 1 and 3),
  subject_claim text not null default 'sub' check (subject_claim in ('sub', 'oid')),
  groups_claim text check (groups_claim is null or groups_claim ~ '^[A-Za-z0-9_:.-]{1,64}$'),
  groups_mode text not null default 'ignore' check (groups_mode in ('ignore', 'require_mapped')),
  session_max_seconds integer not null default 43200 check (session_max_seconds between 900 and 86400),
  clock_skew_seconds integer not null default 60 check (clock_skew_seconds between 0 and 120),
  discovery jsonb,
  discovery_fetched_at timestamptz,
  enabled boolean not null default false,
  last_login_at timestamptz,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (token_auth_method = 'none' or client_secret_ref is not null),
  check (not enabled or discovery is not null)
);
create trigger oidc_providers_touch_updated_at
before update on public.oidc_providers
for each row execute procedure public.touch_updated_at();

-- Tenant-bound domain verification. The email domain asserted by the IdP must be
-- a domain this tenant proved it controls (DNS TXT), and a verified domain
-- belongs to exactly one tenant, so provider A can never sign users into B.
create table public.oidc_tenant_domains (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  domain text not null check (domain = lower(domain) and domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'),
  verification_token text not null check (verification_token ~ '^[A-Za-z0-9_-]{32,64}$'),
  verified_at timestamptz,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  primary key (tenant_id, domain)
);
create unique index oidc_tenant_domains_verified_unique
  on public.oidc_tenant_domains(domain) where verified_at is not null;

-- One row per authorization request. `consumed_at` is set by the single UPDATE
-- that also validates state, so a replayed state value matches no row.
create table public.oidc_auth_requests (
  id uuid primary key default gen_random_uuid(),
  state_hash text not null unique check (state_hash ~ '^[0-9a-f]{64}$'),
  provider_id uuid not null references public.oidc_providers(id) on delete cascade,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  nonce_hash text not null check (nonce_hash ~ '^[0-9a-f]{64}$'),
  code_verifier text not null check (code_verifier ~ '^[A-Za-z0-9._~-]{43,128}$'),
  binding_hash text not null check (binding_hash ~ '^[0-9a-f]{64}$'),
  redirect_uri text not null,
  mode text not null default 'login' check (mode in ('login', 'link')),
  link_user_id uuid references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  check (expires_at > created_at),
  check ((mode = 'link') = (link_user_id is not null))
);
create index oidc_auth_requests_expiry on public.oidc_auth_requests(expires_at);

create table public.oidc_identities (
  provider_id uuid not null references public.oidc_providers(id) on delete cascade,
  subject text not null check (length(subject) between 1 and 255),
  auth_user_id uuid not null references auth.users(id) on delete cascade,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  email_claim text,
  created_at timestamptz not null default now(),
  last_login_at timestamptz,
  primary key (provider_id, subject),
  unique (provider_id, auth_user_id)
);

create table public.oidc_login_tickets (
  id uuid primary key default gen_random_uuid(),
  ticket_hash text not null unique check (ticket_hash ~ '^[0-9a-f]{64}$'),
  provider_id uuid not null references public.oidc_providers(id) on delete cascade,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  auth_user_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  check (expires_at > created_at)
);

create table public.oidc_sso_sessions (
  session_id uuid primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  provider_id uuid not null references public.oidc_providers(id) on delete cascade,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  check (expires_at > created_at)
);
create index oidc_sso_sessions_user on public.oidc_sso_sessions(user_id, provider_id);

alter table public.oidc_providers enable row level security;
alter table public.oidc_tenant_domains enable row level security;
alter table public.oidc_auth_requests enable row level security;
alter table public.oidc_identities enable row level security;
alter table public.oidc_login_tickets enable row level security;
alter table public.oidc_sso_sessions enable row level security;
revoke all on public.oidc_providers, public.oidc_tenant_domains, public.oidc_auth_requests,
  public.oidc_identities, public.oidc_login_tickets, public.oidc_sso_sessions
  from public, anon, authenticated;
grant select, insert, update, delete on public.oidc_providers, public.oidc_tenant_domains,
  public.oidc_auth_requests, public.oidc_identities, public.oidc_login_tickets,
  public.oidc_sso_sessions to service_role;

-- Enforcement. SAML and OIDC are mutually exclusive per tenant, and one provider
-- row can be required by at most one policy.
alter table public.tenant_identity_policies
  add column required_oidc_provider_id uuid references public.oidc_providers(id) on delete restrict,
  add constraint tenant_identity_policies_single_sso
    check (required_saml_provider_id is null or required_oidc_provider_id is null);
create unique index tenant_identity_policies_oidc_provider_unique
  on public.tenant_identity_policies(required_oidc_provider_id)
  where required_oidc_provider_id is not null;

-- The restrictive RLS predicate gains one clause: when a tenant enforces OIDC,
-- the JWT's session must have a live, unrevoked oidc_sso_sessions row for that
-- provider. Everything else is the 20260923000021 definition, unchanged.
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
    )
    and not exists (
      select 1 from public.tenant_identity_policies p
      where p.tenant_id = p_tenant_id
        and p.required_oidc_provider_id is not null
        and not exists (
          select 1 from public.oidc_sso_sessions o
          where coalesce(auth.jwt()->>'session_id', '') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            and o.session_id = (auth.jwt()->>'session_id')::uuid
            and o.user_id = auth.uid()
            and o.provider_id = p.required_oidc_provider_id
            and o.tenant_id = p_tenant_id
            and o.revoked_at is null
            and o.expires_at > now()
        )
    );
$$;
revoke all on function public.tenant_identity_access_allowed(uuid) from public, anon;
grant execute on function public.tenant_identity_access_allowed(uuid) to authenticated, service_role;

-- Atomically consume a login ticket and bind the browser's new Auth session to
-- the provider. The ticket is single-use, short-lived and tied to the Auth user.
create or replace function public.oidc_record_sso_session(
  p_ticket_hash text,
  p_user_id uuid,
  p_session_id uuid
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_ticket public.oidc_login_tickets%rowtype;
  v_provider public.oidc_providers%rowtype;
  v_expires timestamptz;
begin
  if p_ticket_hash !~ '^[0-9a-f]{64}$' or p_user_id is null or p_session_id is null then
    return null;
  end if;
  update public.oidc_login_tickets
     set consumed_at = clock_timestamp()
   where ticket_hash = p_ticket_hash
     and auth_user_id = p_user_id
     and consumed_at is null
     and expires_at > clock_timestamp()
  returning * into v_ticket;
  if not found then return null; end if;
  select * into v_provider from public.oidc_providers where id = v_ticket.provider_id and enabled;
  if not found then return null; end if;
  v_expires := clock_timestamp() + make_interval(secs => v_provider.session_max_seconds);
  insert into public.oidc_sso_sessions(session_id, user_id, provider_id, tenant_id, expires_at)
    values (p_session_id, p_user_id, v_provider.id, v_provider.tenant_id, v_expires)
    on conflict (session_id) do nothing;
  if not found then return null; end if;
  update public.oidc_providers set last_login_at = clock_timestamp() where id = v_provider.id;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
    values (p_user_id, v_provider.tenant_id, p_user_id, 'identity.oidc.session_bound',
      jsonb_build_object('provider_id', v_provider.id, 'session_expires_at', v_expires));
  return jsonb_build_object('provider_id', v_provider.id, 'tenant_id', v_provider.tenant_id,
    'expires_at', v_expires);
end;
$$;
revoke all on function public.oidc_record_sso_session(text, uuid, uuid) from public, anon, authenticated;
grant execute on function public.oidc_record_sso_session(text, uuid, uuid) to service_role;

-- Bind a verified (provider, subject) Auth user to the SCIM user with the same
-- external id. Mirrors scim_bind_saml_identity: only when the tenant enforces
-- this provider, only by subject (never email), never over a manual membership
-- and never over a different bound Auth user.
create or replace function public.oidc_bind_scim_identity(p_provider_id uuid, p_auth_user_id uuid)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public, auth, pg_temp
as $$
declare
  v_tenant_id uuid;
  v_subject text;
  v_scim_user_id uuid;
  v_bound_user_id uuid;
begin
  if p_provider_id is null or p_auth_user_id is null then return null; end if;
  select p.tenant_id into v_tenant_id
    from public.tenant_identity_policies p join public.tenants t on t.id = p.tenant_id
   where p.required_oidc_provider_id = p_provider_id and t.status = 'active';
  if v_tenant_id is null then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 2607));
  select i.subject into v_subject from public.oidc_identities i
   where i.provider_id = p_provider_id and i.auth_user_id = p_auth_user_id and i.tenant_id = v_tenant_id;
  if v_subject is null or position('@' in v_subject) > 0 then return null; end if;
  select su.id, su.auth_user_id into v_scim_user_id, v_bound_user_id
    from public.scim_users su
   where su.tenant_id = v_tenant_id and su.external_id = v_subject and su.active
   for update;
  if v_scim_user_id is null then return null; end if;
  if v_bound_user_id is not null and v_bound_user_id <> p_auth_user_id then
    raise exception 'scim_oidc_identity_conflict' using errcode = '23505';
  end if;
  if v_bound_user_id is null then
    if exists (
      select 1 from public.tenant_members m
      where m.tenant_id = v_tenant_id and m.user_id = p_auth_user_id
        and not exists (
          select 1 from public.scim_managed_memberships smm
          where smm.tenant_id = v_tenant_id and smm.scim_user_id = v_scim_user_id
            and smm.auth_user_id = p_auth_user_id
        )
    ) then raise exception 'scim_cannot_take_over_manual_membership' using errcode = '42501'; end if;
    perform public.scim_bind_user(v_tenant_id, v_scim_user_id, p_auth_user_id);
  end if;
  return v_tenant_id;
end;
$$;
revoke all on function public.oidc_bind_scim_identity(uuid, uuid) from public, anon, authenticated;
grant execute on function public.oidc_bind_scim_identity(uuid, uuid) to service_role;

-- Audited enforcement change. Activation is deliberately hard to do by accident:
--   * actor is an active owner with a live SSO session for this very provider
--     (so the operator is provably not locking themselves out),
--   * every active owner already has a verified identity for the provider and
--     there are at least two of them (no single-owner lockout),
--   * no SCIM user is bound to an Auth user that lacks the matching identity,
--   * a reason and a change reference are recorded.
create or replace function public.oidc_set_enforcement(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_session_id uuid,
  p_provider_id uuid,
  p_reason text,
  p_change_ref text
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, auth, pg_temp
as $$
declare
  v_old uuid;
  v_provider public.oidc_providers%rowtype;
  v_owner_count integer;
  v_verified_owner_count integer;
begin
  if p_tenant_id is null or p_actor_user_id is null
     or length(coalesce(btrim(p_reason), '')) < 12 or length(p_reason) > 500
     or p_change_ref is null or p_change_ref !~ '^[A-Za-z0-9._:/#-]{3,64}$' then
    raise exception 'invalid_oidc_enforcement_request' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2607));
  if not exists (
    select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
     where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id and m.role = 'owner'
       and (m.expires_at is null or m.expires_at > now()) and t.status = 'active'
  ) then raise exception 'oidc_enforcement_forbidden' using errcode = '42501'; end if;
  select required_oidc_provider_id into v_old from public.tenant_identity_policies
   where tenant_id = p_tenant_id;

  if p_provider_id is null then
    update public.tenant_identity_policies
       set required_oidc_provider_id = null, updated_by = p_actor_user_id
     where tenant_id = p_tenant_id;
    insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
      values (p_actor_user_id, p_tenant_id, p_actor_user_id, 'identity.oidc.enforcement_disabled',
        jsonb_build_object('old_provider_id', v_old, 'reason', p_reason, 'change_ref', p_change_ref));
    return jsonb_build_object('tenant_id', p_tenant_id, 'required_oidc_provider_id', null);
  end if;

  select * into v_provider from public.oidc_providers
   where id = p_provider_id and tenant_id = p_tenant_id and enabled;
  if not found then raise exception 'oidc_provider_unavailable' using errcode = '22023'; end if;
  if exists (select 1 from public.tenant_identity_policies
              where tenant_id = p_tenant_id and required_saml_provider_id is not null) then
    raise exception 'oidc_saml_enforcement_active' using errcode = '23505';
  end if;
  if not exists (
    select 1 from public.oidc_sso_sessions s
     where s.session_id = p_session_id and s.user_id = p_actor_user_id
       and s.provider_id = p_provider_id and s.tenant_id = p_tenant_id
       and s.revoked_at is null and s.expires_at > now()
  ) then raise exception 'oidc_actor_session_required' using errcode = '42501'; end if;

  select count(*), count(i.auth_user_id) into v_owner_count, v_verified_owner_count
    from public.tenant_members m
    left join public.oidc_identities i
      on i.provider_id = p_provider_id and i.auth_user_id = m.user_id and i.tenant_id = p_tenant_id
   where m.tenant_id = p_tenant_id and m.role = 'owner'
     and (m.expires_at is null or m.expires_at > now());
  if v_verified_owner_count < 2 or v_verified_owner_count <> v_owner_count then
    raise exception 'oidc_verified_owners_required' using errcode = '42501';
  end if;
  if exists (
    select 1 from public.scim_users su
     where su.tenant_id = p_tenant_id and su.active and su.auth_user_id is not null
       and not exists (
         select 1 from public.oidc_identities i
          where i.provider_id = p_provider_id and i.auth_user_id = su.auth_user_id
            and i.subject = su.external_id
       )
  ) then raise exception 'oidc_existing_identity_conflict' using errcode = '23505'; end if;

  insert into public.tenant_identity_policies(tenant_id, required_oidc_provider_id, updated_by)
    values (p_tenant_id, p_provider_id, p_actor_user_id)
    on conflict (tenant_id) do update
      set required_oidc_provider_id = excluded.required_oidc_provider_id,
          updated_by = excluded.updated_by;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
    values (p_actor_user_id, p_tenant_id, p_actor_user_id, 'identity.oidc.enforcement_enabled',
      jsonb_build_object('old_provider_id', v_old, 'provider_id', p_provider_id,
        'reason', p_reason, 'change_ref', p_change_ref, 'verified_owners', v_verified_owner_count));
  return jsonb_build_object('tenant_id', p_tenant_id, 'required_oidc_provider_id', p_provider_id);
end;
$$;
revoke all on function public.oidc_set_enforcement(uuid, uuid, uuid, uuid, text, text)
  from public, anon, authenticated;
grant execute on function public.oidc_set_enforcement(uuid, uuid, uuid, uuid, text, text) to service_role;

-- Break-glass for an IdP outage, using the SAME single-use recovery codes that
-- the password break-glass flow issues (rotate_recovery_codes, owner + AAL2,
-- only while break_glass_enabled). Spending one suspends OIDC enforcement for
-- the tenant and records an audit event. It does not grant a session: the owner
-- then signs in with password (+ MFA when required) and repairs the IdP. Unlike
-- SAML, which has no bypass, OIDC enforcement therefore has a recoverable
-- lockout path whose power equals the recovery code's existing power over that owner.
create or replace function public.oidc_break_glass_suspend(
  p_email text,
  p_code_hash text,
  p_request_id text
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, auth, extensions, pg_temp
as $$
declare
  v_code public.identity_recovery_codes%rowtype;
  v_provider uuid;
begin
  if p_email is null or length(p_email) > 254
     or p_code_hash !~ '^[0-9a-f]{64}$'
     or p_request_id !~ '^[A-Za-z0-9._:-]{1,128}$' then
    return null;
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_code_hash, 2607));
  select c.* into v_code
    from public.identity_recovery_codes c
    join auth.users u on u.id = c.user_id
    join public.tenants t on t.id = c.tenant_id and t.status = 'active'
    join public.tenant_members m
      on m.tenant_id = c.tenant_id and m.user_id = c.user_id and m.role = 'owner'
     and (m.expires_at is null or m.expires_at > clock_timestamp())
    join public.tenant_identity_policies p
      on p.tenant_id = c.tenant_id and p.break_glass_enabled
     and p.required_oidc_provider_id is not null
   where c.code_hash = p_code_hash
     and c.used_at is null
     and c.expires_at > clock_timestamp()
     and lower(u.email) = lower(btrim(p_email))
   for update of c;
  if not found then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_code.tenant_id::text, 2607));
  select required_oidc_provider_id into v_provider
    from public.tenant_identity_policies where tenant_id = v_code.tenant_id for update;
  update public.identity_recovery_codes
     set used_at = clock_timestamp(),
         used_request_id = p_request_id,
         recovery_proof_challenge_hash = encode(digest('oidc_break_glass:' || v_code.id::text, 'sha256'), 'hex'),
         recovery_started_at = clock_timestamp(),
         recovery_request_id = p_request_id
   where id = v_code.id and used_at is null;
  if not found then return null; end if;
  update public.tenant_identity_policies
     set required_oidc_provider_id = null, updated_by = v_code.user_id
   where tenant_id = v_code.tenant_id;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
    values (null, v_code.tenant_id, v_code.user_id, 'identity.oidc.break_glass_enforcement_suspended',
      jsonb_build_object('recovery_code_id', v_code.id, 'request_id', p_request_id,
        'suspended_provider_id', v_provider));
  return jsonb_build_object('tenant_id', v_code.tenant_id, 'user_id', v_code.user_id);
end;
$$;
revoke all on function public.oidc_break_glass_suspend(text, text, text) from public, anon, authenticated;
grant execute on function public.oidc_break_glass_suspend(text, text, text) to service_role;

-- Housekeeping used by the Edge function: drop spent/expired request and ticket rows.
create or replace function public.oidc_prune_transient_rows() returns integer
language plpgsql security definer set search_path = pg_catalog, public, pg_temp as $$
declare v_count integer := 0; v_step integer;
begin
  delete from public.oidc_auth_requests where expires_at < now() - interval '1 hour';
  get diagnostics v_step = row_count; v_count := v_count + v_step;
  delete from public.oidc_login_tickets where expires_at < now() - interval '1 hour';
  get diagnostics v_step = row_count; v_count := v_count + v_step;
  delete from public.oidc_sso_sessions where expires_at < now() - interval '7 days';
  get diagnostics v_step = row_count; v_count := v_count + v_step;
  return v_count;
end;
$$;
revoke all on function public.oidc_prune_transient_rows() from public, anon, authenticated;
grant execute on function public.oidc_prune_transient_rows() to service_role;
