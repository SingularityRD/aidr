-- Executive report and team rollup (E6), on top of the scheduled governance
-- summary (20260927000060 / 20260927000061).
--
-- * tenant_governance_settings.digest_language ('en' | 'tr') picks the language
--   of the scheduled summary e-mail and its attachment; digest_attachment
--   attaches the printable executive report (self-contained HTML) to it.
--   Changed only through set_governance_report_options (service role, called by
--   the `reports` Edge Function after session, identity barrier, owner/admin and
--   AAL2 checks); every change is audited.
-- * executive_report_teams lists the workspaces whose figures a user may see in
--   the team rollup: active workspaces where the user is an active owner or
--   admin. The Edge Function additionally applies each workspace's identity
--   barrier to the caller's session and reads the counts-only summary
--   (governance_digest_summary + incident_triage_summary) per workspace.
-- * governance_report_context gives the governance-digest Edge Function the
--   language, the attachment choice and the incident triage counts.
--
-- Additive: two defaulted columns, three new functions.

alter table public.tenant_governance_settings
  add column if not exists digest_language text not null default 'en'
    check (digest_language in ('en', 'tr')),
  add column if not exists digest_attachment boolean not null default true;

comment on column public.tenant_governance_settings.digest_language is
  'Language of the scheduled governance summary and its executive report attachment (en, tr).';
comment on column public.tenant_governance_settings.digest_attachment is
  'Attach the printable executive report (HTML) to the scheduled governance summary.';

grant select (digest_language, digest_attachment) on public.tenant_governance_settings to authenticated;

create or replace function public.set_governance_report_options(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_language text,
  p_attachment boolean
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_role text;
  v_row public.tenant_governance_settings;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_attachment is null
     or p_language is null or p_language not in ('en', 'tr') then
    raise exception 'invalid_report_options' using errcode = '22023';
  end if;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or v_role not in ('owner', 'admin') then
    raise exception 'report_options_forbidden' using errcode = '42501';
  end if;

  insert into public.tenant_governance_settings as s (tenant_id, digest_language, digest_attachment, updated_by, updated_at)
  values (p_tenant_id, p_language, p_attachment, p_actor_user_id, now())
  on conflict (tenant_id) do update set
    digest_language = excluded.digest_language,
    digest_attachment = excluded.digest_attachment,
    updated_by = excluded.updated_by,
    updated_at = excluded.updated_at
  returning * into v_row;

  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'governance_report_options.updated',
    jsonb_build_object('digest_language', v_row.digest_language, 'digest_attachment', v_row.digest_attachment));

  return jsonb_build_object(
    'digest_language', v_row.digest_language,
    'digest_attachment', v_row.digest_attachment,
    'digest_enabled', v_row.digest_enabled,
    'digest_cadence', v_row.digest_cadence,
    'digest_next_at', v_row.digest_next_at,
    'updated_at', v_row.updated_at);
end;
$$;
revoke all on function public.set_governance_report_options(uuid, uuid, text, boolean) from public, anon, authenticated;
grant execute on function public.set_governance_report_options(uuid, uuid, text, boolean) to service_role;

-- Workspaces in the caller's team rollup, by name; at most 50.
create or replace function public.executive_report_teams(p_actor_user_id uuid)
returns jsonb
language sql
stable
security definer
set search_path = pg_catalog, public, pg_temp
as $$
  select coalesce(jsonb_agg(jsonb_build_object('tenant_id', x.id, 'name', x.name, 'role', x.role)
    order by x.name, x.id), '[]'::jsonb)
  from (
    select t.id, t.name, m.role
      from public.tenant_members m
      join public.tenants t on t.id = m.tenant_id
     where m.user_id = p_actor_user_id
       and m.role in ('owner', 'admin')
       and (m.expires_at is null or m.expires_at > now())
       and t.status = 'active'
     order by t.name, t.id
     limit 50
  ) x
$$;
revoke all on function public.executive_report_teams(uuid) from public, anon, authenticated;
grant execute on function public.executive_report_teams(uuid) to service_role;

-- What the governance-digest Edge Function needs besides the summary: the
-- workspace's language and attachment choice and the incident triage counts
-- for the same period. Service role only; counts and enums, no identities.
create or replace function public.governance_report_context(p_tenant_id uuid, p_from timestamptz, p_to timestamptz)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_language text;
  v_attachment boolean;
begin
  if p_tenant_id is null or p_from is null or p_to is null or p_to <= p_from then
    raise exception 'invalid_report_period' using errcode = '22023';
  end if;
  if not exists (select 1 from public.tenants t where t.id = p_tenant_id and t.status = 'active') then
    raise exception 'governance_tenant_not_active' using errcode = '42501';
  end if;
  select s.digest_language, s.digest_attachment into v_language, v_attachment
    from public.tenant_governance_settings s where s.tenant_id = p_tenant_id;
  return jsonb_build_object(
    'language', coalesce(v_language, 'en'),
    'attachment', coalesce(v_attachment, true),
    'triage', public.incident_triage_summary(p_tenant_id, p_from, p_to));
end;
$$;
revoke all on function public.governance_report_context(uuid, timestamptz, timestamptz) from public, anon, authenticated;
grant execute on function public.governance_report_context(uuid, timestamptz, timestamptz) to service_role;
