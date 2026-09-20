-- Compile exact submitted YAML at the Edge before entering this transaction.
-- Keep legacy rows intact: the newest (updated_at, id) row is the draft head.
-- Browser writers must use the authenticated/MFA-checked Edge action, not bypass
-- compilation with direct table writes. Read/delete policies are unchanged.
begin;

alter table public.team_policies
  add column version bigint not null default 1 check (version between 1 and 9007199254740991),
  add column source_sha256 text;
-- Metadata backfill must not reorder legacy drafts by touching updated_at.
-- The ALTER TABLE lock and transaction keep normal writers out until restored.
alter table public.team_policies disable trigger team_policies_touch_updated_at;
update public.team_policies
  set source_sha256 = encode(sha256(convert_to(content, 'UTF8')), 'hex');
alter table public.team_policies enable trigger team_policies_touch_updated_at;
alter table public.team_policies
  alter column source_sha256 set not null,
  add constraint team_policies_source_sha256_format check (source_sha256 ~ '^[0-9a-f]{64}$');

-- Maintain the revision and exact-source fingerprint even for trusted service
-- maintenance. The caller can never supply its own version or fingerprint.
create function public.version_policy_document()
returns trigger language plpgsql set search_path = pg_catalog as $$
begin
  new.version := case when tg_op = 'INSERT' then 1 else old.version + 1 end;
  new.source_sha256 := encode(sha256(convert_to(new.content, 'UTF8')), 'hex');
  return new;
end;
$$;
revoke all on function public.version_policy_document() from public, anon, authenticated;
create trigger team_policies_version_document
  before insert or update on public.team_policies
  for each row execute function public.version_policy_document();

-- Legacy GRANT ALL also included non-RLS-safe TRUNCATE and schema privileges.
-- Browser operators need only their existing RLS-checked reads/deletes here.
revoke insert, update, truncate, references, trigger on public.team_policies from public, anon, authenticated;

create function public.save_policy_document_draft(
  p_tenant_id uuid,
  p_user_id uuid,
  p_content text,
  p_source_sha256 text,
  p_expected_id uuid,
  p_expected_version bigint,
  p_expected_source_sha256 text
)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public, pg_temp as $$
declare
  v_row public.team_policies%rowtype;
begin
  -- One lock covers both an absent head and an existing head, so concurrent
  -- first saves cannot create two drafts and concurrent updates cannot win twice.
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 912));
  perform 1 from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
    where m.user_id = p_user_id and m.tenant_id = p_tenant_id
      and m.role in ('owner', 'admin', 'member')
      and (m.expires_at is null or m.expires_at > clock_timestamp()) and t.status = 'active'
    for share of m, t;
  if not found then raise exception 'policy_forbidden' using errcode = '42501'; end if;

  if p_content is null or octet_length(p_content) not between 1 and 65536
     or p_source_sha256 is null
     or p_source_sha256 is distinct from encode(sha256(convert_to(p_content, 'UTF8')), 'hex') then
    raise exception 'invalid_policy_document_source' using errcode = '22023';
  end if;
  if (p_expected_id is null and (p_expected_version is not null or p_expected_source_sha256 is not null))
     or (p_expected_id is not null and (p_expected_version is null or p_expected_version < 1
       or p_expected_version >= 9007199254740991 or p_expected_source_sha256 is null
       or p_expected_source_sha256 !~ '^[0-9a-f]{64}$')) then
    raise exception 'invalid_document_precondition' using errcode = '22023';
  end if;

  select * into v_row from public.team_policies
    where team_id = p_tenant_id and tenant_id = p_tenant_id
    order by updated_at desc, id desc limit 1 for update;
  if not found then
    if p_expected_id is not null then
      raise exception 'policy_document_conflict' using errcode = 'PT409';
    end if;
    insert into public.team_policies(team_id, tenant_id, content, updated_by)
      values (p_tenant_id, p_tenant_id, p_content, p_user_id) returning * into v_row;
  else
    if v_row.id is distinct from p_expected_id
       or v_row.version is distinct from p_expected_version
       or v_row.source_sha256 is distinct from p_expected_source_sha256 then
      raise exception 'policy_document_conflict' using errcode = 'PT409';
    end if;
    update public.team_policies set content = p_content, updated_by = p_user_id
      where id = v_row.id and team_id = p_tenant_id and tenant_id = p_tenant_id
        and version = p_expected_version and source_sha256 = p_expected_source_sha256
      returning * into v_row;
    if not found then raise exception 'policy_document_conflict' using errcode = 'PT409'; end if;
  end if;

  return jsonb_build_object('id', v_row.id, 'version', v_row.version,
    'source_sha256', v_row.source_sha256, 'updated_at', v_row.updated_at);
end;
$$;
revoke all on function public.save_policy_document_draft(uuid,uuid,text,text,uuid,bigint,text) from public, anon, authenticated;
grant execute on function public.save_policy_document_draft(uuid,uuid,text,text,uuid,bigint,text) to service_role;

commit;
