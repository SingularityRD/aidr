-- Publish only the exact YAML revision compiled by the Edge handler.
create function public.publish_runtime_policy_document(
  p_tenant_id uuid,
  p_user_id uuid,
  p_expected_version bigint,
  p_policy jsonb,
  p_expected_document_id uuid,
  p_expected_document_version bigint,
  p_expected_source_sha256 text
)
returns public.tenant_runtime_policies
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  document public.team_policies%rowtype;
begin
  if p_expected_document_id is null
     or p_expected_document_version is null
     or p_expected_document_version not between 1 and 9007199254740991
     or p_expected_source_sha256 is null
     or p_expected_source_sha256 !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid_document_precondition' using errcode = '22023';
  end if;

  -- Use the same lock as draft saves, then hold the selected head through the
  -- existing publication transaction so a concurrent edit cannot slip in.
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 912));
  select * into document from public.team_policies
   where team_id = p_tenant_id and tenant_id = p_tenant_id
   order by updated_at desc, id desc
   limit 1
   for update;
  if not found
     or document.id is distinct from p_expected_document_id
     or document.version is distinct from p_expected_document_version
     or document.source_sha256 is distinct from p_expected_source_sha256 then
    raise exception 'policy_document_conflict' using errcode = 'PT409';
  end if;

  return public.publish_runtime_policy(p_tenant_id, p_user_id, p_expected_version, p_policy);
end;
$$;
revoke all on function public.publish_runtime_policy_document(uuid,uuid,bigint,jsonb,uuid,bigint,text) from public, anon, authenticated;
grant execute on function public.publish_runtime_policy_document(uuid,uuid,bigint,jsonb,uuid,bigint,text) to service_role;
