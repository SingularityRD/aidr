-- The pre-exchange rate-limit lookup must recognize the same bounded retired
-- hash as the atomic exchange; otherwise rotated tokens fail before exchange.
create or replace function public.resolve_enrollment_token(p_token_hash text)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare v_token public.enrollment_tokens%rowtype;
begin
  if p_token_hash is null or p_token_hash !~ '^[a-f0-9]{64}$' then return null; end if;
  select t.* into v_token from public.enrollment_tokens t
   where t.token_hash = p_token_hash
      or (t.previous_hash = p_token_hash
          and t.previous_hash_expires_at is not null
          and t.previous_hash_expires_at > now())
   order by (t.token_hash = p_token_hash) desc
   limit 1;
  if not found or v_token.consumed_at is not null or v_token.expires_at <= now() then
    return null;
  end if;
  if not exists (
    select 1 from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = v_token.tenant_id and m.user_id = v_token.user_id
     and (m.expires_at is null or m.expires_at > now()) and t.status = 'active'
  ) then return null; end if;
  return jsonb_build_object('tenant_id', v_token.tenant_id, 'user_id', v_token.user_id);
end;
$$;
revoke all on function public.resolve_enrollment_token(text) from public, anon, authenticated;
grant execute on function public.resolve_enrollment_token(text) to service_role;
