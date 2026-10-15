-- T19: owner-visible attribution of SCIM-granted tenant roles.
--
-- Authorization is unchanged: public.scim_reconcile_membership still derives
-- the one effective role from mapped groups joined on the exact immutable
-- Group.externalId, with the deterministic precedence admin > member > viewer.
-- Display names and Auth user/app metadata never participate.
--
-- This read lets a tenant owner see, per SCIM user, which mapped group(s)
-- back the live membership and which one decided the effective role. The
-- deciding group is the highest-privilege mapped group; ties between groups
-- mapped to the same role are broken by external ID in byte order ("C"
-- collation) so the answer is stable. The response is informational only:
-- it grants nothing and is never read back as an authorization input.
create or replace function public.scim_admin_list_role_grants(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_after_scim_user_id uuid default null,
  p_limit integer default 100
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_rows jsonb;
  v_has_more boolean;
  v_next uuid;
begin
  perform app.scim_assert_tenant_owner(p_tenant_id, p_actor_user_id);
  if p_limit is null or p_limit < 1 or p_limit > 100 then
    raise exception 'scim_admin_invalid_pagination' using errcode = '22023';
  end if;

  with candidates as (
    select su.id, su.user_name, su.active, su.auth_user_id
      from public.scim_users su
     where su.tenant_id = p_tenant_id
       and (p_after_scim_user_id is null or su.id > p_after_scim_user_id)
       and (
         exists (select 1 from public.scim_managed_memberships smm
                  where smm.tenant_id = su.tenant_id and smm.scim_user_id = su.id)
         or exists (select 1
                      from public.scim_group_memberships sgm
                      join public.scim_groups sg
                        on sg.tenant_id = sgm.tenant_id and sg.id = sgm.group_id
                      join public.scim_group_role_mappings m
                        on m.tenant_id = sg.tenant_id and m.external_group_id = sg.external_id
                     where sgm.tenant_id = su.tenant_id and sgm.user_id = su.id)
       )
     order by su.id
     limit p_limit + 1
  ), page as (
    select c.*, row_number() over (order by c.id) as n from candidates c
  ), detail as (
    select p.id, p.user_name, p.active, p.auth_user_id, p.n,
           live.role as effective_role,
           exists (select 1 from public.tenant_members tm
                    where tm.tenant_id = p_tenant_id and tm.user_id = p.auth_user_id) as has_membership,
           groups.items, groups.total
      from page p
      left join lateral (
        select tm.role
          from public.scim_managed_memberships smm
          join public.tenant_members tm
            on tm.tenant_id = smm.tenant_id and tm.user_id = smm.auth_user_id and tm.role = smm.role
         where smm.tenant_id = p_tenant_id and smm.scim_user_id = p.id
      ) live on true
      cross join lateral (
        select coalesce(jsonb_agg(jsonb_build_object(
                   'external_group_id', g.external_id,
                   'display_name', g.display_name,
                   'role', g.role) order by g.rank, g.external_id collate "C")
                 filter (where g.ord <= 50), '[]'::jsonb) as items,
               count(*)::integer as total
          from (
            select sg.external_id, sg.display_name, m.role,
                   case m.role when 'admin' then 1 when 'member' then 2 else 3 end as rank,
                   row_number() over (order by case m.role when 'admin' then 1 when 'member' then 2 else 3 end,
                                               sg.external_id collate "C") as ord
              from public.scim_group_memberships sgm
              join public.scim_groups sg
                on sg.tenant_id = sgm.tenant_id and sg.id = sgm.group_id
              join public.scim_group_role_mappings m
                on m.tenant_id = sg.tenant_id and m.external_group_id = sg.external_id
             where sgm.tenant_id = p_tenant_id and sgm.user_id = p.id
          ) g
      ) groups
     where p.n <= p_limit
  )
  select coalesce((select jsonb_agg(jsonb_build_object(
           'scim_user_id', d.id,
           'user_name', d.user_name,
           'active', d.active,
           'bound', d.auth_user_id is not null,
           'effective_role', d.effective_role,
           'status', case
             when d.effective_role is not null then 'granted'
             when not d.active then 'inactive'
             when d.auth_user_id is null then 'unbound'
             when d.has_membership then 'manual_conflict'
             else 'not_granted' end,
           'granted_by_external_group_id', case
             when d.effective_role is not null and d.items->0->>'role' = d.effective_role
               then d.items->0->>'external_group_id' end,
           'mapped_groups', d.items,
           'mapped_group_count', d.total
         ) order by d.id) from detail d), '[]'::jsonb),
         -- The look-ahead row (n = limit + 1) proves another page exists.
         exists (select 1 from page where page.n > p_limit)
    into v_rows, v_has_more;

  -- Keyset continuation: the last returned SCIM user id, only when more exist.
  if v_has_more then
    v_next := (v_rows->(p_limit - 1)->>'scim_user_id')::uuid;
  end if;

  return jsonb_build_object('grants', v_rows, 'next_after_scim_user_id', v_next);
end;
$$;

revoke all on function public.scim_admin_list_role_grants(uuid, uuid, uuid, integer) from public, anon, authenticated;
grant execute on function public.scim_admin_list_role_grants(uuid, uuid, uuid, integer) to service_role;
