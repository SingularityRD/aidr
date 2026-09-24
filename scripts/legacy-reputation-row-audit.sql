-- Read-only pre-upgrade/field audit. Run privately with psql -X -v ON_ERROR_STOP=1.
-- Every team row is listed because the old OR policy did not record which
-- principal inserted it. A current membership is context, not proof of origin.
-- Do not auto-delete these rows: a departed member can have legitimate rows.
select kind, row_id, tenant_id, user_id, created_at,
  case
    when tenant_status is null then 'missing_tenant'
    when tenant_status <> 'active' then 'inactive_tenant'
    when current_member then 'current_member_origin_unproven'
    else 'no_current_membership_origin_unproven'
  end as review_reason
from (
  select 'url_reputation' as kind, r.id as row_id, r.tenant_id, r.user_id,
    r.created_at, t.status as tenant_status,
    exists (
      select 1 from public.tenant_members m
      where m.tenant_id = r.tenant_id and m.user_id = r.user_id
        and (m.expires_at is null or m.expires_at > now())
    ) as current_member
  from public.url_reputation r
  left join public.tenants t on t.id = r.tenant_id
  where r.tenant_id <> r.user_id
  union all
  select 'file_reputation', r.id, r.tenant_id, r.user_id,
    r.created_at, t.status,
    exists (
      select 1 from public.tenant_members m
      where m.tenant_id = r.tenant_id and m.user_id = r.user_id
        and (m.expires_at is null or m.expires_at > now())
    )
  from public.file_reputation r
  left join public.tenants t on t.id = r.tenant_id
  where r.tenant_id <> r.user_id
) candidates
order by tenant_id, kind, row_id;
