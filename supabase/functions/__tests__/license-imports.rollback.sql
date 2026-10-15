-- Run against a disposable, fully migrated Supabase database (after
-- 20261014120200_signed_license_imports.sql). Everything is rolled back.
-- Signatures are verified by the Edge functions, not here; the documents below
-- only need the aidr-license-v1 shape.
begin;
do $setup$
declare
  v_owner uuid := gen_random_uuid();
  v_admin uuid := gen_random_uuid();
  v_member uuid := gen_random_uuid();
  v_operator uuid := gen_random_uuid();
  v_other uuid := gen_random_uuid();
begin
  perform set_config('aidr.fixture.owner', v_owner::text, true);
  perform set_config('aidr.fixture.admin', v_admin::text, true);
  perform set_config('aidr.fixture.member', v_member::text, true);
  perform set_config('aidr.fixture.operator', v_operator::text, true);
  perform set_config('aidr.fixture.other', v_other::text, true);
  insert into auth.users(id, email, email_confirmed_at) values
    (v_owner, 'lic-owner-' || v_owner || '@test.invalid', clock_timestamp()),
    (v_admin, 'lic-admin-' || v_admin || '@test.invalid', clock_timestamp()),
    (v_member, 'lic-member-' || v_member || '@test.invalid', clock_timestamp()),
    (v_operator, 'lic-operator-' || v_operator || '@test.invalid', clock_timestamp()),
    (v_other, 'lic-other-' || v_other || '@test.invalid', clock_timestamp());
  insert into public.tenant_members(tenant_id, user_id, role) values
    (v_owner, v_admin, 'admin'), (v_owner, v_member, 'member');
  update app.tenant_admission_config set mode = 'onprem', configured_at = clock_timestamp() where singleton;
  insert into public.platform_operators(user_id, change_reference) values (v_operator, 'CHG-LICENSE-IMPORT');
  insert into public.admission_operators(tenant_id, user_id) values (v_owner, v_operator), (v_other, v_operator);
end;
$setup$;

create function pg_temp.license_doc(p_license_id text, p_seats integer, p_expires text, p_sig text default 'AAAA')
returns jsonb language sql as $$
  select jsonb_build_object('format', 'aidr-license-v1', 'key_id', 'aidr-license-test-1',
    'sig', p_sig,
    'payload', jsonb_build_object('license_id', p_license_id, 'customer', 'Example Customer AG',
      'customer_id', 'example-ag', 'plan_id', 'enterprise', 'seats', p_seats,
      'features', jsonb_build_array('managed_policy'), 'deployment', 'onprem',
      'issued_at', '2026-01-01T00:00:00Z', 'not_before', '2026-01-01T00:00:00Z',
      'expires_at', p_expires, 'grace_days', 14))
$$;

do $checks$
declare
  v_owner uuid := current_setting('aidr.fixture.owner')::uuid;
  v_admin uuid := current_setting('aidr.fixture.admin')::uuid;
  v_member uuid := current_setting('aidr.fixture.member')::uuid;
  v_operator uuid := current_setting('aidr.fixture.operator')::uuid;
  v_other uuid := current_setting('aidr.fixture.other')::uuid;
  v_doc jsonb := pg_temp.license_doc('LIC-IMPORT-1', 25, '2030-01-01T00:00:00Z');
  v_doc2 jsonb := pg_temp.license_doc('LIC-IMPORT-2', 40, '2031-01-01T00:00:00Z');
  v_sha text := repeat('a', 64);
  v_sha2 text := repeat('b', 64);
  v_result jsonb;
  v_import uuid;
  v_admission public.tenant_admissions%rowtype;
begin
  -- Only an owner/admin of the tenant may stage a license.
  begin
    perform public.submit_license_import(v_member, v_owner, v_doc, v_sha);
    raise exception 'member staged a license';
  exception when sqlstate '42501' then null;
  end;
  begin
    perform public.submit_license_import(v_operator, v_owner, v_doc, v_sha);
    raise exception 'non-member staged a license';
  exception when sqlstate '42501' then null;
  end;
  begin
    perform public.submit_license_import(v_admin, v_owner, v_doc - 'payload', v_sha);
    raise exception 'malformed document staged';
  exception when sqlstate '22023' then null;
  end;
  v_result := public.submit_license_import(v_admin, v_owner, v_doc, v_sha);
  if v_result->>'status' <> 'pending' or (v_result->'import'->>'seats')::int <> 25
     or v_result->'import'->>'grace_ends_at' is null then
    raise exception 'submit result wrong: %', v_result;
  end if;
  v_import := (v_result->'import'->>'id')::uuid;
  -- Submitting never changes admission.
  if exists (select 1 from public.tenant_admissions where tenant_id = v_owner) then
    raise exception 'submission changed admission';
  end if;
  -- Re-submitting the same document is idempotent.
  if (public.submit_license_import(v_owner, v_owner, v_doc, v_sha)->'import'->>'id')::uuid <> v_import then
    raise exception 'duplicate submission created a new import';
  end if;
  if not exists (select 1 from public.admin_audit_logs where tenant_id = v_owner
                  and action = 'license.import_submitted' and actor_user_id = v_admin) then
    raise exception 'submission not audited';
  end if;

  -- Applying requires a platform operator; a tenant admin cannot apply.
  begin
    perform public.operator_apply_license(v_admin, v_owner, v_import, v_doc, v_sha, null);
    raise exception 'tenant admin applied a license';
  exception when sqlstate '42501' then null;
  end;
  -- The stored document and digest must match what operator-admin re-verified.
  begin
    perform public.operator_apply_license(v_operator, v_owner, v_import, v_doc2, v_sha, null);
    raise exception 'mismatched document applied';
  exception when sqlstate '22023' then null;
  end;
  begin
    perform public.operator_apply_license(v_operator, v_owner, v_import, v_doc, v_sha2, null);
    raise exception 'mismatched digest applied';
  exception when sqlstate '22023' then null;
  end;
  -- Expired (past grace) and not-yet-valid terms are refused.
  begin
    perform public.operator_apply_license(v_operator, v_owner, null,
      pg_temp.license_doc('LIC-OLD', 5, '2026-02-01T00:00:00Z'), repeat('c', 64), null);
    raise exception 'expired license applied';
  exception when sqlstate '22023' then null;
  end;

  v_result := public.operator_apply_license(v_operator, v_owner, v_import, v_doc, v_sha, null);
  if v_result->>'status' <> 'granted' or v_result->'import'->>'status' <> 'applied' then
    raise exception 'apply result wrong: %', v_result;
  end if;
  select * into v_admission from public.tenant_admissions where tenant_id = v_owner;
  if v_admission.seats <> 25 or v_admission.kind <> 'licensed'
     or v_admission.grant_reference <> 'LIC-IMPORT-1'
     or v_admission.expires_at <> '2030-01-15T00:00:00Z'::timestamptz
     or v_admission.plan_id <> 'enterprise' then
    raise exception 'signed terms not applied: %', row_to_json(v_admission);
  end if;
  if (select included_agents from public.entitlements where tenant_id = v_owner) <> 25 then
    raise exception 'entitlement seats not applied';
  end if;
  if not exists (select 1 from public.admin_audit_logs where tenant_id = v_owner
                  and action = 'license.applied' and actor_user_id = v_operator
                  and detail->>'canonical_sha256' = v_sha) then
    raise exception 'apply not audited';
  end if;
  -- The same import cannot be applied twice.
  begin
    perform public.operator_apply_license(v_operator, v_owner, v_import, v_doc, v_sha, null);
    raise exception 'applied import applied again';
  exception when sqlstate '55000' then null;
  end;
  if not exists (select 1 from public.license_imports where id = v_import and status = 'applied') then
    raise exception 'import not marked applied';
  end if;
end;
$checks$;

do $renewal$
declare
  v_owner uuid := current_setting('aidr.fixture.owner')::uuid;
  v_operator uuid := current_setting('aidr.fixture.operator')::uuid;
  v_other uuid := current_setting('aidr.fixture.other')::uuid;
  v_doc2 jsonb := pg_temp.license_doc('LIC-IMPORT-2', 40, '2031-01-01T00:00:00Z');
  v_result jsonb;
  v_message text;
begin
  -- Renewal by direct operator upload supersedes the applied license.
  v_result := public.operator_apply_license(v_operator, v_owner, null, v_doc2, repeat('d', 64), null);
  if v_result->'import'->>'source' <> 'operator_upload' then raise exception 'direct upload wrong: %', v_result; end if;
  if (select count(*) from public.license_imports where tenant_id = v_owner and status = 'applied') <> 1
     or (select status from public.license_imports where license_id = 'LIC-IMPORT-1') <> 'superseded' then
    raise exception 'renewal did not supersede the previous license';
  end if;
  if (select seats from public.tenant_admissions where tenant_id = v_owner) <> 40 then
    raise exception 'renewal seats not applied';
  end if;
  -- One signed license cannot admit a second tenant.
  begin
    perform public.operator_apply_license(v_operator, v_other, null, v_doc2, repeat('d', 64), null);
    raise exception 'license reused for another tenant';
  exception when sqlstate '42501' then
    get stacked diagnostics v_message = message_text;
    if v_message <> 'license_bound_to_other_tenant' then raise exception 'wrong refusal: %', v_message; end if;
  end;
  -- Separation of duty: an operator who joins the tenant can no longer apply.
  insert into public.tenant_members(tenant_id, user_id, role) values (v_owner, v_operator, 'member');
  begin
    perform public.operator_apply_license(v_operator, v_owner, null,
      pg_temp.license_doc('LIC-IMPORT-3', 50, '2031-06-01T00:00:00Z'), repeat('e', 64), null);
    raise exception 'tenant member applied a license as operator';
  exception when sqlstate '42501' then
    get stacked diagnostics v_message = message_text;
    if v_message <> 'admission_operator_forbidden' then raise exception 'wrong refusal: %', v_message; end if;
  end;
  delete from public.tenant_members where tenant_id = v_owner and user_id = v_operator;

  -- Usage facts and the monitoring summary.
  v_result := public.usage_report_facts(v_owner);
  if (v_result->>'seats_licensed')::int <> 40 or v_result->'license'->>'license_id' <> 'LIC-IMPORT-2'
     or (v_result->>'devices_enrolled')::int <> 0 then
    raise exception 'usage facts wrong: %', v_result;
  end if;
  v_result := public.license_expiry_summary();
  if (v_result->>'licensed_tenants')::int < 1 or v_result->>'grace_ends_at' is null then
    raise exception 'expiry summary wrong: %', v_result;
  end if;
  v_result := public.operator_list_license_imports(v_operator, 50);
  if jsonb_typeof(v_result->'imports') <> 'array' then raise exception 'operator list wrong'; end if;
end;
$renewal$;

-- Browser: members read status; only owners/admins see the pending import and
-- the usage report; nobody reads the table directly.
select public.submit_license_import(current_setting('aidr.fixture.admin')::uuid,
  current_setting('aidr.fixture.owner')::uuid,
  pg_temp.license_doc('LIC-IMPORT-4', 60, '2032-01-01T00:00:00Z'), repeat('f', 64)) is not null;
select set_config('request.jwt.claim.role', 'authenticated', true);
select set_config('request.jwt.claims', jsonb_build_object(
  'sub', current_setting('aidr.fixture.member'), 'role', 'authenticated',
  'aal', 'aal2', 'iat', extract(epoch from clock_timestamp())::bigint)::text, true);
select set_config('request.jwt.claim.sub', current_setting('aidr.fixture.member'), true);
set local role authenticated;
do $member$
declare
  v_owner uuid := current_setting('aidr.fixture.owner')::uuid;
  v_status jsonb;
begin
  v_status := public.tenant_license_status(v_owner);
  if v_status->'license'->>'license_id' <> 'LIC-IMPORT-2' or (v_status->>'can_manage')::boolean
     or v_status->'pending' <> 'null'::jsonb then
    raise exception 'member license status wrong: %', v_status;
  end if;
  begin
    perform public.tenant_usage_report(v_owner);
    raise exception 'member read the usage report';
  exception when sqlstate '42501' then null;
  end;
  begin
    perform 1 from public.license_imports limit 1;
    raise exception 'browser read license_imports';
  exception when sqlstate '42501' then null;
  end;
  begin
    perform public.tenant_license_status(current_setting('aidr.fixture.other')::uuid);
    raise exception 'foreign tenant status readable';
  exception when sqlstate '42501' then null;
  end;
end;
$member$;
reset role;
select set_config('request.jwt.claims', jsonb_build_object(
  'sub', current_setting('aidr.fixture.admin'), 'role', 'authenticated',
  'aal', 'aal2', 'iat', extract(epoch from clock_timestamp())::bigint)::text, true);
select set_config('request.jwt.claim.sub', current_setting('aidr.fixture.admin'), true);
set local role authenticated;
do $admin$
declare
  v_owner uuid := current_setting('aidr.fixture.owner')::uuid;
  v_status jsonb;
  v_report jsonb;
begin
  v_status := public.tenant_license_status(v_owner);
  if not (v_status->>'can_manage')::boolean or v_status->'pending'->>'license_id' <> 'LIC-IMPORT-4' then
    raise exception 'admin license status wrong: %', v_status;
  end if;
  v_report := public.tenant_usage_report(v_owner);
  if (v_report->>'seats_licensed')::int <> 40 then raise exception 'admin usage report wrong: %', v_report; end if;
  begin
    perform public.submit_license_import(auth.uid(), v_owner, pg_temp.license_doc('X', 1, '2032-01-01T00:00:00Z'), repeat('0', 64));
    raise exception 'browser called submit_license_import directly';
  exception when sqlstate '42501' then null;
  end;
end;
$admin$;
reset role;
do $$ begin raise notice 'LICENSE_IMPORTS_OK'; end; $$;
rollback;
