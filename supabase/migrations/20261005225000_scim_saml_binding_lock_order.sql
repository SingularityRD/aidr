-- Shared SCIM binding takes tenant lock 2607 before the user row. The SAML
-- entry point must do the same before its own FOR UPDATE, or simultaneous
-- SAML/direct binds can each wait for a lock already held by the other.
-- Preserve the existing provider-qualified checks, authorization and ACLs.
do $migration$
declare
  v_definition text;
  v_old text := 'if v_tenant_id is null then return null; end if;';
begin
  select pg_get_functiondef('public.scim_bind_saml_identity(uuid,uuid)'::regprocedure) into v_definition;
  if position('hashtextextended(v_tenant_id::text, 2607)' in v_definition) > 0 then return; end if;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 then
    raise exception 'unexpected_scim_saml_binding_lock_definition';
  end if;
  execute replace(v_definition, v_old, v_old || E'\n  '
    || 'perform pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 2607));');
end;
$migration$;
