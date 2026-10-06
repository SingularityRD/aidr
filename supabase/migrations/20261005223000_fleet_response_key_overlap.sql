-- Renewed endpoint credentials keep the same bounded overlap on command poll /
-- acknowledgement as policy and telemetry. Recheck the presented hash inside
-- the existing locked RPC; never replace it with a current hash at the Edge.
do $migration$
declare
  v_signature text;
  v_definition text;
  v_old text := 'k.key_hash=p_key_hash';
  v_new text := '(k.key_hash=p_key_hash or (k.previous_hash=p_key_hash and k.previous_hash_expires_at>clock_timestamp()))';
begin
  foreach v_signature in array array[
    'public.poll_fleet_response_command(text,uuid,uuid)',
    'public.record_fleet_response_command(text,uuid,uuid,uuid,text,text,text)'
  ] loop
    select pg_get_functiondef(v_signature::regprocedure) into v_definition;
    if position(v_new in v_definition) > 0 then continue; end if;
    if cardinality(string_to_array(v_definition, v_old)) <> 2 then
      raise exception 'unexpected_fleet_response_auth_definition: %', v_signature;
    end if;
    execute replace(v_definition, v_old, v_new);
  end loop;
end
$migration$;
