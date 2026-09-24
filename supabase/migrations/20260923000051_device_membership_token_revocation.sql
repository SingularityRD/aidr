-- Serialize token issue/rotation with membership removal. The API-key guard
-- from migration 47 already holds the canonical member row; reuse it here.
create trigger enrollment_tokens_owner_membership
before insert or update of token_hash on public.enrollment_tokens
for each row execute function app.require_credential_member();

-- A removed member must not revive an old device approval or unspent token
-- by joining the same tenant again. Expire both in the removal transaction.
create function app.expire_member_enrollment()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
begin
  if tg_op = 'UPDATE'
     and old.tenant_id is not distinct from new.tenant_id
     and old.user_id is not distinct from new.user_id
     and old.role in ('owner', 'admin', 'member')
     and new.role in ('owner', 'admin', 'member')
     and (old.expires_at is null or old.expires_at > clock_timestamp())
     and (new.expires_at is null or new.expires_at > clock_timestamp()) then
    return new;
  end if;

  update public.enrollment_tokens
     set expires_at = least(expires_at, transaction_timestamp()),
         previous_hash = null, previous_hash_expires_at = null
   where tenant_id = old.tenant_id and user_id = old.user_id
     and consumed_at is null and expires_at > clock_timestamp();
  update public.device_sessions
     set expires_at = least(expires_at, transaction_timestamp()), status = 'revoked'
   where tenant_id = old.tenant_id and user_id = old.user_id
     and authorized_at is not null and expires_at > clock_timestamp();

  if tg_op = 'DELETE' then return old; end if;
  return new;
end;
$$;
revoke all on function app.expire_member_enrollment()
  from public, anon, authenticated, service_role;
create trigger tenant_members_expire_enrollment
after update or delete on public.tenant_members
for each row execute function app.expire_member_enrollment();
