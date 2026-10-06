// GoTrue creates identities during a complete deployment; the isolated
// PostgreSQL image needs the fields read by the SAML identity/owner guards.
export const authIdentityFixtureSql = `
create table auth.identities (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  provider text not null,
  provider_id text not null,
  identity_data jsonb not null,
  unique (provider_id, provider)
);
grant select, insert, update, delete on auth.identities to postgres;
`;
