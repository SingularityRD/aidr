# On-prem single sign-on: Keycloak, ADFS, Active Directory / LDAP

Türkçe: [onprem-sso.tr.md](onprem-sso.tr.md)

This runbook connects a self-hosted AIDR control plane (Docker Compose from
`scripts/deployment-prepare.mjs`, or the Helm chart) to an identity provider on
the customer's own network. It covers:

- tenant **OIDC** sign-in against Keycloak, ADFS or any standards-compliant
  OpenID Connect provider, including one whose TLS certificate is issued by an
  internal CA and whose address is private;
- **just-in-time (JIT) provisioning**: AIDR creates the tenant membership at the
  first sign-in and keeps the role in step with the user's IdP groups, so no
  SCIM client is required;
- **Active Directory / LDAP** through Keycloak user federation (AIDR has no
  LDAP client of its own, by design);
- **SAML** in the self-hosted GoTrue (`auth` service).

The protocol and security design of OIDC sign-in is in
[oidc-sso-admin.md](../production-readiness/oidc-sso-admin.md); every security
property listed there (PKCE, single-use state, signature and claim checks,
DNS-verified domains, provider-qualified identities, enforcement and
break-glass) applies unchanged to the providers below.

## Choose a path

| You have | Use | Users and roles come from |
| --- | --- | --- |
| AD / LDAP, no IdP yet | Keycloak with LDAP user federation, then OIDC + JIT | AD groups via Keycloak's group mapper |
| Keycloak | OIDC + JIT | Keycloak groups or realm roles |
| ADFS 2016 or newer | OIDC + JIT (preferred) | AD groups through ADFS claim rules |
| An IdP with a SCIM client (Entra ID, Okta) | OIDC or SAML + SCIM | SCIM groups ([scim-directory-admin.md](../production-readiness/scim-directory-admin.md)) |
| SAML only | GoTrue SAML + SCIM | SCIM groups; SAML sign-in alone grants no membership |

JIT is OIDC only. A SAML sign-in still needs SCIM to create the membership.

## 1. Prepare the control plane

All three settings are opt-in. Without them the stack is prepared exactly as
before and OIDC fetches stay restricted to public HTTPS endpoints on port 443.

### Docker Compose (`deployment-prepare`)

```sh
node scripts/deployment-prepare.mjs --mode self-hosted --output /srv/aidr ... \
  --idp-ca-file /secure-delivery/corp-root-ca.pem \
  --oidc-internal-idp-hosts sso.corp.example:8443 \
  [--with-saml]
```

- `--idp-ca-file` takes a PEM file with only the CA certificates (root and, if
  needed, issuing CA) that signed the IdP's TLS certificate. Preparation refuses
  private keys, other PEM blocks and expired certificates, writes the bundle to
  `functions-trust/idp-ca.pem` (mode 0644), mounts it read-only into the
  `functions` container and sets `DENO_TLS_CA_STORE=mozilla,system` with
  `SSL_CERT_FILE=/etc/aidr/idp-ca.pem`. The pinned Edge runtime then trusts the
  public Mozilla roots **plus** your CA; nothing is replaced. The bundle's
  SHA-256 and subjects are recorded in `deployment.json` (`identity.idp_ca`).
- `--oidc-internal-idp-hosts` is a comma-separated list of exact,
  fully qualified `host[:port]` names (at most 16, no IP literals, no
  wildcards). It is written to `AIDR_OIDC_INTERNAL_IDP_HOSTS` in
  `.env.functions`. Only these hosts may resolve to private addresses
  (10/8, 172.16/12, 192.168/16, 100.64/10, IPv6 ULA) and only on the listed
  port (443 when none is given). Loopback, link-local and metadata addresses,
  plain HTTP and redirects stay refused for every host. A malformed value makes
  the `oidc-sso` function answer `server_misconfigured` to every request, so a
  typo is visible immediately instead of silently changing the policy.
- `--with-saml` turns on SAML in GoTrue and generates its RSA-2048 signing key
  **on this host** (`GOTRUE_SAML_PRIVATE_KEY` in `.env`, mode 0600). See
  [section 6](#6-saml-in-the-self-hosted-gotrue).

To show the work-email SSO form on the sign-in page, set `AIDR_OIDC_SSO=true` in
`/srv/aidr/.env` and restart the dashboard (`docker compose ... up -d dashboard`).

The functions container must reach the IdP and resolve its name. Compose uses
the host's DNS resolvers; check from the host with
`curl --cacert corp-root-ca.pem https://sso.corp.example:8443/realms/corp/.well-known/openid-configuration`.

Changing these settings later: edit `functions-trust/idp-ca.pem` or
`AIDR_OIDC_INTERNAL_IDP_HOSTS` in `.env.functions`, then
`docker compose --project-directory /srv/aidr -f /srv/aidr/compose.yml up -d functions`.

### Kubernetes (Helm)

```yaml
functions:
  identityProvider:
    caBundle:
      existingConfigMap: corp-idp-ca   # kubectl create configmap corp-idp-ca --from-file=ca.crt=corp-root-ca.pem
      key: ca.crt
    internalHosts: ["sso.corp.example:8443"]
networkPolicy:
  identityProviderEgress:
    - { cidr: 10.20.30.40/32, port: 8443 }
dashboard:
  oidcSso: true
```

`identityProviderEgress` opens only the listed address and port for the
functions pods; `functionsEgressCIDRs` still covers port 443 only.

## 2. Configure the tenant in the dashboard

As a tenant owner with MFA (AAL2), open **Single sign-on**:

1. **Provider**: type *Generic OpenID Connect*, the issuer from the runbook
   below, client ID, client authentication and secret reference. Put the client
   secret in `.env.functions` as `AIDR_OIDC_CLIENT_SECRET_<REF>` and have the
   operator bind `<REF>` to this tenant and issuer in
   `AIDR_OIDC_CLIENT_SECRET_BINDINGS` (see
   [oidc-sso-admin.md](../production-readiness/oidc-sso-admin.md#deployment-configuration)).
   Groups claim: `groups` (or the claim name you configured). Group
   requirement: **Ignore groups**. Extra scopes: `allatclaims` for ADFS,
   empty for Keycloak. **Save and validate**: the discovery document is fetched
   and checked now, so CA and host settings are tested at this step.
2. **Domains**: add the users' email domain and publish the TXT record
   `_aidr-sso.<domain>` in your internal DNS, then **Verify**. JIT never
   provisions an address outside a verified domain.
3. **Just-in-time provisioning**: tick *Create members at sign-in*, list the
   allowed email domains (each must be verified), choose the role for users
   whose groups match no mapping (*No access* is the safest), and map exact
   group values to roles, one per line: `/aidr/admins=admin`,
   `/aidr/users=member`. Matching is exact and case-sensitive, the highest role
   wins and `owner` is never granted.
4. Sign in from a private window with a test user, check the membership on the
   **Members** page, then follow the normal owner-linking and enforcement steps
   in [oidc-sso-admin.md](../production-readiness/oidc-sso-admin.md).

### How JIT behaves

- **First sign-in**: a membership is created with the mapped role (or the
  default role). Audit: `identity.oidc.jit_provisioned`.
- **Later sign-ins**: the role follows the current groups
  (`identity.oidc.jit_role_changed`). A user whose groups no longer map, and with
  no default role, loses the membership at that sign-in
  (`identity.oidc.jit_membership_revoked`) and is refused.
- **Removal in AIDR**: an administrator who removes a JIT member on the Members
  page keeps them out: the next sign-in is refused (`not_provisioned`) until an
  owner clicks **Re-admit** (`identity.oidc.jit_readmitted`).
- **Not touched by JIT**: owners, invited or manually added members, and every
  user SCIM knows. If SCIM later provisions a JIT user, the membership is handed
  to SCIM (`identity.oidc.jit_handed_to_scim`). JIT cannot be enabled while
  directory-authoritative membership is on.
- **Fail-safe outcomes**: a missing or overflowing groups claim, a domain that is
  not allowed or verified, an issuer that changed since the JIT policy was saved,
  or an unreadable policy all refuse the sign-in and change nothing; the precise
  reason is in the `identity.oidc.login_failed` audit detail.
- **What JIT does not do**: it does not see users who never sign in again.
  Disabling a user in AD stops new sign-ins at once, but an existing AIDR session
  lasts until `session_max_seconds` (default 12 hours) and the membership stays
  until it is removed. Remove leavers on the Members page or use SCIM where
  immediate deprovisioning is required.

## 3. Keycloak runbook

Tested settings for Keycloak 24 or newer; adapt names to your realm.

1. **Realm**: use the realm your users sign in to, for example `corp`. The issuer
   is `https://sso.corp.example:8443/realms/corp` (exactly the `issuer` value
   in `/.well-known/openid-configuration`).
2. **Client**: *Clients → Create client*, type **OpenID Connect**, client ID
   `aidr`. *Client authentication* **On** (confidential), *Standard flow* only
   (disable implicit, direct access grants and service accounts). *Valid
   redirect URIs*: `https://<dashboard>/auth/oidc/callback`; *Web origins*: the
   dashboard origin. In *Advanced → Proof Key for Code Exchange* choose **S256**.
3. **Secret**: *Credentials* tab, copy the client secret into
   `AIDR_OIDC_CLIENT_SECRET_<REF>` and bind the reference as described above.
4. **Email**: users need a verified email. With LDAP federation map the `mail`
   attribute (section 4); AIDR refuses `email_verified=false`.
5. **Groups claim**: *Client scopes → aidr-dedicated → Add mapper → By
   configuration → Group Membership*. Token claim name `groups`, *Full group
   path* **On** (values look like `/aidr/admins`), *Add to ID token* **On**.
   Map those paths on the AIDR JIT page.
6. **Roles instead of groups** (optional): add a *User Realm Role* mapper with
   token claim name `roles` (flat, no dots) and *Add to ID token* on, then set
   the AIDR groups claim to `roles`.
7. **Signing algorithm**: the realm default RS256 matches AIDR's default.
8. **Subject**: Keycloak's `sub` is the user's stable Keycloak id; keep the AIDR
   subject claim `sub`.

## 4. Active Directory / LDAP through Keycloak

AIDR does not bind to LDAP itself. Keycloak federates AD, AIDR trusts Keycloak.

1. *User federation → Add LDAP provider*. Vendor **Active Directory**,
   connection URL `ldaps://dc01.corp.example:636` (import the domain
   controllers' CA into Keycloak's truststore), bind DN of a read-only service
   account, users DN such as `OU=Users,DC=corp,DC=example`.
2. *Edit mode* **READ_ONLY**; *Import users* on; *Sync registrations* off.
   Username LDAP attribute `sAMAccountName` (or `userPrincipalName`), RDN `cn`,
   UUID `objectGUID`. Optional: *Kerberos integration* for desktop SSO.
3. Mappers: `email` → `mail`, `first name` → `givenName`, `last name` → `sn`.
   Set *Trust email* **On** in the provider so AD addresses count as verified.
4. Add a **group-ldap-mapper**: LDAP groups DN `OU=Groups,DC=corp,DC=example`,
   mode **READ_ONLY**, *Membership attribute* `member`, user groups retrieve
   strategy *LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY* for nested groups. AD
   groups then appear as Keycloak groups such as `/AIDR-Admins`.
5. *Synchronize all users* and set periodic changed-user sync (for example every
   15 minutes). Disabled AD accounts can no longer sign in to Keycloak.
6. Map the imported group paths on the AIDR JIT page, for example
   `/AIDR-Admins=admin`, `/AIDR-Users=member`.

## 5. ADFS runbook (Windows Server 2016 or newer)

1. *AD FS Management → Application Groups → Add*. Template **Server application
   accessing a web API**. Client identifier: note it (for example a GUID).
   Redirect URI `https://<dashboard>/auth/oidc/callback`.
2. *Configure application credentials*: **Generate a shared secret**; store it as
   `AIDR_OIDC_CLIENT_SECRET_<REF>` and bind it (section 2).
3. *Configure Web API*: identifier = the **same client identifier** as step 1,
   so the ID token's audience is the AIDR client id.
4. *Access control policy*: for example *Permit specific group* `AIDR-Users`.
5. *Configure application permissions*: scopes `openid`, `email`, `profile` and
   **`allatclaims`**. ADFS puts custom claims into the ID token only for
   `allatclaims`; that is why the AIDR provider has *Extra scopes:
   allatclaims*.
6. *Web API → Issuance Transform Rules*:
   - *Send LDAP Attributes as Claims*: `E-Mail-Addresses` → `E-Mail Address`
     (emitted as `email`).
   - *Send Group Membership as a Claim* for each AIDR group, outgoing claim
     type `Group`, value for example `AIDR-Admins`; or a custom rule that sends
     all `Token-Groups - Unqualified Names` as `group`. Set the AIDR groups
     claim to the short claim name ADFS emits (usually `group`; decode a test ID
     token to confirm). A single group arrives as a string; AIDR accepts that.
7. Issuer: `https://adfs.corp.example/adfs` (check the `issuer` in
   `https://adfs.corp.example/adfs/.well-known/openid-configuration`). ADFS signs
   ID tokens with RS256.
8. Subject: ADFS `sub` is a stable pairwise identifier per client. Keep the AIDR
   subject claim `sub` and never change the client identifier after users have
   signed in (the identity namespace is locked once identities exist).
9. If ADFS uses a certificate from an internal CA, prepare with `--idp-ca-file`
   and `--oidc-internal-idp-hosts adfs.corp.example`.

## 6. SAML in the self-hosted GoTrue

Use SAML only together with SCIM: SAML sign-in proves identity, but AIDR grants
membership to SAML users only through SCIM.

1. Prepare with `--with-saml` (Compose) or set `auth.saml.enabled=true` and
   `auth.saml.privateKeyKey` (Helm; generate the key on an administrator host with
   `openssl genrsa 2048 | openssl rsa -outform DER | base64 -w0` and store it in
   the platform Secret).
2. Give the IdP the service-provider metadata
   `https://<api>/auth/v1/sso/saml/metadata` (ACS
   `https://<api>/auth/v1/sso/saml/acs`).
3. Register the IdP from the deployment host through the GoTrue admin API on the
   loopback gateway, using the service-role key from `/srv/aidr/.env`. Prefer
   inline `metadata_xml` so GoTrue does not need to reach the IdP:

   ```sh
   curl -sS -X POST http://127.0.0.1:8000/auth/v1/admin/sso/providers \
     -H "apikey: $SERVICE_ROLE_KEY" -H "Authorization: Bearer $SERVICE_ROLE_KEY" \
     -H "Content-Type: application/json" \
     --data "$(jq -n --rawfile xml FederationMetadata.xml \
       '{type:"saml", metadata_xml:$xml, domains:["corp.example"]}')"
   ```

   Record the returned provider `id`.
4. Set `AIDR_SAML_PROVIDER_ID=<id>` (or `AIDR_SAML_PROVIDERS` for several) in
   `/srv/aidr/.env` and restart the dashboard. Configure the IdP to send a
   persistent, opaque `NameID` equal to the SCIM `externalId`, then follow
   [scim-directory-admin.md](../production-readiness/scim-directory-admin.md).

## 7. Troubleshooting

| Symptom (`oidc-sso` response reason or `identity.oidc.login_failed` audit detail) | Cause and fix |
| --- | --- |
| Save refused, reason `discovery_private_address` | The IdP resolves to a private address and is not in `AIDR_OIDC_INTERNAL_IDP_HOSTS`. |
| `discovery_blocked_host` | Internal suffix (`.local`, `.corp`, `.lan`, single label) not listed in `AIDR_OIDC_INTERNAL_IDP_HOSTS`. |
| `discovery_port_not_allowed` | The issuer uses a port that is not listed (`host:8443`). |
| `discovery_network_error` | Usually TLS: the IdP certificate is not signed by a CA in `--idp-ca-file`, or DNS/firewall. |
| `discovery_issuer_mismatch` | The issuer typed in AIDR differs from the document's `issuer` (trailing slash, port, realm). |
| Every `oidc-sso` call answers `server_misconfigured` | `AIDR_OIDC_INTERNAL_IDP_HOSTS` is malformed. |
| Login refused, audit `jit_no_role` | The groups claim is missing or no group matches; check the mapper adds groups to the **ID token**, and the ADFS `allatclaims` scope. |
| Login refused, audit `jit_domain_not_allowed` | Email domain is not in the JIT allow-list or not verified. |
| Login refused, audit `jit_removed_by_admin` | The user was removed in AIDR; an owner must re-admit them. |
| Login refused, audit `jit_disabled` while JIT is on | The provider issuer changed after the JIT policy was saved: save the JIT section again. |

## Acceptance before a customer go-live

Local suites prove the logic (`supabase/functions/__tests__/oidc-sso-jit.test.ts`,
`scripts/oidc-jit-provisioning-postgres.test.mjs`, `scripts/lib/onprem-sso.test.mjs`,
`deploy/helm/chart.test.mjs`). They are not live acceptance. Before relying on
this in production, run one sign-in per IdP (Keycloak with AD federation, ADFS)
against the deployed release candidate with an internal-CA certificate, and keep
redacted receipts: discovery saved, first-login provisioning, group change,
removal and re-admission, and the audit events above.
