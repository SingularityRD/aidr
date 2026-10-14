---
"@singularityrd/aidr-dashboard": minor
---

On-prem single sign-on without SCIM:

- Just-in-time OIDC provisioning on the Single sign-on page: opt-in per tenant, allowed (DNS-verified) email domains, issuer pin, exact group claim to admin/member/viewer mapping with an optional member/viewer default, role sync and removal at later sign-ins, administrator removals that stick until an owner re-admits the user, and an audit event for every membership change. SCIM-provisioned users keep working unchanged.
- Extra authorization scopes from a fixed allow-list (`allatclaims` for ADFS group claims, `groups`, `roles`).
- Internal identity providers: operator-listed internal IdP hosts (`AIDR_OIDC_INTERNAL_IDP_HOSTS`) and an internal CA for the Edge Functions runtime (`deployment-prepare --idp-ca-file`, Helm `functions.identityProvider`), plus `--with-saml` for the self-hosted GoTrue. Keycloak, ADFS and Active Directory (through Keycloak) runbooks in English and Turkish.
