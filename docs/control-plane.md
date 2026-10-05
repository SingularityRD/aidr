# Control Plane (Auth, Dashboard, Licensing)

The control plane is the managed layer for:

- User authentication (dashboard login)
- Centralized agent inventory (installations)
- Telemetry-backed dashboards (verdict/event timeline)
- Incidents view derived from telemetry events (see `docs/incidents.md`)
- Agent-seat licensing (1 free agent, paid per additional agent)

For commercial builds, Singularity AIDR is **managed-first**: enrollment is required before protection is activated.

## Single sign-on

Tenants can require SAML or OpenID Connect (Entra ID, Okta, generic) sign-in; see [OIDC SSO](production-readiness/oidc-sso-admin.md) and [SCIM directory setup](production-readiness/scim-directory-admin.md). Both are optional and off by default.

## Enrollment (recommended)

The primary onboarding flow is **device authorization**:

1. Install the connector (Claude Code / Cursor / VS Code / OpenClaw / OpenCode).
2. Start the agent once.
3. Singularity AIDR prints a short verification code and a verification URL.
4. Open the URL, sign in, and approve.
5. Restart the agent (or rerun the enable-protection command).

See [Device Auth](device-auth.md).

## API keys (fallback)

For advanced or support scenarios, you can still use API keys:

1. Sign in to the dashboard.
2. Create an API key.
3. Set `auth.api_key` in `~/.singularity-aidr/config.json` and enable `control_plane.enabled`.

## Licensing model (recommended)

- **1 free agent per user**: first unique installation id (`iid`) that phones home under a given API key.
- **Paid per additional agent**: each additional unique `iid` requires an entitlement.

Enforcement is intended to be **server-side**:

- If the control plane sees a new `iid` over the entitlement limit, it should reject ingest (`402`/`403`) and optionally return a machine-readable error.
- The client should keep running local protections and simply disable cloud-only features (fail-open).
