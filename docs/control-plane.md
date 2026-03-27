# Control Plane (Auth, Dashboard, Licensing)

Singularity AIDR can run **fully local** (no account) or connect to an optional **control plane** for:

- User authentication (dashboard login)
- Centralized agent inventory (installations)
- Telemetry-backed dashboards (verdict/event timeline)
- Agent-seat licensing (1 free agent, paid per additional agent)

## How a user connects an agent

1. Create an account in the dashboard (Supabase Auth).
2. Generate an API key.
3. Set `auth.api_key` in `~/.singularity-aidr/config.json`.
4. Enable control plane telemetry (optional):

```json
{
  "auth": { "api_key": "aidr_live_..." },
  "control_plane": {
    "enabled": true,
    "send_audit_logs": true,
    "endpoint": "https://YOUR_PROJECT.supabase.co/functions"
  }
}
```

When enabled, Singularity AIDR will send best-effort runtime verdict events to the control plane (`POST /v1/ingest`). Local detection is unaffected if the control plane is down (fail-open).

## Licensing model (recommended)

- **1 free agent per user**: first unique installation id (`iid`) that phones home under a given API key.
- **Paid per additional agent**: each additional unique `iid` requires an entitlement.

Enforcement is intended to be **server-side**:

- If the control plane sees a new `iid` over the entitlement limit, it should reject ingest (`402`/`403`) and optionally return a machine-readable error.
- The client should keep running local protections and simply disable cloud-only features (fail-open).
