# Device Auth (Browser Verification)

Device authorization is a managed-enrollment flow, not part of a local-only
installation. It requires a deployed and live-accepted control plane, an
authentication method configured for that deployment, a signed runtime
configuration, and an approved pilot account. The current first-customer
readiness decision is NO-GO, so this is not a currently available customer
enrollment path; see the [readiness profile](production-readiness/first-customer-ready.md).

## Flow after deployment acceptance

1. Install the accepted connector version for the supported runtime and host.
2. Start the agent once.
3. If the connector supports device enrollment and the runtime configuration is
   valid, it shows:
   - a short **verification code**
   - a **verification URL**
4. Open the URL and sign in using an authentication method enabled for that
   deployment. The method is deployment-specific; Google OAuth is not required
   or universally configured.
5. Enter the code and approve the device, if the account is authorized for the
   pilot.
6. Restart the agent (or rerun the host's enable-protection command).

After approval and successful enrollment, AIDR caches the resulting managed
state locally under `~/.singularity-aidr/managed.json`. A code or successful
browser approval alone does not prove that the host loaded or enforced the
connector; use the accepted host-specific checks.

## Offline behavior

- Device authorization requires network access.
- After enrollment, managed entitlement checks use `control_plane.grace_period_hours`.
  A customer deployment also requires a fresh central policy: its cached policy
  expires separately, with `control_plane.remote_policy_offline_grace_seconds`
  (3,600 seconds by default) after expiry. Once that period ends, protected
  operations block until policy refresh succeeds.

## Security notes

- Verification codes are short-lived and single-use.
- Enrollment requires an approved account and accepted deployment (see [Pilot Program](pilot-program.md)).
- API keys and enrollment tokens are stored hash-only server-side; plaintext is shown only at issuance.
