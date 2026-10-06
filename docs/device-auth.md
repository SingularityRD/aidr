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

## Interrupted enrollment and operator repair

The control plane stores API key hashes, not the plaintext keys. It cannot
recover an API key whose issuance response was lost. A timeout, connection loss,
or `enrollment_outcome: unknown`/`committed` is not evidence of rollback. A
consumed pairing code must not be approved or exchanged again. A confirmed
`not_committed` enrollment response is safe to retry.

Before exchange, the runtime exclusively creates a private, non-secret
`~/.singularity-aidr/managed.json.enrollment-pending` journal. Startup and tool
evaluation share it. A timeout, crash, expiry, or config change does not clear
it. If key storage fails, the journal remains and the runtime shows
`enrollment_repair_required` instead of the old browser code. Local detection
and the configured authentication/policy requirements keep their normal
behavior; enrollment repair does not grant managed access.

To repair an uncertain or committed issuance:

1. Stop the affected agent and settle the outstanding request with the
   deployment operator. Record the existing installation ID from
   `~/.singularity-aidr/installation-id` and the original tenant. Keep that file,
   tenant configuration, credential vault references, and telemetry namespace.
2. An authenticated tenant owner/admin opens **API Keys** in the accepted
   dashboard, finds the affected keys labelled `enroll:<installation-id>`, and
   revokes each uncertain issuance using the existing audited revoke action.
   Re-pairing does not revoke old keys automatically. The list shows at most
   200 recent keys: an absent entry or an in-flight request is not proof that no
   key committed. If the operator cannot establish and revoke the outcome,
   keep the agent stopped and escalate; do not reset the journal or re-pair.
3. After the operator confirms settlement/revocation, remove only the pending
   journal and the old device cache fields from `managed.json`: `device_code`,
   `user_code`, `verification_url`, `device_expires_at`, `device_started_at`.
   Preserve all other state. If configuration contains the old consumed
   `auth.enrollment_token`, remove that old token too. Never delete the whole
   AIDR state directory or installation ID to retry enrollment.
4. Start the accepted connector to obtain a fresh server-issued URL/code,
   have the authorized human approve it, and restart the host. A fresh approved
   token issued through the existing enrollment-token administration flow is
   also supported. Re-enroll in the original tenant with the same installation
   ID; this updates the existing fleet agent and consumes one seat, not two.
5. Verify the new credential is saved in the approved secret store, only the
   replacement key is active, and the accepted host enforcement checks pass.

Device polling can safely retry issuance of the same *unused enrollment token*
from its existing device code. This does not recover a plaintext API key. Once
that token has been consumed, polling returns `already_exchanged` and requires
the operator repair procedure above if no credential was saved locally.

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
