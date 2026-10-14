---
"@singularityrd/aidr-cli": minor
"@singularityrd/aidr-core": minor
---

Machine policy: an administrator's settings for every user of a computer, read from `HKLM\SOFTWARE\Policies\Singularity AIDR` (Windows) or the root-owned `/etc/singularity-aidr/managed.json` (Linux). It carries the company control-plane address, a fleet enrollment key (`aidr_fleet_…`), the deployment's licensing public keys, proxy / CA settings, support and privacy-notice links, the approval channel and the offline policy, and it wins over the user's config for those keys. `aidr setup` applies its company connection without the `connect` confirmation, so per-machine (Intune/SCCM/GPO, Active Setup) and root package installs now connect every user. A policy that fails a check is refused as a whole and reported. The MSI takes the values as `AIDR_POLICY_*` properties (per-machine; remembered across upgrades; a SYSTEM install turns `ENROLLMENT_URL` into the policy), the Linux package hook as `AIDR_POLICY_*` variables.

New configuration: `network.ca_file`, `network.use_os_trust_store`, `network.https_proxy`, `network.no_proxy` (every first-party client; `HTTPS_PROXY` / `NO_PROXY` are honoured when unset; certificate verification is never turned off), `organization.support_contact_url`, `organization.privacy_notice_url`, `operator_approvals.approvals_mode` and `control_plane.offline_policy` (`keep_enforcing_local` | `block_after_grace`, which decides `remote_policy_required`). While the control plane does not answer, the session-start banner says which offline policy applies and when a block begins.

Customer packets may carry `licensing_public_keys_pem` (the deployment's Ed25519 signing keys), which `aidr setup` trusts. Older `aidr` versions refuse a packet with this field. Installer enrollment codes also accept fleet keys.
