# AIDR scheduled maintenance

The generated deployment uses the existing SIEM maintenance timer at a
one-minute cadence for the active control-plane signing key, configured durable
queue sources, and the SIEM drain. It
loads the same owner-only `.env.functions` key material used by the functions
runtime, writes only fixed safe
evidence to `/srv/aidr/health`, and replaces stale green files with `failed`
evidence when any source cannot be verified.

That local key canary applies only to self-hosted mode, where Compose loads the
same `.env.functions` file. Managed cloud stays failed until a provider-side
signed canary endpoint is implemented and accepted; checking an undeployed
local copy must never make cloud signing readiness green.

Production preparation requires `--telemetry-queue-root`; it has no fabricated
default. The path must name a real fleet-aggregated `DurableTelemetryQueue` root
under `/var/lib/aidr-telemetry`. The external authenticated fleet aggregator
must create at least one 64-hex queue namespace before installation; the
installer refuses an absent or empty root. To use additional sources, set one
or more comma-separated roots under that directory. You may also set
`SINGULARITY_AIDR_SIEM_CONFIG_PATH` to a real protected SIEM configuration.
That configuration's `state_file` must be under `/var/lib/aidr-siem`.
At least one real queue source is required; an absent or empty source stays red.
The installer rejects paths outside these systemd-writable state directories.
User-local or remote endpoint queues are not inferred from an empty
dashboard-host directory.

### Syslog destination (TCP, TLS, UDP)

Besides the HTTPS providers, the `adapter` block can be
`{ "provider": "syslog", "endpoint": "tls://collector.example.com:6514" }`.
Messages are RFC 5424 (UTF-8 BOM + single-line JSON MSG, structured data
`aidr@32473`); TCP and TLS use RFC 6587 octet counting. The dashboard
**SIEM export** page (`/siem`) generates and validates this block locally.

- `tls://` verifies the certificate chain and host name and cannot be
  downgraded. `tlsCaCertificatePem` replaces the system roots with your private
  CA; `tlsPinnedSha256` additionally requires that one certificate in the
  presented chain has a matching SHA-256 public-key pin (hex or base64).
- `tcp://` and `udp://` send incident data unencrypted and are refused unless
  `allowPlaintextTransport` is `true`.
- Egress policy: loopback, link-local (including cloud metadata), multicast,
  broadcast and unspecified addresses are always refused. RFC 1918, CGNAT, ULA
  and similar ranges need `allowPrivateNetwork: true`. Every address a host name
  resolves to is checked on every send and the connection is made to the
  checked address, so a rebinding answer cannot steer the sender.
- Delivery uses the same durable queue, bounded exponential backoff
  (`maxAttempts`, default 10) and dead-letter counters as the HTTPS adapters.
  Receipts carry `deliveryCode`: `syslog_tcp_written` / `syslog_tls_written`
  mean every byte was flushed and the peer closed cleanly; UDP records
  `syslog_udp_sent_unacknowledged` because syslog has no application
  acknowledgement. None of these proves downstream indexing, so validate
  visibility in the SIEM during acceptance.
- `facility`, `hostname`, `appName`, `structuredDataId` and `maxMessageBytes`
  (default 64 KiB; events are truncated to fit; UDP datagrams over 8 KiB are
  dead-lettered rather than split) tune the message. Verification-disabling
  options do not exist.

Protect the SIEM JSON configuration and state as secrets: the config contains
provider credentials in plaintext, and the local state contains incident
payloads. On Linux, the state directory and file must be owner-only; the
delivery code rejects broader permissions and symlinked state files. The
state-file SHA-256 detects accidental corruption, but is not a signature or a
defense against an attacker who can write the file. Keep both paths outside the
customer kit, restrict backups, and rotate provider credentials through the
customer's secret-management process.

Splunk HEC, Sentinel, and Elastic require their configured token. Generic
webhooks permit bearer auth or custom secret headers but do not require either,
and the adapter does not provide mTLS or request signing. Do not point an
unauthenticated webhook at an internet-reachable receiver; use a private,
TLS-protected route or configure the receiver's supported auth header and
verify it during customer acceptance.

Delivery is **at least once**, not exactly once. A crash after a receiver
accepts an event but before AIDR records the receipt can cause a retry. AIDR
uses a stable `event_id` and idempotency headers where supported, but only
Elastic's deterministic document ID provides deduplication in the adapter;
other receivers must deduplicate on `event_id` if duplicates are unacceptable.
`delivered` means the configured provider's receipt contract was met (a
correlated webhook response, Splunk HEC success, Sentinel HTTP 204, or an
accepted Elastic bulk item). It does **not** prove downstream indexing,
alerting, or search visibility. Monitor queue age/depth, retry and dead-letter
counts, and validate visibility in the customer's SIEM during acceptance.
When capacity is exhausted AIDR refuses new queue entries; do not delete the
state file to recover capacity or clear a failure.

## Alert notification dispatcher (optional)

Settings → Notifications channels (Slack, Teams, signed webhooks, e-mail) are
delivered by the `notification-dispatch` Edge Function. On Compose it is driven
by `aidr-notification-dispatch.timer`, which runs
`maintenance/notification-dispatch.mjs` once a minute: it POSTs to
`<supabase_url>/functions/v1/notification-dispatch` with
`AIDR_NOTIFICATION_DISPATCH_TOKEN` from the owner-only `.env.functions` and
prints delivery counts only (never the token, a destination or a payload).
`deployment-prepare.mjs` generates that token and
`AIDR_NOTIFICATION_ENCRYPTION_KEYS`; for an installation prepared before alert
integrations, add both to `.env.functions` (a `k1:` prefixed base64 32-byte key
and a random token of at least 32 characters), then recreate the `functions`
service. Enable the timer with `--with-notifications`; the installer refuses
when either variable is missing and runs one supervised dispatch before
enabling the schedule. Deliveries leave from the `functions` container, so the
host firewall or egress proxy must allow Slack, Teams, the webhook receivers
and the mail provider.

Install on the production Linux host:

```sh
sudo sh /srv/aidr/maintenance/install-systemd.sh
```

This first runs the evidence worker and then enables
`aidr-siem-delivery.timer`; a missing key, queue, or configuration fails before
activation. Add `--with-backup`
only after `/etc/aidr/backup-offsite.env` and
`/etc/aidr/aidr-recovery.key` are installed; this installs the backup units and
enables boot recovery only. Run and verify one offsite backup cycle and its
failure alert before explicitly enabling `aidr-backup-offsite.timer`, as described
in [the backup guide](../backup/README.md). The installer fails when required
queue or backup inputs are missing.

## Windows hosts (Task Scheduler)

`Install-AidrMaintenanceTasks.ps1` mirrors every systemd timer in this directory
as a Windows Scheduled Task with a fixed name in the `\AIDR\` task folder:

| Task | systemd source | Schedule | Command | Working directory | Time limit |
|------|----------------|----------|---------|-------------------|------------|
| `\AIDR\aidr-siem-delivery` | `aidr-siem-delivery.timer` / `.service` | 30 s after boot, then every minute; missed runs start when available | `node.exe "--env-file=<deployment>\.env.readiness" "<deployment>\maintenance\readiness-evidence-worker.mjs"` | `<deployment>` | 5 min |
| `\AIDR\aidr-export-retention` | `aidr-export-retention.timer` / `.service` | hourly with up to 5 min random delay; missed runs start when available | `node.exe "<kit>\scripts\deployment-maintenance.mjs" "<deployment>" --apply` | `<kit>` | 15 min |
| `\AIDR\aidr-notification-dispatch` (opt-in, `-WithNotifications`) | `aidr-notification-dispatch.timer` / `.service` | 45 s after boot, then every minute; missed runs start when available | `node.exe "<deployment>\maintenance\notification-dispatch.mjs" "<deployment>"` | `<deployment>` | 2 min (`TimeoutStartSec=2min`) |

Every task ignores a new start while a run is still in progress, like a oneshot
unit. Do not rename them: `scripts/deployment-doctor.mjs` queries exactly these
names.

The notification dispatcher is registered only with `-WithNotifications`, the
mirror of `install-systemd.sh --with-notifications`. The installer then refuses
to continue unless the prepared `aidr-notification-dispatch.service`, `.timer`
and `notification-dispatch.mjs` exist and `.env.functions` holds an
`AIDR_NOTIFICATION_DISPATCH_TOKEN` of at least 32 characters and an
`AIDR_NOTIFICATION_ENCRYPTION_KEYS` value with a key-id prefix (for example
`k1:`); a value containing `REPLACE_` is also refused. Like the systemd unit,
the task loads no environment file: the dispatcher reads the API origin from
`deployment.json` and its token from `.env.functions` itself, and writes
nothing. Re-running the installer without `-WithNotifications` leaves an
already registered dispatcher unchanged and still declared; remove it with the
uninstaller.

Before activation, edit `<deployment>\.env.readiness` so
`AIDR_DEPLOYMENT_DIR` names the deployment directory and
`AIDR_HEALTH_STATE_DIR` names `<deployment>\health`; the prepared values are the
Linux `/srv/aidr` paths, and a scheduled task cannot override them. The
installer checks the same inputs as `install-systemd.sh` (signing key expiries,
no `REPLACE_` placeholders, at least one real queue source whose roots already
contain a fleet-aggregated namespace, a readable SIEM configuration) and stops
on the first failure.

From an elevated PowerShell session, preferably with a dedicated group managed
service account that holds the *Log on as a batch job* right:

```powershell
.\maintenance\Install-AidrMaintenanceTasks.ps1 `
  -DeploymentDirectory D:\aidr\deployment -KitDirectory D:\aidr\kit `
  -ServiceAccount 'CONTOSO\aidr-maint$'
```

With `-ServiceAccount`, the account is granted only what the workers touch:
read on `deployment.json`, `.env`, `.env.functions`, `.env.readiness`,
`agent-config.json`, the `maintenance` directory and the kit; modify on
`health`, `maintenance-evidence.json`, the configured telemetry queue roots and
the SIEM state directory. The notification dispatcher needs no further grant:
it only reads `deployment.json`, `.env.functions` and its script under
`maintenance`. No password is stored. `-RunAsSystem` runs as
LocalSystem, matching the `root` user of the systemd units, and should be used
only where no gMSA is available. `-NodePath` selects a Node.js 24+ `node.exe`
when it is not on `PATH`.

The installer registers the SIEM and retention tasks, writes
`<deployment>\windows-maintenance-tasks.json` (its `tasks` list names every task
it installed, including the dispatcher when requested) and then runs
`aidr-siem-delivery` once through Task Scheduler as the chosen principal. If
that first run fails, the task is left disabled and the installer exits
non-zero. With `-WithNotifications`, the dispatcher task is registered only
after that run succeeds and is then run once itself, like the supervised
`systemctl start` in `install-systemd.sh`; if its first dispatch fails, it is
left disabled and the installer exits non-zero. Re-running the installer is
idempotent. The retention reaper waits for its first hourly trigger.

`windows-maintenance-tasks.json` is the declaration the doctor relies on. On a
Windows host, `scripts/deployment-doctor.mjs` reads each task's definition with
`schtasks /Query /TN \AIDR\<name> /XML` and checks that the task is enabled, has
an active trigger, and runs `node.exe` with this deployment's worker:

- task present, enabled and wired to this deployment: PASS;
- task present but disabled, without an active trigger, or pointing elsewhere: FAIL;
- task absent or unreadable and the declaration exists: FAIL;
- task absent and no declaration exists: UNVERIFIED, because the operator may
  schedule the workers by other means the doctor cannot inspect. UNVERIFIED
  still makes the doctor exit non-zero.

The opt-in `aidr-notification-dispatch` task is checked only when the
declaration's `tasks` list names it or the task is installed; then the same
PASS/FAIL rules apply (it must run this deployment's
`maintenance\notification-dispatch.mjs` with the deployment directory as its
argument). Absent and undeclared, the doctor prints an INFO line and records
nothing as passed. The Linux doctor does not inspect
`aidr-notification-dispatch.timer`.

To remove the tasks, the `\AIDR\` folder (when empty), the recorded service
account's file grants and the declaration:

```powershell
.\maintenance\Uninstall-AidrMaintenanceTasks.ps1 -DeploymentDirectory D:\aidr\deployment
```

Evidence files remain on disk after removal and go stale, so the dashboard's
freshness checks turn them red. The backup timers in `deploy/backup` are not
covered by these scripts.

## Development manifests and the doctor

A deployment prepared with `--development` never configures a certificate, and
it only has signing, backup and queue evidence when the maintenance units above
actually run. Its readiness is a rehearsal. `deployment-doctor.mjs --online`
therefore fails a development manifest with *production evidence requires a
production manifest*. Pass `--development` to run the doctor against a loopback
rehearsal on purpose. `doctor-evidence.json` then records
`"evidence_class": "development"`, and passing `--development` with a
production manifest is a failure. When `/readyz` is not ready, the doctor names
the failing readiness checks, for example
`FAIL dashboard readiness (not ok: signing, backup, certificate)`.
## Governance summaries

`aidr-export-retention.timer` runs `scripts/deployment-maintenance.mjs --apply` hourly.
After the retention steps it calls the `governance-digest` Edge Function with the
deployment service credential, which sends due weekly/monthly governance summaries
(counts only) to each workspace's owners/admins through the configured mailer and
records a receipt. The dispatch counts are written to `maintenance-evidence.json`
under `governance_digest`. See `docs/ai-governance-frameworks.md`.
