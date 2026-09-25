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
`/etc/aidr/aidr-recovery.key` are installed; the same command then enables the
backup timer. The installer fails instead of claiming activation when required
queue or backup inputs are missing.
