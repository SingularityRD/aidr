# AIG Threat Intelligence Sync Pipeline

## Overview

The sync pipeline keeps AIDR edge agents updated with the latest
threat intelligence from the AIDR-owned AI-Infra-Guard source, based on
[Tencent AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard).

## How It Works

```
vendor/ai-infra-guard/data/         ← AIG vulnerability data (upstream YAML files)
         │
         ▼
scripts/compile-aig-data.mjs        ← Compiles YAML → compact JSON indices
         │
         ▼
scripts/sync-aig-threats.mjs        ← Pipeline orchestrator (hash diff, report, watch)
         │
         ▼
packages/core/src/generated/        ← Compiled indices for edge agent consumption
    ├── aig-cve-index.json
    ├── aig-fingerprints.json
    └── aig-mcp-categories.json
         │
         ▼
packages/core/src/aig-sync.ts       ← Edge client (checks/loads/applies updates)
```

### Pipeline Steps

1. **AIG data** lives at `vendor/ai-infra-guard/data/` in the AIDR Git tree.
2. **compile-aig-data.mjs** parses YAML vulnerability definitions and compiles them into three compact JSON index files.
3. **sync-aig-threats.mjs** runs the full pipeline:
   - Checks if AIG is installed (graceful if missing — no crash).
   - Snapshots current file hashes.
   - Invokes the compiler.
   - Compares new hashes against old.
   - Reports a diff (added/removed/changed CVEs, fingerprints, categories).
   - Skips unnecessary writes when nothing changed.
4. **Edge agents** call `aig-sync.ts` at session start or on a timer to load the latest indices.

## Running

```bash
# Full sync (compile + diff + report)
pnpm sync:aig

# Watch mode — recompiles automatically when AIG data changes
pnpm sync:aig:watch

# Force recompile even if hashes match
pnpm sync:aig:force

# Quiet mode — suppress info logs, show only warnings/errors
node scripts/sync-aig-threats.mjs --quiet
```

### Exit Codes

| Code | Meaning                                      |
|------|----------------------------------------------|
| 0    | Success (no changes or changes applied)      |
| 1    | Compilation or disk error                    |

## Automation

### Local (cron / systemd timer)

```bash
# Run every hour
0 * * * * cd /path/to/aidr && pnpm sync:aig --quiet
```

### CI/CD (GitHub Actions)

```yaml
- name: Sync AIG threat intel
  run: pnpm sync:aig
```

### Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: aig-threat-sync
spec:
  schedule: "0 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: sync
            image: node:22.12.0
            workingDir: /app
            command: ["node", "scripts/sync-aig-threats.mjs", "--quiet"]
```

## Edge Client Integration

The edge-side client (`packages/core/src/aig-sync.ts`) exposes a simple API:

```typescript
import { getSyncStatus, checkForUpdates, fullSyncCycle } from "@singularityrd/aidr-core/aig-sync";

// Check current status
const status = await getSyncStatus();
console.log(status.cveCount); // 1500+

// Full sync cycle (check → download → apply)
const ok = await fullSyncCycle();
```

### Configuration

The client respects the AIDR config (`~/.singularity-aidr/config.json`) under the `intel` section or an `aig_sync` override:

```json
{
  "intel": {
    "enabled": true
  },
  "aig_sync": {
    "enabled": true,
    "mode": "local",
    "generated_dir": "/path/to/generated",
    "remote_url": "https://control-plane.example.com/api/v1/aig-sync",
    "poll_interval_seconds": 3600
  }
}
```

## File Layout

```
vendor/ai-infra-guard/
  data/
    vuln_en/          ← English CVE data (preferred)
    vuln/             ← Chinese CVE data (fallback)
    fingerprints/     ← Framework fingerprint definitions

packages/core/src/generated/
  aig-cve-index.json        ← Compiled CVE index
  aig-fingerprints.json     ← Compiled fingerprint index
  aig-mcp-categories.json   ← MCP risk category definitions
```

## Data Flow for SaaS Deployments

For managed (SaaS) deployments, the sync pipeline runs on the control plane:

1. Control plane runs `sync-aig-threats.mjs` periodically.
2. Compiled indices are published to a CDN / API endpoint.
3. Edge agents poll the endpoint via `aig-sync.ts` in HTTP mode.
4. Agents cache fetched indices locally and apply on next session start.

## Signed production feed

Production agents must enable the complete trust policy; a public key by itself
is not an identity:

```bash
export AIG_REQUIRE_SIGNED=true
export AIG_SIGNING_PUBLIC_KEY_PATH=/etc/aidr/aig-data-signing-public.pem
export AIG_TRUSTED_SIGNING_KEY_ID=aig-data-production-1
export AIG_TRUSTED_SIGNING_PUBLIC_KEY_SHA256=<64-lowercase-hex-SPKI-digest>
```

Compute the fingerprint from the independently distributed public key:

```bash
openssl pkey -pubin -in /etc/aidr/aig-data-signing-public.pem -outform DER \
  | sha256sum
```

The key ID must match the signed manifest and the fingerprint must match the
DER-encoded SPKI. HTTP-mode feeds require HTTPS, refuse redirects and oversized
responses, and reject a bundle older than the active manifest. Keep
`AIG_SIGNING_PRIVATE_KEY` / `AIG_SIGNING_PRIVATE_KEY_PATH` only in the isolated
release-signing environment; endpoint agents need only the public key.

### Publishing a new corpus

Every published corpus has a monotonically increasing `release_sequence`.
When the pinned AIG commit or compiled bundle changes, append exactly one entry
to `config/aig-release-sequence.json` using the next contiguous sequence and the
compiler-reported commit/bundle tuple. Never edit or reuse an existing mapping.
The compiler fails before writing generated files when the tuple is missing or
the registry is non-contiguous; this is the rollback boundary for agents that
already installed an older signed bundle.

## Air-gapped updates

A disconnected installation cannot poll a feed. Signed intel packs are carried
in on approved media and imported with `scripts/import-offline-pack.mjs`, which
verifies everything before it writes anything and never contacts the network.

**What the vendor delivers.** A signed pack directory in the format the release
tooling already produces: `manifest.json` (`pack_id`, `version`, `issued_at`,
optional `expires_at`, `key_id`, `files[]` with SHA-256 or ciphertext SHA-256),
the `manifest.sig` written by `scripts/sign-intel-pack-manifest.mjs` over the
exact manifest bytes, and every listed file. For single-file transfer the same
bytes can be wrapped in an `aidr-intel-pack-bundle-v1` JSON (`--export-bundle`).
The publisher's public key is delivered separately (for example with the signed
customer kit) as a trusted-keys file in the core loader format:
`{ "<key_id>": "<Ed25519 public key PEM>" }`.

**Verification** (identical for every target, using the core
`IntelPackManifestSchema` and `verifyEd25519Signature`):

- the manifest matches the schema and `pack_id`/`version` are path-safe;
- its exact bytes carry a valid Ed25519 signature from a key in the trusted-keys
  file (`--revoked-key-id` refuses a withdrawn key);
- every listed file is present and matches its SHA-256 (ciphertext SHA-256 for
  encrypted files; those are decrypted later by the endpoint keyring);
- no unlisted file, symlink, absolute or `..` path is present;
- the pack has not expired;
- the version is not older than the installed or registered one (rollback) and a
  different pack under an already installed version is refused (equivocation).

**Install for endpoints / a shared intel directory** — the layout the endpoint
loader reads (`~/.singularity-aidr/intel/packs/<pack_id>/<version>/` plus
`active.json`):

```sh
node scripts/import-offline-pack.mjs --pack /media/aidr/aidr-intel-2026.09 \
  --trusted-keys /etc/aidr/intel-trusted-keys.json --target local \
  [--packs-dir /srv/aidr-intel/packs]
```

Files are staged, re-verified from disk, renamed into place and activated; a
re-import of identical bytes reports `already_installed`. Endpoints still verify
the signature and hashes themselves each time they load the pack.

**Install into the self-hosted control plane** so the authenticated
`packs-manifest` / `packs-download` functions serve it to entitled tenants:

```sh
node scripts/import-offline-pack.mjs --pack /media/aidr/aidr-intel-2026.09.aidrpack.json \
  --trusted-keys /etc/aidr/intel-trusted-keys.json --target storage \
  --deployment /srv/aidr [--tenant-id <tenant uuid>]
```

The verified bundle is uploaded without overwrite to the private `aidr-packs`
bucket (migration `20260924000013`) at `<tenant_id|shared>/<pack_id>/<version>.aidrpack.json`
and registered in `pack_versions` with the signed manifest, signature and key id.
The service-role credential is read from the deployment's private `.env`, never
from arguments. If registration fails after the upload, re-run the same command:
an identical object is accepted and registration completes; a different object
or row is refused.

The command prints a JSON receipt (`outcome`, `pack_id`, `version`, `key_id`,
`manifest_sha256`, file count). A pack that fails any check exits non-zero and
leaves the installation unchanged. Local detection rules shipped with the
connectors are unaffected by pack imports; packs only add intelligence.

## Troubleshooting

| Symptom                     | Likely Cause                        | Fix                                      |
|-----------------------------|-------------------------------------|------------------------------------------|
| `AIG not found` warning     | Incomplete AIDR checkout            | Restore the committed `vendor/ai-infra-guard` directory from AIDR |
| `Compilation failed` error  | Corrupt YAML or missing dependency  | Check `node version`, run `compile-aig-data.mjs` directly |
| No changes detected         | AIG data hasn't changed             | Normal — use `--force` to re-test        |
| Watch mode crashes          | `recursive` watcher unsupported     | Use polling cron instead                 |
