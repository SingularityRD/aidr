# AIG Threat Intelligence Sync Pipeline

## Overview

The sync pipeline keeps AIDR edge agents updated with the latest
threat intelligence from [AI-Infra-Guard (AIG)](https://github.com/aliyun/ai-infra-guard).

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

1. **AIG data** lives at `vendor/ai-infra-guard/data/` — cloned as a git submodule or vendored copy.
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
            image: node:20
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

## Troubleshooting

| Symptom                     | Likely Cause                        | Fix                                      |
|-----------------------------|-------------------------------------|------------------------------------------|
| `AIG not found` warning     | AIG repo not cloned                 | `git submodule update --init vendor/ai-infra-guard` |
| `Compilation failed` error  | Corrupt YAML or missing dependency  | Check `node version`, run `compile-aig-data.mjs` directly |
| No changes detected         | AIG data hasn't changed             | Normal — use `--force` to re-test        |
| Watch mode crashes          | `recursive` watcher unsupported     | Use polling cron instead                 |
