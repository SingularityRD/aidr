# Gate verdicts at the last full rehearsal

Captured from the gate logs after `node scripts/run-evidence-gates.mjs`.
Each row is the exit code the gate itself wrote as its terminal marker.
Another eleven declared gates had no captured log at this run, so they are
not listed; the index records them as `unknown` rather than guessing.

| Gate | Exit |
|---|---|
| `01-git-diff-check` | 0 |
| `02-feature-inventory` | 0 |
| `03-sales-gap-audit` | 0 |
| `04-next-agent-prompt` | 0 |
| `06-quality-static` | 0 |
| `07-audit-prod` | 0 |
| `08-supabase-check` | 0 |
| `09-verify-enforcement` | 0 |
| `10-verify-codex` | 0 |
| `13-build-release` | 0 |
| `14-node-contracts` | 0 |
| `15-aig-pytest` | 0 |
| `16-support-bundle` | 0 |
| `18-native-host` | 1 |
| `19-release-e2e` | 1 |
| `20-customer-kit` | 0 |
| `20-release-bundle` | 0 |
| `21-aig-verify` | 0 |
| `22-e2e-negative` | 0 |
| `23-fleet` | 0 |
| `24-monitoring-and-upgrade` | 0 |
| `26-generator-determinism` | 0 |
| `27-empty-path-package-install` | 0 |
| `28-interception-matrix` | 0 |
| `29-repo-hygiene` | 0 |
| `30-commercial-gates` | 0 |
| `run-12-coverage` | 0 |

Totals: 25 pass, 2 non-zero.
