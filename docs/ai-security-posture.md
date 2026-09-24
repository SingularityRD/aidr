# AI Security Posture

The posture view answers three questions for a team: which AI infrastructure is
exposed to known vulnerabilities, which MCP servers are configured and how risky
they are, and which skill or plugin packages contain dangerous patterns. It is
built from three deterministic, local scanners whose findings can be uploaded to
the managed control plane and reviewed on the dashboard's **Posture** page
(`/posture`).

Everything here is detection, not enforcement. Runtime allow/ask/deny decisions
for agent tool calls are unchanged; the skill-scan rules use `match_on` values
the runtime engine never evaluates.

## Scanners

| Scanner | Command | What it checks | Data source |
|---|---|---|---|
| Infrastructure exposure | `aidr scan --target <url>` / `--file targets.txt` | Fingerprints AI services (Ollama, vLLM, ComfyUI, Gradio, …), extracts versions and matches CVEs/advisories | Compiled AI-Infra-Guard fingerprints and CVE index (`packages/core/src/generated/`) |
| MCP inventory | `aidr discover [--config <path>…]` | Local MCP configurations: server names, transport, risk indicators, tool-manifest attestation status | Local JSON/JSONC configs; AIG MCP categories |
| Skill / plugin packages | `aidr scan --skill <dir>` (and every session-start plugin scan) | AIG Skill-Scan T01–T09 taxonomy as deterministic rules | `threats/skill-scan.yaml` |

`aidr scan --target` only contacts loopback/private targets unless
`--allow-public` is given. A target that could not be reached or identified is
reported as *not scanned*, never as clean. A package path that does not exist,
or files that could not be read, are reported as incomplete coverage and make
the command exit `1`. Critical or high findings exit `2` for CI use.

## Skill-scan rules (T01–T09)

The AI-Infra-Guard Skill-Scan combines an LLM audit with a regex pre-scan. AIDR
ships the deterministic part only, as reviewable data in
`threats/skill-scan.yaml` (rule ids `SKILL-Txx-nnn`):

| Code | Category | Examples of what the rules match |
|---|---|---|
| T01 | Skill instruction hijacking | "ignore previous instructions", "do not tell the user", agent-directed HTML comments, zero-width / Unicode tag characters, bidirectional control characters |
| T02 | Agent memory poisoning | writes to `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, agent memory; "remember these rules for all future sessions" |
| T03 | Remote payload retrieval and execution | `curl … \| sh`, PowerShell `iex (New-Object Net.WebClient)…`, `exec(requests.get(…))` |
| T04 | Embedded malicious code | Python bytecode without its `.py` source, decode-then-exec, reverse shells, credential files or secret env values sent over the network |
| T05 | Unauthorized access / privilege escalation | `--dangerously-skip-permissions`, `bypassPermissions`, unrestricted `Bash(*)` / `*` tool grants, `sudo chmod`, setuid, cloud metadata endpoint |
| T06 | System persistence | crontab, systemd/launchd/schtasks registration, appends to shell startup files |
| T07 | Tool hijacking and spoofing | aliases shadowing `git`/`npm`/…, writable PATH prefixes, rewriting agent hook/MCP/permission config |
| T08 | Insecure dependencies | plain-HTTP or `--trusted-host` package indexes, direct archive URLs |
| T09 | Insecure coding practices | hard-coded credentials (reported as a digest, never echoed), `shell=True`, disabled TLS verification |

Bytecode inside `__pycache__` next to its source is the interpreter's normal
cache and is not a finding. Every pattern is bounded and tested against a 512 KB
adversarial input per rule, and against the benign benchmark corpus.

A finding means a pattern matched; it is not a semantic judgement of intent. No
match means only that none of these rules matched.

## Uploading findings

```bash
aidr scan --target http://10.0.0.5:11434 --upload
aidr scan --skill ~/.claude/skills/my-skill --upload
aidr discover --upload
```

`--upload` sends the findings to `/v1/ingest` with this installation's
**enrolled API key** (`auth.api_key`, or the key a connector obtained during
enrollment). An enrollment token alone is not used. The upload fails with a
named reason and a non-zero exit when the control plane is disabled or not
configured, the endpoint is not HTTPS, the installation is not enrolled, sync
has been disabled for it, or the tenant is not admitted. Batches that could not
be delivered stay in the durable telemetry queue and are retried on the next
delivery from this installation.

### What leaves the machine

| Event type | Fields |
|---|---|
| `infra_scan_finding` | CVE/GHSA id (free-text AIG advisory titles are omitted), severity, CVSS, component name and version, applicability (`confirmed`/`unconfirmed`), sha256 digest of the target origin |
| `mcp_inventory_finding` | server name (omitted when credential-shaped), transport, risk categories (`remote_mcp_url`, `shell_wrapper_command`, `broad_filesystem_access_arg`, AIG `mcp-01`…`mcp-14`), attestation status, digests of the inventory id and configuration |
| `plugin_scan_finding` | plugin key and version, rule id, T01–T09 code, severity, digest of the plugin-relative file path |

Never uploaded: target URLs and hostnames, file paths, matched text, MCP
commands, arguments, headers, environment, endpoints, and credentials. The
client projection (`packages/core/src/posture-events.ts`) and the server
projection (`supabase/functions/ingest/posture.ts`) validate every field
independently; unknown fields and out-of-shape values are dropped.

## Storage, access and retention

Accepted events are stored in `public.events` and projected by a database
trigger into `public.posture_findings`
(`supabase/migrations/20260925000050_posture_findings.sql`):

- **Access** — row-level security limits reads to active members of the tenant
  (`app.is_tenant_member`). Browser roles cannot insert, update or delete; only
  the ingest projection writes rows.
- **Retention** — each row references its source event with `ON DELETE CASCADE`,
  so the tenant's telemetry retention policy
  (`prune_expired_telemetry_events`) and legal holds apply unchanged.
- **Offboarding** — the offboarding `events` phase removes the rows by cascade.
  A residue guard refuses to close a tenant or complete an offboarding run while
  any posture row remains.

## Dashboard

The **Posture** page shows, for the last 90 days:

- infrastructure CVEs grouped by vulnerability and component, ordered by
  severity then CVSS, with the number of distinct targets and applicability;
- MCP servers with transport, risk categories and attestation status;
- skill/plugin findings with the T01–T09 category;
- a 30-day trend of findings reported per day.

Tables show the latest observation of each distinct finding; the trend counts
every upload. When nothing has been uploaded the page says so and shows the
commands above — an empty posture is never presented as a clean environment. If
the data cannot be read, the page shows an error instead of an empty state.

## Limitations

- The infrastructure scan covers only the compiled AI-Infra-Guard fingerprint
  and CVE dataset, and only reachable targets that were identified.
- MCP discovery reads local configuration files; it is not cloud-wide discovery.
  AIG MCP categories for a server are suggested from its name.
- Skill rules are deterministic patterns. The LLM-based review stage of
  AI-Infra-Guard Skill-Scan is not part of AIDR.
- Findings reflect what was uploaded; a resolved issue remains visible until it
  ages out of the 90-day window or the tenant's telemetry retention removes it.
