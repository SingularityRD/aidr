# Native host scenario manifests

This directory holds the **per-host scenario manifests** that drive a real,
installed host binary (Claude Code, Cursor, VS Code, OpenClaw, OpenCode, Codex)
through the seven native acceptance cases. It is consumed by two runners:

| Runner | What it does | Manifest it looks for |
| --- | --- | --- |
| `scripts/verify-native-host-matrix-v6.mjs` | The native-host gate. Probes host binaries, runs the cases of a single manifest (`hosts` keyed by host id) and reports one record per host. | `--scenario-file <path>`, otherwise the committed default `deploy/native/scenarios/native-host-scenarios.json` |
| `deploy/native/run-support-matrix.mjs` | Reads `deploy/native/support-matrix.json`, probes every advertised host and runs each connector's own manifest. | `deploy/native/scenarios/<connector>.json` (for example `codex.json`), or — with `--scenario-file <path>` — one explicit manifest for the rows whose connector it declares |

## This directory is not evidence

`TEMPLATE.json` is the only manifest committed here on purpose. It is a **schema
template**: every value that can only come from a real host run is the literal
placeholder `REPLACE_WITH_...`. Nothing in this directory was produced by
running a host, and **a template is never acceptance evidence** — not when
`--validate-only` accepts it, not when the gate probes it, not when a reviewer
reads it. Copying `TEMPLATE.json` into place and deleting `template`/`kind`
changes the *validation severity* of its placeholders; it does not create a
single observation, digest or owner name. Both the gate and the support-matrix
runner therefore refuse that copy with `SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE`.

## Commands

```bash
# Gate. Exits 1 while no named accepted-host record exists.
pnpm verify:native-host

# Structure validation only. Not host acceptance, and it prints no PASS.
pnpm verify:native-host:validate
node scripts/verify-native-host-matrix-v6.mjs --scenario-file deploy/native/scenarios/TEMPLATE.json --validate-only

# Inventory only: probe installed host versions, run nothing. Exit code 0.
node scripts/verify-native-host-matrix-v6.mjs --probe-only

# Run a filled-in manifest for one host.
node scripts/verify-native-host-matrix-v6.mjs --scenario-file deploy/native/scenarios/codex.json --output .release-evidence/v8-native-codex.json
```

Exit codes: `0` — inventory (`--probe-only`) or a structurally valid
`--validate-only` input; `1` — the gate is `NO_GO`, or the manifest is
structurally invalid; `2` — the manifest could not be read/parsed, or a case
tried to forge acceptance evidence (for example a fixture that pre-creates the
side-effect marker or an observation file).

## Status vocabulary

The gate prints one aggregate `status`, one `gate` decision and one status per
host. `status_vocabulary` in the JSON report always lists all six values.

| Status | Meaning | Requires a real host run? |
| --- | --- | --- |
| `SCENARIO_MANIFEST_MISSING` | No `--scenario-file` was given and the committed default manifest does not exist, so the per-host matrix could not be exercised. Repository state, not a host result. | **Yes, to clear it** — only a real host run can produce a manifest worth committing |
| `HOST_UNAVAILABLE` | A manifest exists but the host binary is not installed on this machine. | Yes — the row can only be exercised on a machine where that host is installed |
| `VERSION_PROBED` | `--probe-only` inventory: the version string was read. Nothing was exercised. | Yes, for `HOST_ACCEPTANCE_OPEN` and above; the probe alone needs only the installed binary |
| `HOST_ACCEPTANCE_OPEN` | Scenarios ran (or failed) and/or the named `acceptance` record is still incomplete. | **Yes** |
| `LOCAL_SCENARIOS_COMPLETE_REVIEW_OPEN` | Every GA host passed every local case on this one OS/architecture, and the named acceptance record is complete. | **Yes** — plus independent trace collection and named review |
| `NO_GO` | The gate decision. It is emitted while any accepted-host record is missing, and is never `GO` on repository state alone. | **Yes** — `GO` requires a real host run per sold OS/architecture plus named external acceptance |

The gate never prints `PASS` for a host row and never exits `0` when no accepted
host exists. A case-level `PASS` means only that the declared attempt, hook and
side-effect observations matched for that one local case.

## Runner refusal codes (`deploy/native/run-support-matrix.mjs`)

The support-matrix runner refuses a manifest instead of launching it, and
records the refusal as both the row's `scenarios.status` and a
`<connector>:<code>` blocker:

| Code | Meaning |
| --- | --- |
| `SCENARIO_MANIFEST_MISSING` | No `deploy/native/scenarios/<connector>.json` is committed and no explicit `--scenario-file` matched this row. |
| `SCENARIO_MANIFEST_UNREADABLE` | The manifest exists but is not valid JSON, so nothing could be validated. |
| `SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE` | The manifest is `TEMPLATE.json`, a copy of it, or any manifest still carrying its `REPLACE_WITH_*` placeholders — with or without the `kind`/`template` markers that make it a declared template. |

A refused row stays `HOST_ACCEPTANCE_OPEN` and its `scenarios.exitCode` is
absent: it never becomes `SCENARIOS_PASSED_REVIEW_OPEN`, and the runner's
decision stays `NO-GO`.

## Manifest schema

```jsonc
{
  "schema_version": 1,                       // required, must be 1
  "kind": "aidr-native-host-scenario-template", // optional; marks a template
  "template": true,                          // optional; marks a template
  "hosts": {                                 // required, keyed by host id
    "codex": {                               // claude | cursor | vscode | opencode | openclaw | codex | sdk
      "binary": "REPLACE_WITH_HOST_BINARY_PATH",
      "version_args": ["REPLACE_WITH_HOST_VERSION_ARG"],
      "acceptance": { /* see below */ },
      "cases": [ /* see below */ ]
    }
  }
}
```

Host ids are exactly `claude`, `cursor`, `vscode`, `opencode`, `openclaw`,
`codex` and `sdk`. Any other key is a hard error. A host you do not list is
simply probed (and reported `HOST_UNAVAILABLE` when its binary is absent).

### Per-host fields

| Field | Required | Notes |
| --- | --- | --- |
| `binary` | Yes (except `sdk`) | Path to the launcher that was acceptance-tested. The runner prefers this value, then the host's environment override (`AIDR_CURSOR_PATH`, `AIDR_VSCODE_PATH`, `OPENCODE_E2E_BIN`), then `PATH`. |
| `version_args` | No | Arguments used for the version probe. Defaults to `["--version"]`. Each entry must be a string shorter than 100 characters. The probed version must equal `acceptance.host_version`. |
| `acceptance` | Yes | Named acceptance record, see below. |
| `cases` | Yes | Non-empty array of cases, see below. |

### `acceptance` block

Every field below is required. Values that must come from a real host run are
placeholders in the template and must be replaced verbatim from that run.

| Field | Required | Notes |
| --- | --- | --- |
| `os_platform` | Yes | Must equal `process.platform` of the acceptance machine (`win32`, `linux`, `darwin`). A mismatch is an `UNPINNED_OR_MISMATCHED_OS_PLATFORM` blocker. |
| `os_release` | Yes | Must equal the acceptance machine's `os.release()`. |
| `architecture` | Yes | Must equal `process.arch` (`x64`, `arm64`). |
| `host_version` | Yes | Must equal the version string the probe reads from this `binary` with `version_args`. |
| `launcher_sha256` | Yes | SHA-256 (lowercase hex, 64 chars) of the launcher file at `binary`. A `.ps1`/`.cmd` shim digest does not identify the installed package underneath it. |
| `candidate_sha256` | Yes | SHA-256 of the accepted candidate artifact. |
| `policy_sha256` | Yes | SHA-256 of the effective policy used during the run. |
| `install_evidence_sha256` | Yes | SHA-256 of the install evidence file. |
| `uninstall_evidence_sha256` | Yes | SHA-256 of the uninstall evidence file. |
| `qa_owner` | Yes | Named accountable person (at least 3 characters). |
| `endpoint_owner` | Yes | Named accountable person. |
| `support_owner` | Yes | Named accountable person. |
| `unobserved_actions` | Yes | Array of strings. **Empty means everything was observed**; a non-empty list is reported as `UNOBSERVED_ACTIONS_REMAIN`. |
| `required_attack_ids` | Yes | Non-empty array of threat ids (`^[a-z0-9][a-z0-9_.-]{0,100}$`, unique). For each id the report requires a `denied_side_effect` case **and** a `benign_allow` case carrying that same `attack_id` and passing. One generic attack case cannot stand for a whole attack family. |

### `cases` array

| Field | Required | Notes |
| --- | --- | --- |
| `id` | Yes | One of `denied_side_effect`, `benign_allow`, `disabled_hook`, `crash`, `timeout`, `offline`, `restart`. An unknown id fails validation. |
| `attack_id` | No | Threat id this case exercises (`^[a-z0-9][a-z0-9_.-]{0,100}$`). The pair `id:attack_id` must be unique inside a host — two `denied_side_effect` cases for the same attack id are a duplicate. |
| `argv` | Yes | Array of strings. The **first entry must be exactly `{host_binary}`** so the gate launches the probed launcher; the rest are interpolated and appended. |
| `attempt` | Yes | Observation proving the host actually attempted the tool call. |
| `hook` | Yes | Observation proving the connector was invoked. |
| `condition` | No | Observation of the injected fault (`disabled_hook`, `crash`, `timeout`, `offline`, `restart`). Cases that declare one of those ids cannot pass without an observed condition. |
| `boundary` | No | Independent observation of the enforcement boundary claim for the fault cases. |
| `files` | No | Array (max 20) of `{ "path": "...", "content": "..." }` fixtures created before the host starts. A fixture may not pre-create the side-effect marker, the hook receipt, or any observation path. |
| `env` | No | Object of environment overrides for the host process: uppercase `A-Z0-9_` keys, values up to 2000 characters. `HOME`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `PATH`, `NODE_OPTIONS` and `AIDR_NATIVE_TEST_*` may not be overridden. |
| `expected_exit_code` | No | Integer compared with the host process exit code; a mismatch is reported as `EXIT_MISMATCH`. |
| `timeout_ms` | No | Integer between 1000 and 180000 (default 90000). |
| `inherit_host_profile` | No | Boolean. `true` runs the host against the operator's real profile instead of the disposable one; `false`/absent uses the disposable workspace. |

### Observation objects

`attempt`, `hook`, `condition` and `boundary` share one shape:

```json
{ "source": "file", "path": "{workspace}/attempt.log", "contains": "ATTEMPT:{case_nonce}" }
```

| Field | Required | Notes |
| --- | --- | --- |
| `source` | Yes | `stdout`, `stderr` or `file`. `stdout`/`stderr` read the host process output; `file` reads a file inside the disposable workspace. |
| `contains` | Yes | Non-empty marker string (max 200 characters) that must appear in the observed content. Interpolated before matching. |
| `path` | When `source` is `file` | Path that must resolve inside the disposable workspace. |

Interpolation variables available in `argv`, `env`, `files` and observations:

| Variable | Value |
| --- | --- |
| `{host_binary}` | The probed launcher path (required as `argv[0]`) |
| `{workspace}` | The disposable per-case workspace directory |
| `{home}` | A disposable `HOME`/`USERPROFILE` inside the workspace |
| `{sentinel}` | Side-effect marker file the case must *not* create unless the case is `benign_allow` |
| `{receipt}` | Hook receipt file the connector writes when it is invoked |
| `{case_nonce}` | A fresh UUID for the case; include it in every file observation so traces can be correlated |

## Placeholder convention

Any value that must come from a real host run is written as the literal string
`REPLACE_WITH_<FIELD_IN_UPPER_SNAKE>`, for example
`"candidate_sha256": "REPLACE_WITH_CANDIDATE_ARTIFACT_SHA256"`. Do not invent a
version, digest, owner name or acceptance record to fill the gap.

A manifest that declares itself a template (`"template": true` or
`"kind": "aidr-native-host-scenario-template"`) reports these values as
`placeholder` findings, so the template itself is structurally valid. In a
manifest that does **not** declare itself a template, every placeholder is an
`error` and the file fails validation — an accepted manifest may not ship an
unfilled or invented value.

## Validation findings

`--validate-only` reports every violation with a stable `code`, the JSON `path`
of the offending value, and — for manifests that are not templates — an
`error` severity. It never throws on a readable file and never launches a host.

| Code | Detects |
| --- | --- |
| `MANIFEST_NOT_OBJECT`, `SCHEMA_VERSION_UNSUPPORTED`, `HOSTS_MISSING`, `HOSTS_NOT_OBJECT`, `HOSTS_EMPTY` | Manifest envelope problems |
| `UNKNOWN_HOST`, `HOST_CONFIG_NOT_OBJECT`, `HOST_BINARY_MISSING`, `HOST_VERSION_ARGS_INVALID` | Per-host problems |
| `HOST_CASES_MISSING`, `HOST_CASES_NOT_ARRAY`, `CASE_NOT_OBJECT`, `CASE_ID_MISSING` | Missing or malformed case list |
| `UNKNOWN_CASE_ID` | A case `id` outside the seven-case vocabulary |
| `DUPLICATE_CASE_ID_ATTACK_PAIR` | The same `id:attack_id` pair declared twice in one host |
| `CASE_ATTACK_ID_INVALID` | Malformed threat id |
| `CASE_ARGV_INVALID`, `CASE_ARGV_MUST_START_WITH_HOST_BINARY`, `CASE_ARGV_ENTRY_INVALID` | `argv` missing, not starting with `{host_binary}`, or holding a bad entry |
| `ATTEMPT_OBSERVATION_MISSING`, `HOOK_OBSERVATION_MISSING` | The mandatory attempt or hook observation is absent |
| `*_OBSERVATION_NOT_OBJECT`, `*_OBSERVATION_SOURCE_INVALID`, `*_OBSERVATION_CONTAINS_INVALID`, `*_OBSERVATION_PATH_MISSING` | Malformed `attempt`/`hook`/`condition`/`boundary` observation |
| `CASE_TIMEOUT_MS_INVALID`, `CASE_EXPECTED_EXIT_CODE_INVALID` | Out-of-range or non-integer numeric fields |
| `CASE_FILES_INVALID`, `CASE_FILE_INVALID`, `CASE_FILE_PATH_INVALID`, `CASE_FILE_CONTENT_INVALID` | Malformed fixtures |
| `CASE_ENV_INVALID`, `CASE_ENV_KEY_INVALID`, `CASE_ENV_VALUE_INVALID` | Malformed environment overrides |
| `ACCEPTANCE_BLOCK_MISSING`, `ACCEPTANCE_BLOCK_NOT_OBJECT` | Acceptance record absent or malformed |
| `ACCEPTANCE_FIELD_MISSING` | A required `acceptance` field is absent (the `field` property names it) |
| `ACCEPTANCE_FIELD_INVALID` | A pinned runtime field is not a non-empty string |
| `ACCEPTANCE_SHA256_INVALID` | A `*_sha256` field is not lowercase 64-character hex |
| `ACCEPTANCE_OWNER_INVALID` | A named owner is shorter than 3 characters |
| `ACCEPTANCE_ARRAY_INVALID`, `ACCEPTANCE_ATTACK_ID_INVALID`, `ACCEPTANCE_ARRAY_DUPLICATE` | `unobserved_actions` is not an array, or `required_attack_ids` is empty, malformed or duplicated |
| `PLACEHOLDER_VALUE_UNREPLACED` | A `REPLACE_WITH_*` value is still in place (`placeholder` severity in a template, `error` anywhere else) |

## Filling in the template

1. Install the connector on a disposable machine and complete a real run of all
   seven cases for that host.
2. Copy `TEMPLATE.json`, keep one host block per host you actually exercised,
   and replace every `REPLACE_WITH_*` value with what the run produced.
3. Delete `kind`/`template` so the placeholders become hard errors, then run
   `node scripts/verify-native-host-matrix-v6.mjs --scenario-file <your file> --validate-only`.
4. Run the gate against the filled manifest and record the report. Expect
   `NO_GO`: local scenarios can raise a host row to
   `LOCAL_SCENARIOS_COMPLETE_REVIEW_OPEN` at most. Independent trace collection,
   the sold OS/architecture matrix and named external acceptance remain outside
   what this repository can produce.
