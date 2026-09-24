# Architecture

Singularity AIDR is a TypeScript monorepo with a shared core library and platform-specific connectors.

## Packages

```
packages/
├── core/          @singularityrd/aidr-core         Platform-agnostic detection engine
├── claude-code/   @singularityrd/aidr-claude-code   Claude Code hook entry points
├── openclaw/      @singularityrd/aidr-openclaw       OpenClaw plugin connector
├── opencode/      @singularityrd/aidr-opencode       OpenCode plugin connector
└── extension/     aidr-cursor                     Cursor and VS Code extensions (unscoped: vsce rejects @ and / in extension names)
```

### `@singularityrd/aidr-core`

The core library contains all detection logic. It has no platform dependencies and is imported by all connectors.

| Module | Purpose |
|--------|---------|
| `extractors.ts` | Extracts URLs, commands, file paths from tool inputs |
| `heuristics.ts` | Matches artifacts against YAML threat patterns |
| `engine.ts` | Decision engine - combines signals into a Verdict |
| `threat-loader.ts` | Loads YAML threat definitions |
| `config.ts` | Config loading and validation (Zod schemas) |
| `cache.ts` | JSON file verdict cache with TTLs |
| `allowlist.ts` | User allowlist management |
| `audit-log.ts` | JSONL audit logging |
| `trusted-domains.ts` | Trusted domain loading and matching |
| `plugin-scanner.ts` | Plugin file scanning |
| `package-checker.ts` | npm/PyPI supply-chain checks |
| `installation-id.ts` | Persistent installation UUID (`~/.singularity-aidr/installation-id`) |
| `version-check.ts` | Version check via POST with environment context |
| `session-start.ts` | Session start orchestrator (scan + version check) |
| `clients/url-check.ts` | URL reputation API client and endpoint resolver |
| `clients/file-check.ts` | File reputation API client |
| `clients/package-registry.ts` | npm/PyPI registry client |

### `@singularityrd/aidr-claude-code`

Two entry points, each bundled by esbuild into a single CJS file:

- **`pre-tool-use.ts`** - Reads tool call JSON from stdin, orchestrates core, outputs verdict JSON to stdout.
- **`session-start.ts`** - Scans installed plugins for threats.

Registered via `hooks/hooks.json`.

### `@singularityrd/aidr-openclaw` (OpenClaw)

In-process plugin using `api.on('before_tool_call')`. Includes:

- **`tool-handler.ts`** - Intercepts tool calls, runs detection pipeline
- **`allowlist-tools.ts`** - `aidr_allowlist_add` / `aidr_allowlist_remove`; adding refuses unless a genuine approval was already recorded
- **`approval-store.ts`** - Tracks per-session approvals (operator-held; deliberately **not** exposed to the agent as a tool)
- **`startup-scan.ts`** - Plugin scanning at gateway/session start

> There is deliberately no agent-callable approval tool. The model receives the
> `actionId` in the block reason, so an approval tool it could call would let a
> prompt-injected agent approve its own block.

### Extension (Cursor / VS Code)

VS Code API extension with platform-specific installers:

- **`shared_extension.ts`** - Registers commands: enable/disable protection, open config, show hook health
- **`cursor_hook_installer.ts`** / **`vscode_hook_installer.ts`** - Install managed hooks into Cursor or VS Code

## Data Flow

### Claude Code

```
Hook stdin (JSON) -> extract artifacts -> check allowlist -> check cache
  -> heuristics + URL check + package check -> DecisionEngine
  -> cache result -> audit log -> hook stdout (JSON)
```

Claude Code hooks exit 0. Errors return an `allow` verdict.

### OpenClaw

```
before_tool_call event -> extract artifacts -> check approval store
  -> check allowlist -> check cache -> heuristics + URL check + package check
  -> DecisionEngine -> cache result -> audit log -> block/pass
```

Blocked actions return an `actionId` as an **operator-only reference**. There is no
agent-callable approval tool: approval is an out-of-band, human-only action taken
through the operator-held approval store or the on-disk allowlist.

### Cursor / VS Code

```
Managed hook intercepts tool call -> spawns aidr-hook.cjs subprocess
  -> extract artifacts -> check allowlist -> check cache
  -> heuristics + URL check + package check -> DecisionEngine
  -> cache result -> audit log -> return verdict
```

Extension hooks (Cursor / VS Code) always exit with code `0`; the host reads the JSON response to enforce blocking.

## Key Design Decisions

- **All patterns are data.** Detection rules live in `threats/*.yaml`, not in code. This makes rules easy to review, contribute, and update independently.
- **Failure policy is scoped.** Connector entry points return a deny on their own parse or evaluation failures; mandatory identity, tenant, and rate-limit controls also reject unavailable state. Optional detection legs report unavailability instead of claiming a clean scan. A host that never invokes a hook, kills it before it emits a verdict, or permits a bypass remains outside the connector's enforcement guarantee; Codex has an explicit host-owned fail-open boundary.
- **Inspection limits fail closed.** Extraction never silently stops part-way. Free text (file content of `Write`/`Edit`/`Read`, and free-text strings of MCP/unknown tools) longer than 64 KiB is scanned in full as overlapping 64 KiB windows. Anything the extractor cannot cover is denied with category `input_not_fully_inspected` (`POL-INPUT-003`): MCP/unknown tool input nested deeper than 16 levels, with more than 1024 strings or 2048 artifacts, a command/URL/path field over 64 KiB, or more than 4 MiB of text in one call (including file content over 4 MiB). A `Bash` command over 64 KiB is denied as `input_truncated`. MCP tool input is re-walked by the evaluator, so a connector that builds its own artifact list cannot drop the signal.
- **Shared core.** All platforms use the same `@singularityrd/aidr-core` library, ensuring consistent detection regardless of connector.
- **Packaged runtime dependencies are connector-specific.** The core uses native `fetch`, `yaml` for YAML parsing, and `zod` for validation. JavaScript connector code is bundled; Windows AMSI may also need a packaged native Koffi module or the slower PowerShell fallback. Inspect the exact released artifact and host before claiming a standalone installation.



