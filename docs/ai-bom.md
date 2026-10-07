# AI-BOM (AI Bill of Materials)

The AI-BOM is an exportable inventory of the AI components in use: the agents
on a machine and whether Singularity AIDR protects them, the MCP servers those
agents are configured to call, the AI SDKs, frameworks, runtimes and models a
project depends on, the installed skills and plugins, and the known
vulnerabilities found in any of them. It is written as a
[CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/) JSON document, so it can
be loaded into SBOM tooling, a GRC system or a procurement questionnaire as is.

There are two exports:

| Export | Scope | Where |
|---|---|---|
| `aidr aibom` | One project on one machine | CLI, fully local; nothing is uploaded |
| **Export AI-BOM** | The whole tenant, as reported to the control plane | Dashboard → **Posture** page |

## CLI: `aidr aibom`

```sh
aidr aibom                                   # CycloneDX 1.6 JSON on stdout, current directory
aidr aibom --path ~/src/support-agent -o support-agent.cdx.json
aidr aibom --format json                     # the AIDR inventory the BOM is rendered from
aidr aibom --config ~/.cursor/mcp.json       # explicit MCP configuration files
aidr aibom --scan-report infra-scan.json     # include a saved `aidr scan --save-report`
```

| Option | Meaning |
|---|---|
| `--format cyclonedx-json\|json` | CycloneDX 1.6 (default) or the AIDR inventory (`aidr-ai-inventory/v1`, snake_case) |
| `-o, --output <file>` | Write to a **new** file created with mode `0600`; an existing file is never overwritten |
| `--path <project>` | Project whose manifests and project-level MCP configurations are read (default: current directory) |
| `--config <paths…>` | MCP configuration files to read instead of the defaults |
| `--scan-report <path>` | Saved infrastructure scan to include. Without it, the report configured for the AI infrastructure policy (`policy.ai_infrastructure.report_path`) is used when that policy is enabled |

The command exits `0` when every source was read, and `1` when the BOM was
produced but is incomplete: an MCP configuration or a project manifest could not
be parsed, the model-file search hit its bound, or the requested scan report is
missing or invalid. Each gap is printed on stderr and recorded in the BOM's
`metadata.properties` (`aidr:coverage:*`), so an incomplete inventory is never
presented as a complete one.

### What is collected

Every source reuses an existing AIDR discovery path; nothing is executed and no
network request is made.

| Source | Collected from | CycloneDX |
|---|---|---|
| Agents | The same connector detection as `aidr status` (Claude Code, Cursor, VS Code, OpenClaw, OpenCode, Codex). An agent whose runtime is present but not protected is listed with `aidr:agent:protection_state = runtime_present_not_installed` | `components[]`, `type: application` |
| MCP servers | The same inventory as `aidr discover`: the default agent configuration files (home and project) or `--config`. Transport, endpoint origin, redacted command line, configuration digest, tool-manifest attestation status, risk indicators and all **14 MCP risk categories** as `aidr:mcp:risk:mcp-01`…`mcp-14` = `true`/`false` | `services[]`; remote servers carry `endpoints` and `x-trust-boundary: true` |
| AI packages | `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `requirements*.txt`, `pyproject.toml` (PEP 621, PEP 735, Poetry), `Pipfile`, `poetry.lock`, `uv.lock` in the project root, matched against a data file of AI SDKs, frameworks, inference runtimes, vector stores and packaged models | `components[]` with a `purl`; `library`, `framework`, `application` or `machine-learning-model` |
| Model files | Weight files (`.gguf`, `.safetensors`, `.onnx`, `.pt`, `.ckpt`, …) under the project, without following symlinks | `components[]`, `type: machine-learning-model` |
| Skills / plugins | The Claude Code plugin registry and the results cached by the session-start plugin scan. A plugin that has not been scanned is marked `aidr:plugin:scan_status = not_scanned` | `components[]`, `type: library` |
| AI infrastructure | A saved `aidr scan --target … --save-report` result: each scanned endpoint with the products and versions identified on it | `services[]` with `endpoints` |
| Vulnerabilities | CVEs of an exactly pinned or locked package version from the bundled AI Security Posture CVE index; CVEs and advisories from the infrastructure scan; skill-scan rule findings (T01–T09) from the plugin scan cache | `vulnerabilities[]` with `ratings` and `affects` |

`dependencies` link the project to its components and each agent to the MCP
servers in its configuration files and (for Claude Code) its plugins.

The AI package list is data, not code:
`packages/core/src/aibom/ai-component-catalog.json`. An entry names the
ecosystem (`npm` or `pypi`), the package (exact or prefix match), the CycloneDX
component type, a category and, only where the package's own release numbers
match the CVE index product, the index product to check it against. A package
declared with a range (`^1.2.0`, `>=0.5`) and no lockfile is listed without a
version and marked `aidr:vulnerability_check = not_evaluated_unpinned`: no CVE
match is guessed from a range.

### What is never included

- environment variables, headers and any other part of an MCP configuration
  other than the command, arguments and URL;
- credentials inside the command line: the value after a credential-named flag
  (`--token X`, `--api-key=X`), after a header flag (`-H X`), of `NAME=value`
  when the name says key/token/secret/password, URL user-info, query strings and
  fragments, bearer tokens, JWTs, well-known token formats and long opaque
  tokens are all replaced with `[Redacted]`;
- remote MCP URLs beyond their origin;
- the text a skill-scan rule matched and the file it matched in;
- the home directory, which is shown as `~`.

## Dashboard: Export AI-BOM

The **Export AI-BOM** button on the **Posture** page builds a tenant-level
CycloneDX 1.6 document in the browser from data the dashboard already has:

- fleet check-ins (`agents`), one component per agent runtime and version with
  the number of devices and the latest check-in;
- the latest observation of every posture finding in the posture window:
  MCP servers with their 14 risk-category flags, AI infrastructure components,
  skills/plugins, and their CVEs, advisories and skill rule findings.

Only uploaded identifiers, versions, severities, counts and digests exist in
the control plane (see [AI Security Posture](ai-security-posture.md)), so the
tenant BOM contains no hosts, paths, arguments or matched text. If the fleet
inventory cannot be read, no file is produced. If the posture query reached its
row limit, the BOM records `aidr:posture:truncated = true`.

## Validation

Both exports were checked against the official CycloneDX 1.6 JSON schema
(`bom-1.6.schema.json`). Unit tests cover the document shape, bom-ref
uniqueness and reference integrity, deterministic ordering, redaction,
de-duplication and the vulnerability mapping:
`packages/core/src/__tests__/aibom.test.ts`,
`packages/cli/src/__tests__/aibom.test.ts` and
`packages/dashboard/src/__tests__/aibom-export.test.tsx`.

## Limits

- Project manifests are read from the project root only; nested workspaces are
  not walked. Lockfiles resolve versions of declared AI dependencies; packages
  that appear only in a lockfile (transitive dependencies) are not listed.
- Only npm and PyPI manifests are recognised. Other ecosystems are not reported.
- MCP risk categories are assigned from the server name, the same
  classification the posture upload uses; they are indicators, not a verdict.
- Model files are listed by name, format and size; they are not hashed.
- CVE matching uses the bundled CVE index. A component the index does not cover
  is marked `aidr:vulnerability_check = not_in_cve_index`, which does not mean
  it has no vulnerabilities.
