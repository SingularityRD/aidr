---
"@singularityrd/aidr-mcp-gateway": minor
---

- `tools/call` arguments are normalised to `mcp__<server>__<tool>` and checked by the core evaluator before they reach the upstream server. The check covers threat rules, the allowlist, policy and optional per-server tenant DLP. A deny becomes `arguments_blocked`. An ask becomes `approval_required`, blocked until an operator acts out of band. An evaluator failure becomes `detection_unavailable`.
- Image, audio and resource blobs are inspected within fixed bounds: MIME allowlist, canonical base64, decoded-size limit, magic bytes and printable-run scanning. Before, the gateway refused them all as `unsupported_binary_output`.
- Server-initiated sampling, elicitation, roots and notifications follow a configurable `deny|ignore` policy (default `deny`). Those client capabilities are removed from the forwarded `initialize`.
- The bundles embed the threat and trusted-domain rules. The CLIs print sanitised `<stage>[:<detail>]` reason codes and exit with 1, or 2 for usage errors.
