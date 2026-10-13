---
"@singularityrd/aidr-cli": minor
"@singularityrd/aidr-claude-code": patch
---

Desktop installers (Windows MSI, Linux .deb/.rpm/tarball) built from the standalone SEA bundle, which now also carries the `aidr` CLI (`build-sea.mjs` adds `--out`, `--prebuilt` and `--remanifest`).

When `aidr setup` runs from that bundle it registers the bundle's Claude Code hook binaries itself, after checking every bundle file against its manifest and passing a deny canary through the PreToolUse binary; `aidr uninstall` accepts the resulting `sea_bundle` receipt. `aidr status` now ends with a one-line verdict (protected hosts, hosts to restart, hosts needing a manual step with the exact command; English and Turkish), and the new `aidr verify` passes a harmless canary and a benign twin through each registered connector's real hook entry point and reports PASS / FAIL / SKIP per host.
