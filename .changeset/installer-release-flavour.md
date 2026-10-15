---
"@singularityrd/aidr-cli": minor
"@singularityrd/aidr-core": patch
"@singularityrd/aidr-claude-code": patch
"@singularityrd/aidr-codex": patch
---

The desktop installers ship the release-flavour standalone bundle: one multi-call `aidr` binary (`aidr hook <name>`, or a hook-named link) replaces the seven per-hook binaries (~150 MB instead of ~900 MB), and carries a runtime manifest (`dist/aidr-artifact.manifest.json`, `sea/dist`) that the hooks verify on every call. `build-sea.mjs` adds `--flavor release`, `--sign`, `--add-extensions` and `--verify --public-key`; release CI signs both bundle manifests between the bundle build and packaging.

`aidr setup` sets up the release public key the installer ships (`integrity.public_keys_pem`; a different operator key is kept unless `--force`), and the new `aidr setup --release-key <file.pem>` does so for a manual install after operator confirmation, printing the key's fingerprint. From the bundle it also registers the Codex hook and installs the bundled Cursor / VS Code extensions. A release hook without its key blocks every call with a message naming the fix. `aidr setup` exits 3 (not 1) when no supported AI tool is installed yet; the Linux package hook says so instead of reporting a failure. The installer builders accept an optional `aidr update` catalog key.
