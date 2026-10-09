---
"@singularityrd/aidr-core": patch
"@singularityrd/aidr-claude-code": patch
"@singularityrd/aidr-codex": patch
"@singularityrd/aidr-openclaw": patch
"aidr-cursor": patch
---

- The Windows native AMSI backend now uses koffi 3 (3.3.2). The vendored `dist/vendor/koffi` payload carries koffi's loader under `lib/koffi/` and the `win32_x64`, `win32_arm64` and `win32_ia32` builds from koffi 3's `@koromix/koffi-win32-*` packages. The staged loader only loads those bundled binaries, never a copy from a surrounding `node_modules`.
