---
"@singularityrd/aidr-core": patch
"@singularityrd/aidr-claude-code": patch
"@singularityrd/aidr-codex": patch
"aidr-cursor": patch
---

- Per-call hooks now reuse Node's on-disk V8 compile cache, which makes every call after a user's first about 55 ms (11%) faster at p50 on Linux. This covers the Claude Code `pre-tool-use`, `post-tool-use`, `user-prompt-submit` and `session-start` hooks, the Codex `aidr-codex-hook`, and the Cursor/VS Code `aidr-hook`.
- `dist/<hook>.cjs` keeps its name and is now a small bootstrap that requires `dist/<hook>.bundle.cjs`. The two files must ship and be copied together.
- The cache is kept in the private `~/.singularity-aidr/compile-cache` directory: 0700 and owner-checked on POSIX, with a protected ACL on Windows.
- The cache is off by default on Windows. `AIDR_ENABLE_COMPILE_CACHE=1` turns it on there.
- `AIDR_DISABLE_COMPILE_CACHE=1` turns it off on every platform.
- If the cache cannot be enabled, the verdict is unchanged.
- A hook bundle that cannot be loaded now blocks with exit 2 instead of crashing with exit 1, which hosts treat as non-blocking.
