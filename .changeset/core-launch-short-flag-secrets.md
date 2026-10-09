---
"@singularityrd/aidr-core": patch
---

- AI-BOM and MCP discovery now redact the value of short flags that carry a secret: `-p <password>` / `-P <password>` (except for docker, podman, node, kubectl, ssh and similar, where `-p` is a port, package or print flag), `curl -u` / `--user`, `redis-cli -a`, and mysql-family `-p<password>`. The command that owns the flag is resolved through `env`, `sudo`, `npx`, `uvx` and similar launchers.
