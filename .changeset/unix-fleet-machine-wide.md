---
"@singularityrd/aidr-cli": patch
"@singularityrd/aidr-core": patch
---

Unix fleet delivery installs machine-wide. `deploy/fleet/unix/aidr-fleet.sh` (Linux scripts, the macOS PKG postinstall and the Jamf policy) now stages the signed standalone (SEA) bundle in the root-owned release store and registers it for every user through `aidr machine-hooks install` (Claude Code managed settings, Codex system config), so the endpoint needs no Node.js and users cannot edit the hooks away. It writes the machine policy (`control_plane_url`, `enrollment_key`, `protection_locked`) when given, keeps the "only managed hooks" choice across upgrade and rollback, and the per-user npm path stays available with `--user`. `aidr machine-hooks install` now verifies the bundle against its manifest (and the release key next to it) before writing any host policy, and macOS reads the machine policy from `/etc/singularity-aidr/managed.json` like Linux.
