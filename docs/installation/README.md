# Installation guides

[Türkçe](README.tr.md)

Start with the [Quickstart](../quickstart.md): one page from zero to protected for each
role. The guides below go into detail. Singularity AIDR is not yet released for customer
use; see [Release status](../../README.md#release-status).

## Developer (AI coding tools on a laptop)

| Guide | Covers |
|---|---|
| [Desktop installers](desktop-installers.md) | Windows MSI and Linux .deb / .rpm / tarball from the dashboard Downloads page, `aidr status`, `aidr verify`, uninstall, troubleshooting. macOS installers are not offered yet. |
| [Getting Started](../getting-started.md) | Per-tool connector packages (Claude Code, Cursor, VS Code, OpenClaw, OpenCode, Codex) for tools and systems the installers do not cover, including macOS |
| [Package Installation](../package-installation.md) | Private-registry access and version-pinned package installs |
| [Integrity verification](../integrity.md) | The release key that connector packages need before they start (the desktop installers already contain it) |
| Platform guides | [Claude Code](../platform-guides/claude-code.md) · [Cursor / VS Code](../platform-guides/cursor.md) · [OpenClaw](../platform-guides/openclaw.md) · [OpenCode](../platform-guides/opencode.md) · [Codex](../platform-guides/codex.md) |
| [AIDR CLI](../../packages/cli/README.md) | Every `aidr` command: setup, status, verify, doctor, pending, approve, uninstall |

## Office user (AI chat in the browser)

| Guide | Covers |
|---|---|
| [Installing Browser Guard](browser-guard.md) | Install from the store link in Chrome, Edge or Firefox (Windows, Linux, macOS), check that it works, remove it |

## IT admin

| Guide | Covers |
|---|---|
| [Desktop installers: silent and managed deployment](desktop-installers.md#silent-and-managed-deployment) | Intune, SCCM/ConfigMgr, GPO, apt/yum/dnf, per-user setup, signature checks |
| [Deploying Browser Guard in an organisation](browser-guard-enterprise.md) | Force-install and lock settings with Intune, Google Admin console, GPO, Jamf (macOS) and Firefox policies; pilot, rollout and rollback |
| [Browser Guard policy files](../../deploy/browser-guard/README.md) | Example policy files and every managed setting |
| [Fleet scripts](../../deploy/fleet/windows/README.md) | Script-based fleet install, upgrade and uninstall (Windows; [Linux](../../deploy/fleet/linux/README.md)) |
| [Operator approvals](../configuration.md#operator-approvals) | How a held action is approved by a person (`aidr pending`, `aidr approve`, dashboard Approvals) |
| [Configuration](../configuration.md) | Every setting and file path |
| [Support diagnostics](../support-diagnostics.md) | `aidr support-bundle` and what it contains |

## On-prem operator (your own servers)

| Guide | Covers |
|---|---|
| [On-premises deployment](../deployment/onprem.md) | Topologies (Docker Compose, Kubernetes, air-gapped) and where to start |
| [AIDR on-prem installation](../../deploy/onprem/README.md) | Single Linux host with Docker Compose: install, upgrade, backup, air-gapped hosts |
| [Running AIDR on Kubernetes](../operations/kubernetes.md) | Helm chart: images, credentials, install, upgrade and rollback, backup |
| [Configuration reference](../operations/onprem-config-reference.md) | Every on-prem setting |
| [Upgrade runbook](../../deploy/UPGRADE.md) | Control-plane upgrades and rollback |
| [Licensing](../operations/licensing.md) | Offline licence and what happens when it lapses |
| [First-customer guide](../../deploy/FIRST_CUSTOMER.md) (Turkish) | Installation and acceptance checklist |

## Release and portal operator (Singularity / vendor side)

| Guide | Covers |
|---|---|
| [Installer download portal](download-portal.md) | Publishing signed installers to the dashboard Downloads page, store-link settings |
| [Desktop installers: building](desktop-installers.md#building-the-installers) | Building and signing the installers |
| [SaaS deployment](../deployment/saas.md) | The hosted control plane |

## Upgrades and removal

- Desktop installers: install the newer version over the old one; see
  [Desktop installers](desktop-installers.md#uninstall) for upgrade and uninstall.
- Connector packages and the CLI: [Upgrade notes](../upgrade-notes.md) and
  [Uninstall](../getting-started.md#uninstall).
