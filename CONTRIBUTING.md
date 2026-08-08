# Contributing to Singularity AIDR

Thank you for your interest in contributing to Singularity AIDR.

## Development Setup

```bash
git clone https://github.com/singularityrd/aidr
cd aidr
git checkout pre-release
pnpm install
pnpm build
pnpm test
```

Requires Node.js >= 18 and pnpm >= 9. See [Development](docs/development.md) for the full command reference.

## Making Changes

1. Create a branch from `pre-release`
2. Make your changes
3. Run `pnpm test` and `pnpm check` to verify
4. Run `pnpm lint:fix` to format code
5. Submit a pull request against `pre-release`

Keep PRs focused on a single change. Include tests for new functionality.

## Licensing of Contributions

This is a commercial/proprietary repository. This contribution policy is a
draft pending Legal review; submitting a contribution does not itself grant
customer distribution rights. By submitting a pull request, you confirm that
you have the right to contribute the material and agree that first-party code
contributions are governed by the commercial terms in [LICENSE](LICENSE) or a
separate signed contributor agreement:

- **First-party source code** (everything except `threats/`): governed by the
  proprietary commercial terms in [LICENSE](LICENSE).
- **Threat detection rules** (`threats/*.yaml`): your contribution is licensed
  under the [Detection Rule License 1.1](threats/LICENSE). Please include an
  `author` field in your rules for proper attribution.

## Contributing Threat Rules

Threat rules live in `threats/*.yaml`. Each rule must include:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier (e.g. `CLT-CMD-001`) |
| `category` | string | `tool`, `network_egress`, `secrets`, or `supply_chain` |
| `severity` | enum | `critical`, `high`, `medium`, or `low` |
| `confidence` | float | 0.0-1.0 |
| `action` | enum | `block`, `require_approval`, or `log` |
| `pattern` | string | Regex pattern |
| `match_on` | string or list | `command`, `url`, `file_path`, `content`, or `domain` |
| `title` | string | Human-readable description |
| `expires_at` | string or null | ISO 8601 date or `null` for permanent |
| `revoked` | boolean | Set `true` to disable without removing |
| `case_insensitive` | boolean | Match pattern case-insensitively (default: `false`) |

See [Threat Rules](docs/threat-rules.md) for the full format reference and examples.

## Coding Conventions

- **Naming:** YAML/JSON data uses `snake_case`; TypeScript uses `camelCase`
- **Fail-open:** Every error path must return an `allow` verdict
- **Formatting:** Biome handles linting and formatting (tabs, double quotes, semicolons)
- **Testing:** Add tests for new functionality. Unit tests go in `packages/core/src/__tests__/`

## Branch Policy

- **`main`** is the release/distribution branch. It is what users install from the Claude Code marketplace. PRs should not target `main`.
- **`pre-release`** is the contribution branch. All external PRs should target `pre-release`. After a further security review the contributions are then synced back to `main` in controlled releases.

This separation ensures that code merged from PRs goes through a review and security audit cycle before reaching users.

## Reporting Issues

Use GitHub Issues for bugs and feature requests.

**Security vulnerabilities:** Please report privately via [GitHub Security Advisories](https://github.com/singularityrd/aidr/security/advisories/new). Do not open public issues for security bugs.
