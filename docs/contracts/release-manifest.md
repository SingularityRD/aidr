# Contract: release manifest for the dashboard download center

The download center (`/downloads` and the "Download & connect" onboarding step)
shows only what a published release manifest lists. It never invents a link,
digest or version. With no manifest configured it shows a "not configured"
notice plus install and enrollment guidance, with no download links.

- JSON Schema: [`packages/dashboard/src/onboarding/release-manifest.schema.json`](../../packages/dashboard/src/onboarding/release-manifest.schema.json)
- Generator: [`scripts/generate-release-manifest.mjs`](../../scripts/generate-release-manifest.mjs)
- Server validation: [`deploy/dashboard/release-manifest.mjs`](../../deploy/dashboard/release-manifest.mjs)
- Browser validation: [`packages/dashboard/src/onboarding/release-manifest.ts`](../../packages/dashboard/src/onboarding/release-manifest.ts)

## Document

```json
{
  "version": "1.4.0",
  "publishedAt": "2026-09-24T08:00:00Z",
  "artifacts": [
    {
      "id": "claude-code",
      "version": "1.4.0",
      "url": "https://downloads.example.com/aidr/1.4.0/aidr-claude-plugin-1.4.0.tar.gz",
      "sha256": "<64 lower-case hex>",
      "signature": "https://downloads.example.com/aidr/1.4.0/aidr-claude-plugin-1.4.0.tar.gz.sig",
      "size": 5242880,
      "platforms": ["any"]
    }
  ]
}
```

| Field | Rule |
| --- | --- |
| `version`, `artifacts[].version` | Semantic version (`1.4.0`, `2.0.0-rc.1`). |
| `publishedAt` | RFC 3339 timestamp. |
| `artifacts` | 0 to 200 entries. |
| `artifacts[].id` | One of `claude-code`, `cursor`, `vscode`, `openclaw`, `opencode`, `codex`, `cli`, `browser-guard-chrome`, `browser-guard-firefox`, `mcp-gateway`. |
| `artifacts[].url` | Absolute `https:` URL without embedded credentials. `http:` and every other scheme are rejected. |
| `artifacts[].sha256` | Required. 64 lower-case hex characters: the SHA-256 of the exact bytes served at `url`. |
| `artifacts[].signature` | Optional `https:` URL of a detached publisher signature. |
| `artifacts[].size` | Byte count, positive integer. |
| `artifacts[].platforms` | 1 to 16 unique identifiers matching `^[a-z0-9][a-z0-9_-]{0,31}$`, for example `any`, `linux-x64`, `darwin-arm64`, `win32-x64`, `chrome`, `edge` or `firefox`. |

The same `id` may appear more than once for different platforms (for example
CLI binaries), but an `(id, platform)` pair must be unique. Unknown fields are
rejected at every level.

## Validation is fail-closed at every hop

1. The generator validates its output before writing it.
2. The dashboard server validates `AIDR_RELEASE_MANIFEST_PATH` at startup and
   exits on an invalid file. It re-reads and re-validates the file on every
   request, so an operator can replace it without a restart. A replacement
   that fails validation gets `503`. It is never served.
3. The browser validates again, because the manifest may come from an external
   URL. One invalid entry (for example an `http:` link or a missing digest)
   rejects the whole manifest, and the page shows "Downloads are withheld".

## Publishing

Generate the manifest from the release directory. Digests and sizes come from
the files on disk:

```sh
node scripts/generate-release-manifest.mjs \
  --dir dist/release-1.4.0 --version 1.4.0 \
  --base-url https://downloads.example.com/aidr/1.4.0/ \
  --out release-manifest.json
```

The generator recognizes the file names from the release pipeline (see
`DEFAULT_PATTERNS`). `--artifact <id>=<file>[@platform,...]` maps any other
file explicitly. A sibling `<file>.sig` becomes the `signature` URL. Files that
match no id are listed on stderr and left out. The generator fails on
symlinks, on a file whose name carries a different version, on an `http:`
base URL, and on a directory with no recognized artifacts. `publishedAt`
defaults to `SOURCE_DATE_EPOCH` when it is set, otherwise to the current time.

Serve it in one of two ways:

- **Dashboard server (Node/Docker):** set `AIDR_RELEASE_MANIFEST_PATH` to the
  absolute path of the file, mounted read-only into the container. The server
  serves it at `/release-manifest.json` with
  `Cache-Control: public, max-age=60, must-revalidate` and a SHA-256 `ETag`, and
  answers `If-None-Match` with `304`. Runtime config then carries
  `releaseManifestUrl: "/release-manifest.json"`.
- **External HTTPS URL:** set `VITE_AIDR_RELEASE_MANIFEST_URL`. On the Node
  server this is read at runtime: the URL goes into runtime config and its
  origin is added to the CSP `connect-src`. On static hosting it is a build-time
  variable, and the host's CSP must allow the origin (the bundled `vercel.json`
  allows only `'self'` for `connect-src`).

Configuring both variables is a startup error. Setting neither is a supported
state: the dashboard shows that no manifest is published.

The manifest is public. Anyone who can reach the dashboard origin can read it.
Never put bearer tokens or pre-signed credentials in `url` or `signature`. If
downloads must be authenticated, protect them at the download host.

## "Detected" status

A runtime card shows "Detected" only when a row in `agents` for the current
team has a matching `agent_runtime`. Browser Guard also needs a matching
`agent_runtime_version` prefix: `chrome-` or `edge-` for the Chrome and Edge
build, and `firefox-` for Firefox. The CLI and the MCP gateway do not check in
with the control plane, so their cards say so instead of guessing. If the check-in
query fails, the card shows "Check-in status unavailable", not "Not detected".
