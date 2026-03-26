# Package Supply-Chain Protection

Singularity AIDR checks npm and PyPI packages for supply-chain threats whenever an install command is run or a manifest file (`package.json`, `requirements.txt`) is written. Root manifests are also scanned at session start.

## What It Detects

| Threat | Verdict | Description |
|--------|---------|-------------|
| Non-existent package | `deny` | Hallucinated or typosquatted name not found on registry |
| Hallucinated version | `deny` | Specific version that does not exist for a real package |
| Malicious package | `deny` | Known malware/PUP detected via file reputation check |
| Suspiciously new package | `ask` | First published less than 7 days ago |

## How It Works

1. Extract package names and versions from install commands or manifest files
2. Query the registry (npm or PyPI) for metadata
3. If the package or version does not exist, block immediately
4. If it exists, check the package hash (`dist.shasum` for npm, `digests.sha256` for PyPI) against a file reputation API
5. If no reputation match, check publication age - flag if less than 7 days old
6. Otherwise, allow

No tarballs are downloaded. Only registry metadata and hash lookups are used.

## Scoped Packages

Scoped packages (`@scope/pkg`) are automatically skipped because they typically come from private registries and would false-positive against public npm/PyPI.

## Configuration

```json
{
  "package_check": {
    "enabled": true,
    "timeout_seconds": 5
  },
  "file_check": {
    "enabled": true,
    "timeout_seconds": 5
  }
}
```

- `package_check.enabled` - set to `false` to disable all package checks
- `file_check.enabled` - set to `false` to skip file reputation lookups (registry existence and age checks still run)

Results are cached in `~/.singularity-aidr/cache.json` with TTLs based on verdict and package age.


