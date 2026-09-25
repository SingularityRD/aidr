# Package Supply-Chain Protection

Singularity AIDR checks npm and PyPI packages for supply-chain threats whenever an install command is run or a manifest file (`package.json`, `requirements.txt`) is written. Root manifests are also scanned at session start.

## What It Detects

| Threat | Verdict | Description |
|--------|---------|-------------|
| Non-existent package | `deny` | Hallucinated or typosquatted name not found on registry |
| Hallucinated version | `deny` | Specific version that does not exist for a real package |
| Malicious package | `deny` | Known malware/PUP detected via file reputation check |
| Suspiciously new package | `ask` | First published less than 7 days ago |
| Possible slopsquatting | `ask` | First published inside the `new_package_days` window (default 30) with low adoption: few weekly downloads (npm) or few published versions |
| Not verified | `ask` | The package exists but no reputation leg could verify it clean |

## How It Works

1. Extract package names and versions from install commands or manifest files
2. Query the registry (npm or PyPI) for metadata
3. If the package or version does not exist, block immediately
4. If it exists, check the package hash against a file reputation API (SHA-256 digests only)
5. Check publication age: under 7 days is held for review; inside the `new_package_days` window with low adoption is held with a slopsquatting reason
6. Otherwise the package is reported as not verified clean and needs review; only a positive reputation result counts as clean

No tarballs are downloaded. Only registry metadata, the npm weekly download count (for young packages, when `adoption_lookup` is on) and hash lookups are used.

Scoped packages (`@scope/pkg`) are checked like any other package.

## Configuration

```json
{
  "package_check": {
    "enabled": true,
    "timeout_seconds": 5,
    "new_package_days": 30,
    "low_adoption_weekly_downloads": 1000,
    "low_adoption_max_versions": 3,
    "adoption_lookup": true
  },
  "file_check": {
    "enabled": true,
    "timeout_seconds": 5
  }
}
```

- `package_check.enabled` - package checks send package names to public registries and are off by default; while off, package operations are reported as unverified (never clean) and need review
- `package_check.new_package_days` - slopsquatting window; `0` turns the low-adoption signal off (the 7-day hold stays)
- `package_check.low_adoption_weekly_downloads` / `low_adoption_max_versions` - what counts as low adoption; the version count is used when download counts are unavailable (always for PyPI)
- `package_check.adoption_lookup` - set to `false` to never call the npm downloads API
- `file_check.enabled` - set to `false` to skip file reputation lookups (registry existence and age checks still run)

Results are cached in `~/.singularity-aidr/cache.json` with TTLs based on verdict and package age.

See also [Data and context poisoning protection](poisoning-protection.md).
