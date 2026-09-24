# Source import record

The local `Singularity-AIDR-Privacy-0.5.0-rc.1` delivery was not a Git repository. Its `RELEASE-MANIFEST.json` listed 605 files; every listed file matched its recorded SHA-256 and size before import. The manifest itself had SHA-256 `a0b0af2f3d1fdc24e8f8e8fda375591bcf6974f5172e7861d40819a9ea0fbd07`. This establishes byte consistency with the supplied manifest, not the author's identity or a signed release.

This workspace package imported 250 manifest-listed source, fixture, model, documentation and summary-report files. Generated `dist/` and `extension/chrome/`, raw test outputs, the standalone npm lockfile, and local TypeScript tarballs were omitted. The package manifest was adapted to use the repository's pnpm workspace and Node 22 type target. Builds generate the omitted output; no standalone package is published from this import.

The package is an integration candidate, not an active AIDR protection path. Its own [merge guide](docs/PLATFORM_MERGE.md) and [feature status](docs/PLATFORM_FEATURE_STATUS.md) describe the remaining trust-boundary and customer acceptance work. Do not present its synthetic tests or historical reports as evidence that the main AIDR application intercepts provider uploads.
