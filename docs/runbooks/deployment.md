# Deployment Runbook

This is a deployment reference, not evidence that a production environment is
configured or accepted. The protected RC and promotion workflows are the only
supported package-release path. Hosting examples below are optional operator
procedures; no Vercel, Netlify, marketplace, or customer production target is
proven by the presence of these instructions.

## Table of Contents

- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [NPM Package Release](#npm-package-release)
- [VS Code/Cursor Extension Publishing](#vscodecursor-extension-publishing)
- [Dashboard Deployment](#dashboard-deployment)
- [Rollback Procedures](#rollback-procedures)
- [Post-Deploy Monitoring Checklist](#post-deploy-monitoring-checklist)

---

## Pre-Deployment Checklist

Before any deployment, ensure:

- [ ] CI and release gates pass for the exact candidate (`node scripts/run-evidence-gates.mjs`)
- [ ] Evidence is candidate-bound and reviewed (`pnpm evidence:index:verify`)
- [ ] Dependency audits reviewed (`pnpm audit:prod` and `pnpm audit:build`)
- [ ] TypeScript compilation successful (`pnpm check`)
- [ ] Linting passes (`pnpm lint`)
- [ ] Package consumers and customer kit verified (`pnpm verify:package-install` and `pnpm verify:customer-kit`)
- [ ] Changeset created (`pnpm changeset`)
- [ ] Version PR reviewed; do not publish directly from the versioning workflow
- [ ] Documentation updated
- [ ] Staging/customer acceptance completed on the exact candidate
- [ ] Current-tree secret scan passed (`pnpm verify:secrets:current`); the release workflow also performs the pinned full-history scan
- [ ] No source maps in release builds (`node scripts/check-no-sourcemaps.mjs packages/`)

---

## NPM Package Release

Singularity AIDR uses [Changesets](https://github.com/changesets/changesets) for
versioning. Versioning and publishing are separate protected operations.

### Supported protected release flow

1. Add a changeset and merge it through the normal reviewed change process.
2. `.github/workflows/release-version.yml` creates or updates a version PR; it
   deliberately never publishes packages.
3. After review, the release operator creates the protected, signed annotated
   `vX.Y.Z-rc.0` tag. `.github/workflows/release-rc.yml` validates the tag and
   builds and verifies the exact candidate.
4. Only after required candidate acceptance, dispatch
   `.github/workflows/release-promote.yml` from the protected default branch
   with the exact tag and successful RC run ID. Use its `promote` action; the
   workflow is the publication authority.
5. Verify package availability through the private GitHub Packages registry
   (`https://npm.pkg.github.com`) using approved credentials. Public npm queries
   are not a valid check for this private scope.

There is no supported direct/manual `pnpm publish`, tag-push, or CI-bypass
fallback. If the protected workflows are unavailable, stop release activity and
restore the workflow path rather than publishing unverified bytes.

### Published Packages

| Package | Private GitHub Packages name | Description |
|---------|----------|-------------|
| Core | `@singularityrd/aidr-core` | Detection engine library |
| SDK | `@singularityrd/aidr-sdk` | Security client and framework-neutral middleware SDK |
| OpenClaw | `@singularityrd/aidr-openclaw` | OpenClaw plugin |
| OpenCode | `@singularityrd/aidr-opencode` | OpenCode plugin |
| Codex | `@singularityrd/aidr-codex` | Codex `PreToolUse` hook |
| CLI | `@singularityrd/aidr-cli` | Local setup and diagnostics |

This table is a naming reference, not an exhaustive package inventory. The
candidate's release inventory and package manifests define the exact published
set for a given release.

---

## VS Code/Cursor Extension Publishing

### Package the signed RC

The supported release entrypoint is the protected `release-rc` workflow. It
builds the extension, generates the manifest and SBOM, signs the manifest, and
then runs the canonical `.github/scripts/package-vsix.mjs` packager. Do not
publish a VSIX produced from a normal local build.

If an operator has restored the exact signed RC package inputs, the packaging-
only commands are:

```bash
pnpm run package:vsix:from-signed-dist

# Or individually, from packages/extension:
pnpm run package:cursor:vsix:from-signed-dist
pnpm run package:vscode:vsix:from-signed-dist
```

These commands do not prepare or sign `dist`. They fail unless both host entry
bundles, the hook runner, signed artifact manifest, SBOM, and SBOM checksum are
already present.

Output files:
- `aidr-cursor.vsix` (Cursor-specific build)
- `aidr-vscode.vsix` (VS Code build)

### Test Local Installation

```bash
# Install for testing
cursor --install-extension aidr-cursor.vsix
code --install-extension aidr-vscode.vsix
```

### Publish to Marketplace

#### Cursor Extension (Open VSX / Cursor Marketplace)

1. Navigate to https://open-vsx.org/
2. Create namespace and upload VSIX
3. Or use CLI (requires `ovsx` tool):
   ```bash
   npx ovsx publish aidr-cursor.vsix -p <PAT_TOKEN>
   ```

#### VS Code Extension (VS Code Marketplace)

1. Navigate to https://marketplace.visualstudio.com/manage
2. Click "Create new extension"
3. Upload `aidr-vscode.vsix`
4. Fill in metadata and submit for review

> **Note:** First-time publication requires manual verification by Microsoft (~1-2 business days).

---

## Dashboard Deployment

The dashboard (`packages/dashboard`) is a Vite + React SPA.

### Build

```bash
cd packages/dashboard

# Development build
pnpm build

# Release build (optimized)
pnpm build:release
```

Output: `packages/dashboard/dist/`

### Deployment Options

#### Vercel (example; not configured by this repository)

```bash
# Using Vercel CLI
vercel --prod

# A Git integration must be configured and separately verified by the operator.
```

Required environment variables in Vercel:
```
SENTRY_DSN=<your-sentry-dsn>
SENTRY_ENVIRONMENT=production
SENTRY_TRACES_SAMPLE_RATE=0.1
VITE_SUPABASE_URL=https://<project>.supabase.co
VITE_SUPABASE_ANON_KEY=<public-anon-key>
VITE_AIDR_COMMERCIAL_MODE=invoice
VITE_SALES_URL=https://<approved-sales-channel>
```

`SENTRY_DSN`, `SENTRY_ENVIRONMENT`, and `SENTRY_TRACES_SAMPLE_RATE` are the
canonical dashboard names. The Vite build maps only these three public values
into static deployments; the Node image validates and injects the same values
at runtime. Leaving `SENTRY_DSN` empty disables browser telemetry.
This paragraph applies to the **dashboard browser**, which uses its configured
DSN independently. Node connector diagnostics remain off unless their separate
explicit runtime opt-in (see [privacy](../privacy.md#what-can-leave-the-process))
and a real DSN are both present; a DSN alone is not consent to send runtime
events. Do not use example or placeholder DSNs for a live diagnostic route.

The download center (`/downloads` and the onboarding "Download & connect"
step) reads a release manifest. On the Node image, set
`AIDR_RELEASE_MANIFEST_PATH` to a read-only mounted manifest file (served at
`/release-manifest.json`), or set `VITE_AIDR_RELEASE_MANIFEST_URL` to an
external HTTPS manifest. Do not set both. On Vercel, `VITE_AIDR_RELEASE_MANIFEST_URL`
is a build-time value and must be same-origin unless you extend the CSP
`connect-src`. Without a manifest the dashboard shows install guidance with no
download links. See the [release manifest contract](../contracts/release-manifest.md).

The Supabase Edge Functions called by the browser also require
`AIDR_ALLOWED_ORIGINS` to contain the exact deployed dashboard origin (for
example `https://demo.example.com`). The device/pilot/credential endpoints
fail closed for an unlisted `Origin` and handle `OPTIONS` preflight before
performing authentication or database work. Keep this value separate from the
dashboard's public Vite variables and rotate it with the deployment record.

#### Netlify

```bash
# Using Netlify CLI
netlify deploy --prod --dir=dist
```

#### Self-Hosted (Static Files)

```bash
# Copy to a versioned release prefix; do not delete from the live bucket as part
# of an unreviewed sync. Promote the exact tested prefix using the host's
# approved deployment mechanism.
aws s3 sync dist/ s3://your-bucket-name/releases/<candidate-id>/

# Or rsync to server
rsync -avz dist/ user@server:/var/www/aidr-dashboard/
```

### Post-Deploy Verification

1. Check build artifacts:
   ```bash
   ls -la packages/dashboard/dist/
   ```

2. Verify no source maps in production:
   ```bash
   node scripts/check-no-sourcemaps.mjs packages/dashboard/dist
   ```

3. Test dashboard loads without errors

4. If Sentry is configured, verify a test event reaches the approved project and
   alert route; a successful page load does not prove telemetry delivery.

---

## Rollback Procedures

### Private GitHub Packages

Package rollback, yank, and publication state are controlled by the protected
`.github/workflows/release-promote.yml` workflow. Use its validated
`rollback`/`yank` operation with the exact release identity and required
confirmation; do not run ad hoc `npm deprecate`, `npm dist-tag`, direct publish,
or working-tree checkout commands. Repository presence alone does not prove a
rollback candidate or production deployment has been accepted.

### VS Code/Cursor Extension

1. **Unpublish from marketplace**:
   - VS Code: https://marketplace.visualstudio.com/manage → Unpublish
   - Open VSX: https://open-vsx.org/ → Namespace → Unpublish

2. **User impact**: Unpublishing does not guarantee clients automatically
   downgrade. Use the marketplace's supported recovery process and communicate
   the exact affected versions.

3. **Emergency disable**: Push update with `activationEvents: []` to disable immediately

### Dashboard

1. **Restore previous build** only through the configured host's reviewed,
   immutable deployment artifact:
   ```bash
   # If using Vercel: Rollback in dashboard
   vercel rollback

   # If using a versioned S3 deployment: repoint the host to the exact
   # previously accepted candidate prefix; do not bulk-delete production files.
   ```

2. Do not rebuild an old Git tag in a mutable working tree as the production
   rollback artifact. Redeploy the exact previously accepted candidate bytes and
   record the artifact digest and host-side result.

---

## Post-Deploy Monitoring Checklist

Check these metrics within **1 hour** of deployment:

### Error Monitoring

- [ ] **Sentry error rate**: https://sentry.io/organizations/singularityrd/
  - Look for new error patterns
  - Check affected release version
  - Set alert threshold: >10 errors/minute

### Package Health

- [ ] **npm download stats**:
  ```bash
  npm view @singularityrd/aidr-core@<version> version --registry=https://npm.pkg.github.com
  ```
  - Requires approved GitHub Packages credentials; public npm is not the registry.

- [ ] **Bundle size changes**: review the exact `pnpm build:release` output and
  candidate artifact inventory. There is no `pnpm bundlesize` script in the
  current root `package.json`.

### Extension Health

- [ ] **Extension installation count**: Check marketplace dashboard
- [ ] **Update propagation**: Test fresh install from marketplace

### Dashboard Health

- [ ] **Uptime**: Verify dashboard loads (check status page)
- [ ] **Core Web Vitals**: LCP <2.5s, CLS <0.1
- [ ] **API connectivity**: Test control plane connection

### User Feedback Channels

- [ ] **GitHub Issues**: Check for new bug reports
- [ ] **Support tickets**: Monitor for deployment-related issues
- [ ] **Slack alerts**: Check #deployments channel

### Automated Alerts

Ensure these are configured:
- Sentry → Slack integration (new issues)
- GitHub Packages publish event → Slack
- Marketplace publish notifications → Email

---

## Emergency Contacts

| System | Owner | Escalation Path |
|--------|-------|-----------------|
| GitHub Packages | DevOps | devops@singularityrd.com |
| VS Code Marketplace | Engineering | eng-leads@singularityrd.com |
| Sentry | DevOps | On-call rotation |
| Dashboard Hosting | SRE | sre@singularityrd.com |

---

## Release Calendar

| Day | Activity |
|-----|----------|
| Monday | Feature freeze |
| Tuesday | Release candidate testing |
| Wednesday | Production release |
| Thursday | Monitor and hotfix if needed |
| Friday | No releases (risk mitigation) |
