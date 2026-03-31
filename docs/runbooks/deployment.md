# Deployment Runbook

Complete guide for deploying Singularity AIDR components to production.

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

- [ ] All tests passing (`pnpm test`)
- [ ] Security scans clean (`pnpm audit --prod`)
- [ ] TypeScript compilation successful (`pnpm check`)
- [ ] Linting passes (`pnpm lint`)
- [ ] Bundle size limits satisfied (`pnpm bundlesize`)
- [ ] Changeset created (`pnpm changeset`)
- [ ] Version bumped (`pnpm run version`)
- [ ] Documentation updated
- [ ] Staging deployment verified
- [ ] Secrets audit passed (`bash scripts/pre-release-audit.sh`)
- [ ] No source maps in release builds (`node scripts/check-no-sourcemaps.mjs packages/`)

---

## NPM Package Release

Singularity AIDR uses [Changesets](https://github.com/changesets/changesets) for versioning and publishing.

### Automatic Release (via CI)

1. **Create a changeset** (during development):
   ```bash
   pnpm changeset
   ```
   - Select affected packages
   - Choose bump type (patch/minor/major)
   - Write summary

2. **Commit the changeset**:
   ```bash
   git add .changeset/
   git commit -m "chore: add changeset for feature X"
   ```

3. **Version packages** (can be done manually or via CI):
   ```bash
   pnpm run version
   ```
   This updates versions, generates changelogs, and syncs manifests.

4. **Merge the release PR**:
   The GitHub Action automatically publishes when merged to `main`/`master`.

5. **Monitor the release**:
   - Watch: https://github.com/SingularityRD/aidr/actions/workflows/release.yml
   - Verify on npm:
     ```bash
     npm view @singularityrd/aidr-core
     npm view @singularityrd/aidr-sdk
     npm view @singularityrd/aidr-openclaw
     npm view @singularityrd/aidr-opencode
     ```

### Manual Release (Emergency)

Only use if CI is unavailable:

```bash
# 1. Ensure clean state
git checkout main
git pull origin main

# 2. Install dependencies
pnpm install --frozen-lockfile

# 3. Build and verify
pnpm build:release

# 4. Login to npm (if not already)
npm login

# 5. Publish packages
pnpm -C packages/core publish --access public
pnpm -C packages/sdk publish --access public
pnpm -C packages/openclaw publish --access public
pnpm -C packages/opencode publish --access public

# 6. Tag release
git tag -a v$(node -p "require('./packages/core/package.json').version") -m "Release"
git push origin --tags
```

### Published Packages

| Package | npm Name | Description |
|---------|----------|-------------|
| Core | `@singularityrd/aidr-core` | Detection engine library |
| SDK | `@singularityrd/aidr-sdk` | Universal integration SDK |
| OpenClaw | `@singularityrd/aidr-openclaw` | OpenClaw plugin |
| OpenCode | `@singularityrd/aidr-opencode` | OpenCode plugin |

---

## VS Code/Cursor Extension Publishing

### Build VSIX Package

```bash
# Build both Cursor and VS Code packages
pnpm run package:vsix

# Or individually:
pnpm -C packages/extension run package:cursor:vsix
pnpm -C packages/extension run package:vscode:vsix
```

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

#### Vercel (Recommended)

```bash
# Using Vercel CLI
vercel --prod

# Or configure GitHub integration
# Dashboard auto-deploys on push to main
```

Required environment variables in Vercel:
```
SENTRY_DSN=<your-sentry-dsn>
SENTRY_ENABLED=true
SENTRY_ENVIRONMENT=production
```

#### Netlify

```bash
# Using Netlify CLI
netlify deploy --prod --dir=dist
```

#### Self-Hosted (Static Files)

```bash
# Sync to S3
aws s3 sync dist/ s3://your-bucket-name/ --delete

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

4. Verify Sentry integration (check for initial connection)

---

## Rollback Procedures

### NPM Packages

npm packages **cannot be unpublished** after 24 hours or if dependents exist. Use these strategies:

#### Strategy 1: Deprecate Version (Immediate)

```bash
npm deprecate @singularityrd/aidr-core@<bad-version> "Critical issue - use @<good-version> instead"
```

#### Strategy 2: Publish Patch with Revert

```bash
# 1. Create revert commit
git revert <bad-commit-hash>

# 2. Add changeset
pnpm changeset
# Select "patch" for affected packages

# 3. Version and publish
pnpm run version
# Push and let CI publish
```

#### Strategy 3: Emergency Dist-Tag

```bash
# Point "latest" to previous version
npm dist-tag add @singularityrd/aidr-core@<previous-version> latest

# Remove bad tag
npm dist-tag rm @singularityrd/aidr-core@<bad-version> latest
```

### VS Code/Cursor Extension

1. **Unpublish from marketplace**:
   - VS Code: https://marketplace.visualstudio.com/manage → Unpublish
   - Open VSX: https://open-vsx.org/ → Namespace → Unpublish

2. **Users auto-update**: Extensions auto-downgrade to previous version after unpublish

3. **Emergency disable**: Push update with `activationEvents: []` to disable immediately

### Dashboard

1. **Restore previous build**:
   ```bash
   # If using Vercel: Rollback in dashboard
   vercel rollback

   # If using S3: Restore from backup
   aws s3 sync s3://backup-bucket/$(date -d 'yesterday' +%Y-%m-%d)/ s3://production-bucket/ --delete
   ```

2. **Redeploy previous version**:
   ```bash
   git checkout <previous-tag>
pnpm -C packages/dashboard run build:release
   # Deploy artifacts
   ```

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
  npm view @singularityrd/aidr-core --json | jq '.versions | keys | last'
  ```
  - Verify version is available
  - Check for 404 errors

- [ ] **Bundle size changes**: Compare to previous release
  ```bash
  pnpm bundlesize
  ```

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
- npm publish webhook → Slack
- Marketplace publish notifications → Email

---

## Emergency Contacts

| System | Owner | Escalation Path |
|--------|-------|-----------------|
| npm | DevOps | devops@singularityrd.com |
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
