# Secrets Management Runbook

Complete guide for managing secrets across local development, CI/CD, and production environments for Singularity AIDR.

## Table of Contents

- [Required Environment Variables](#required-environment-variables)
- [Secret Rotation Procedures](#secret-rotation-procedures)
- [GitHub Actions Secrets Setup](#github-actions-secrets-setup)
- [Local Development Secrets](#local-development-secrets)
- [Production Secrets](#production-secrets)
- [Secret Security Best Practices](#secret-security-best-practices)

---

## Required Environment Variables

### Application Secrets

| Variable | Purpose | Required In | Rotation Frequency |
|----------|---------|-------------|-------------------|
| `SENTRY_DSN` | Error reporting endpoint | All environments | On compromise |
| `SENTRY_AUTH_TOKEN` | Source map upload | CI/CD only | Quarterly |
| `NPM_TOKEN` | Package publishing | GitHub Actions | Quarterly |
| `GITHUB_TOKEN` | Release creation | GitHub Actions | Auto-rotated |

### E2E Testing Secrets

| Variable | Purpose | Required In | Rotation Frequency |
|----------|---------|-------------|-------------------|
| `ANTHROPIC_API_KEY` | Claude Code E2E tests | CI/CD (optional) | On quota exceed |
| `OPENCLAW_GATEWAY_TOKEN` | OpenClaw E2E tests | CI/CD (optional) | On compromise |
| `OPENCODE_API_KEY` | OpenCode E2E tests | CI/CD (optional) | On compromise |

### Payment Provider Secrets

| Variable | Purpose | Required In | Rotation Frequency |
|----------|---------|-------------|-------------------|
| `STRIPE_SECRET_KEY` | Payment processing | Production | Quarterly |
| `STRIPE_WEBHOOK_SECRET` | Webhook validation | Production | On rotation |
| `IYZICO_SECRET_KEY` | TR payments | Production | Quarterly |
| `COINBASE_WEBHOOK_SECRET` | Crypto payments | Production | On rotation |
| `PAYPAL_SECRET` | PayPal payments | Production | Quarterly |

### Infrastructure Secrets

| Variable | Purpose | Required In | Rotation Frequency |
|----------|---------|-------------|-------------------|
| `SUPABASE_URL` | Dashboard database | Production | On compromise |
| `SUPABASE_ANON_KEY` | Dashboard auth | Production | Quarterly |
| `SUPABASE_SERVICE_ROLE_KEY` | Admin operations | Production only | Quarterly |

### Local Development Only

| Variable | Purpose | Source |
|----------|---------|--------|
| `AIDR_CURSOR_PATH` | Custom Cursor path | User system |
| `AIDR_VSCODE_PATH` | Custom VS Code path | User system |
| `VSCODE_NODE_EXEC_PATH` | VS Code Node path | User system |
| `AIDR_E2E_VERBOSE` | Debug logging | Developer pref |

---

## Secret Rotation Procedures

### NPM Token Rotation

**When:** Quarterly or when token is exposed

```bash
# 1. Generate new token on npmjs.com
# Visit: https://www.npmjs.com/settings/<user>/tokens
# Create "Automation" token with publish access

# 2. Update GitHub secret
gh secret set NPM_TOKEN --body "npm_xxxxx" --repo SingularityRD/aidr

# 3. Verify in CI
git commit --allow-empty -m "chore: verify new NPM_TOKEN"
git push origin main
# Check: https://github.com/SingularityRD/aidr/actions

# 4. Revoke old token on npmjs.com (after 24h grace period)
```

### Sentry Auth Token Rotation

**When:** Quarterly or when token is exposed

```bash
# 1. Generate new token on sentry.io
# Visit: https://sentry.io/settings/account/api/auth-tokens/
# Required scopes: project:write, org:read

# 2. Update GitHub secret
gh secret set SENTRY_AUTH_TOKEN --body "sntrys_xxxxx" --repo SingularityRD/aidr

# 3. Verify source map upload works on next release
```

### Payment Provider Rotation (Stripe Example)

**When:** Quarterly

```bash
# 1. Generate new secret key in Stripe Dashboard
# Visit: https://dashboard.stripe.com/apikeys
# Roll: Create restricted key → Roll webhook secrets

# 2. Update production environment
# Vercel Dashboard / Environment Variables

# 3. Deploy with new secrets
vercel --prod

# 4. Revoke old key after 24h monitoring
```

### Generic GitHub Actions Secret Rotation

```bash
# Set/update a secret
gh secret set <NAME> --body "<value>" --repo SingularityRD/aidr

# Set from file
gh secret set <NAME> < secret.txt --repo SingularityRD/aidr

# List secrets (names only)
gh secret list --repo SingularityRD/aidr

# Remove secret
gh secret remove <NAME> --repo SingularityRD/aidr
```

### GitHub Environment Secrets (for review deployments)

```bash
# Set secret for specific environment
gh secret set <NAME> --env production --body "<value>" --repo SingularityRD/aidr
```

---

## GitHub Actions Secrets Setup

### Required Repository Secrets

Navigate to: `https://github.com/SingularityRD/aidr/settings/secrets/actions`

| Secret Name | Value Source | Required For |
|-------------|--------------|--------------|
| `NPM_TOKEN` | npmjs.com Automation token | Package publishing |
| `SENTRY_AUTH_TOKEN` | sentry.io Auth Token | Source map upload |
| `ANTHROPIC_API_KEY` | anthropic.com API Keys | E2E tests (optional) |
| `OPENCLAW_GATEWAY_TOKEN` | Local gateway setup | E2E tests (optional) |
| `OPENCODE_API_KEY` | opencode.ai | E2E tests (optional) |

### Required Environment Secrets (Production)

Navigate to: `https://github.com/SingularityRD/aidr/settings/environments`

Create `production` environment with protection rules:
- Required reviewers: 1+ team lead
- Wait timer: 0 minutes
- Deployment branches: `main`, `master`

Set these secrets for `production`:

| Secret Name | Purpose |
|-------------|---------|
| `SENTRY_DSN` | Production error reporting |
| `STRIPE_SECRET_KEY` | Live payments |
| `STRIPE_WEBHOOK_SECRET` | Webhook validation |
| `SUPABASE_URL` | Dashboard database |
| `SUPABASE_ANON_KEY` | Client auth |

### Organization-Level Secrets (Optional)

If managing multiple repos, set at organization level:
`https://github.com/organizations/SingularityRD/settings/secrets`

Available to: Selected repositories (`aidr`)

---

## Local Development Secrets

### Setup

1. **Copy example file**:
   ```bash
   cp .env.example .env
   ```

2. **Fill in your values** (never commit `.env`):
   ```bash
   # Edit .env with your editor
   code .env
   ```

3. **Verify `.env` is ignored**:
   ```bash
   git check-ignore .env  # Should output: .env
   ```

### Required for Local E2E Testing

```bash
# Claude Code E2E
ANTHROPIC_API_KEY=sk-ant-api03-...

# OpenClaw E2E
OPENCLAW_GATEWAY_TOKEN=your-token
OPENCLAW_E2E_HOST=http://localhost:18789

# OpenCode E2E
OPENCODE_E2E_BIN=opencode
```

### Optional Local Overrides

```bash
# Custom IDE paths (auto-detected if not set)
AIDR_CURSOR_PATH=/Applications/Cursor.app/Contents/MacOS/Cursor
AIDR_VSCODE_PATH=/Applications/Visual Studio Code.app/Contents/MacOS/Electron

# Debug logging
AIDR_E2E_VERBOSE=true
AIDR_LOG_LEVEL=debug
```

### Secure Storage Alternatives

#### macOS Keychain

```bash
# Store secret
security add-generic-password -s "aidr-anthropic-key" -a "$(whoami)" -w "sk-ant-..."

# Retrieve in script
export ANTHROPIC_API_KEY=$(security find-generic-password -s "aidr-anthropic-key" -w)
```

#### 1Password CLI

```bash
# Store in 1Password, then:
export ANTHROPIC_API_KEY=$(op read "op://Private/Anthropic/credential")
```

#### direnv (per-directory)

```bash
# .envrc in project root
export ANTHROPIC_API_KEY=sk-ant-...
export OPENCLAW_GATEWAY_TOKEN=...

# Allow direnv
direnv allow
```

---

## Production Secrets

### Vercel Deployment (Dashboard)

**Dashboard:** https://vercel.com/dashboard

1. Select `aidr-dashboard` project
2. Go to Settings → Environment Variables
3. Add production secrets:

| Variable | Value |
|----------|-------|
| `SENTRY_DSN` | https://...sentry.io/... |
| `SENTRY_ENABLED` | true |
| `SENTRY_ENVIRONMENT` | production |
| `STRIPE_PUBLISHABLE_KEY` | pk_live_... |
| `NEXT_PUBLIC_URL` | https://your-domain.com |

### Supabase (Dashboard Database)

**Dashboard:** https://app.supabase.com

1. Go to Project Settings → API
2. Copy `Project URL` → `SUPABASE_URL`
3. Copy `anon public` → `SUPABASE_ANON_KEY`
4. Copy `service_role secret` → `SUPABASE_SERVICE_ROLE_KEY` (server only)

### AWS Secrets Manager (Alternative)

```bash
# Store secret
aws secretsmanager create-secret \
  --name aidr/stripe-secret-key \
  --secret-string "sk_live_..."

# Retrieve in application
aws secretsmanager get-secret-value \
  --secret-id aidr/stripe-secret-key \
  --query SecretString \
  --output text
```

### GCP Secret Manager (Alternative)

```bash
# Store secret
gcloud secrets create aidr-stripe-secret-key --data-file=- <<< "sk_live_..."

# Access in Cloud Run/Compute
gcloud secrets versions access latest --secret=aidr-stripe-secret-key
```

### Azure Key Vault (Alternative)

```bash
# Store secret
az keyvault secret set \
  --vault-name aidr-keyvault \
  --name stripe-secret-key \
  --value "sk_live_..."

# Retrieve
az keyvault secret show \
  --vault-name aidr-keyvault \
  --name stripe-secret-key \
  --query value \
  --output tsv
```

---

## Secret Security Best Practices

### Prevention

1. **Never commit secrets to git**
   ```bash
   # Pre-commit hook check
   git-secrets --scan
   ```

2. **Use .env.example for templates**
   - Never put real values in `.env.example`
   - Comment required vs optional variables

3. **Scan for leaked secrets**
   ```bash
   # Using gitleaks (already in CI)
   gitleaks detect --source . --verbose
   
   # Using trufflehog
   trufflehog filesystem .
   ```

### Detection

1. **GitHub Secret Scanning**
   - Enabled by default on public repos
   - Monitor: https://github.com/SingularityRD/aidr/security/secret-scanning

2. **CI/CD Detection**
   ```yaml
   # Already in .github/workflows/ci.yml
   - name: Pre-release secrets audit
     run: bash scripts/pre-release-audit.sh
   ```

3. **Local pre-commit hooks**
   ```yaml
   # .pre-commit-config.yaml
   repos:
     - repo: https://github.com/gitleaks/gitleaks
       rev: v8.18.0
       hooks:
         - id: gitleaks
   ```

### Response to Exposed Secret

1. **Immediate (0-15 minutes)**:
   - Revoke the secret in the provider dashboard
   - Rotate to new secret
   - Check access logs for unauthorized use

2. **Short-term (15 minutes - 24 hours)**:
   - Update all dependent systems
   - Verify no service disruptions
   - Document incident

3. **Long-term (24+ hours)**:
   - Review how secret was exposed
   - Update processes/pre-commit hooks
   - Audit other secrets for similar patterns

### Access Control

| Environment | Who Can Access | How to Request |
|-------------|----------------|----------------|
| Local dev | Individual developers | Self-service via `.env` |
| CI/CD | GitHub Actions | Via repository secrets |
| Staging | DevOps team | GitHub environment secrets |
| Production | SRE leads only | Ticket to #infrastructure |

### Secret Naming Conventions

- Use `UPPER_SNAKE_CASE`
- Prefix by provider: `STRIPE_`, `SENTRY_`, `SUPABASE_`
- Suffix by type: `_KEY`, `_SECRET`, `_TOKEN`, `_DSN`
- Examples: `STRIPE_SECRET_KEY`, `SENTRY_DSN`, `SUPABASE_ANON_KEY`

---

## Secret Reference Quick Sheet

### Generating New Secrets

| Service | URL | Token Type |
|---------|-----|------------|
| npm | https://www.npmjs.com/settings/tokens | Automation |
| Sentry | https://sentry.io/settings/account/api/auth-tokens/ | Auth Token |
| Anthropic | https://console.anthropic.com/settings/keys | API Key |
| Stripe | https://dashboard.stripe.com/apikeys | Secret Key |
| GitHub | https://github.com/settings/tokens | Personal Access Token |
| Supabase | https://app.supabase.com/project/_/settings/api | API Keys |

### Emergency Contacts

| Service | Support URL | Phone |
|---------|-------------|-------|
| npm | https://www.npmjs.com/support | - |
| Sentry | https://sentry.io/support | - |
| Stripe | https://support.stripe.com | +1 888-963-8442 |
| GitHub | https://support.github.com | - |
| Vercel | https://vercel.com/support | - |
