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
| `SENTRY_DSN` | Optional error reporting endpoint | Only approved telemetry deployments | On compromise |
| `SENTRY_ENABLED` | Explicit opt-in for Node runtime diagnostics (`true`/`1`) | Only approved runtime telemetry deployments | Review with telemetry approval |
| `SENTRY_AUTH_TOKEN` | Source map upload | CI/CD only | Quarterly |
| `GITHUB_TOKEN` | Release creation | GitHub Actions | Auto-rotated |
| `GITHUB_TOKEN` | GitHub Packages publishing and release creation | GitHub Actions | Auto-rotated |

### E2E Testing Secrets

| Variable | Purpose | Required In | Rotation Frequency |
|----------|---------|-------------|-------------------|
| `ANTHROPIC_API_KEY` | Claude Code E2E tests | CI/CD (optional) | On quota exceed |
| `OPENCLAW_GATEWAY_TOKEN` | OpenClaw E2E tests | CI/CD (optional) | On compromise |
| `OPENCODE_API_KEY` | OpenCode E2E tests | CI/CD (optional) | On compromise |

### Payment Provider Secrets

Stripe is the adopted billing provider; the Lemon Squeezy integration was
removed (its webhook performed no signature verification) and replaced by
`supabase/functions/stripe-webhook`. **Status: the Stripe webhook endpoint is
not deployed and none of the Stripe secrets below are provisioned yet.**

| Variable | Purpose | Required In | Rotation Frequency |
|----------|---------|-------------|-------------------|
| `STRIPE_SECRET_KEY` | Payment processing / server-side Checkout Sessions | Production (not provisioned) | Quarterly |
| `STRIPE_WEBHOOK_SECRET` | `Stripe-Signature` verification of webhook deliveries | Production (not provisioned) | On rotation |
| `AIDR_STRIPE_EXTRA_AGENT_PRICE_ID` | Price id that may grant paid seats (non-secret config) | Production (not configured) | On price-book change |
| `AIDR_STRIPE_WEBHOOK_TOLERANCE_SECONDS` | Replay-window seconds, default `300`, maximum `3600` (a larger or invalid value is refused and the default applies; non-secret config) | Production (optional) | On review |
| `AIDR_BILLING_PROVIDER` | Billing portal provider selector; set to `stripe` only when the shared self-service gate is enabled | Production (unset for direct GA) | On commercial decision |
| `AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING` | Fail-closed gate for Paddle/Stripe self-service endpoints; keep `false` for direct GA | Production | On commercial decision |
| `IYZICO_SECRET_KEY` | TR payments | Production | Quarterly |
| `COINBASE_WEBHOOK_SECRET` | Crypto payments | Production | On rotation |
| `PAYPAL_SECRET` | PayPal payments | Production | Quarterly |

Webhook secrets live in Supabase Edge Function secrets (never in `VITE_*`
browser variables and never in this repository). Use the approved secret-entry
workflow; do not put live values in shell history, command arguments, tickets,
or chat. The values below are not provisioned, and the endpoint is not deployed;
do not run a secret-setting command until the release owner records the selected
project and approved secret-entry procedure:

- `STRIPE_WEBHOOK_SECRET`
- `STRIPE_SECRET_KEY`
- `AIDR_STRIPE_EXTRA_AGENT_PRICE_ID` (non-secret configuration)

The endpoint returns `400` and writes nothing while `STRIPE_WEBHOOK_SECRET` is
unset, and refuses to grant seats while the extra-agent price id is unset.

### Infrastructure Secrets

| Variable | Purpose | Required In | Rotation Frequency |
|----------|---------|-------------|-------------------|
| `SUPABASE_URL` | Dashboard database | Production | On compromise |
| `SUPABASE_ANON_KEY` | Dashboard auth | Production | Quarterly |
| `SUPABASE_SERVICE_ROLE_KEY` | Admin operations | Production only | Quarterly |
| `AIDR_PACK_DOWNLOAD_GRANT_SECRET` | HMAC for scoped pack-download grants; at least 32 random bytes | `packs-manifest` + `packs-download` Edge Functions; self-hosted value stored in `.env.functions` | On compromise or deliberate link invalidation |
| `AIDR_APPROVAL_SIGNING_WRAP_KEY_B64` | Seals the per-tenant Ed25519 dashboard-approval signing keys (AES-256-GCM under an HKDF-derived per-tenant key); 32 random bytes, base64 | `approval-requests` Edge Function; self-hosted value stored in `.env.functions` | On compromise; afterwards owners rotate each tenant's approval key (old sealed keys can no longer sign) |

`deployment-prepare` generates this pack-grant secret into the private `.env.functions` file. Self-hosted Compose supplies that value to the Edge Functions container; preserve it across upgrades and never copy it into browser or agent configuration. For managed Supabase, securely install the same generated value as a server-side Edge Function secret for both `packs-manifest` and `packs-download`; the local file does not configure the hosted project. Do not expose the value through command-line arguments, logs, tickets or chat. Scoped `download_url` grants are temporary bearer capabilities; redact their `grant` query parameter from request logs. The project `SERVICE_ROLE_KEY`/runtime `SUPABASE_SERVICE_ROLE_KEY` is also server-only and must never appear in `.env.functions` sent to a customer endpoint or any browser bundle.

### Local Development Only

| Variable | Purpose | Source |
|----------|---------|--------|
| `AIDR_CURSOR_PATH` | Custom Cursor path | User system |
| `AIDR_VSCODE_PATH` | Custom VS Code path | User system |
| `VSCODE_NODE_EXEC_PATH` | VS Code Node path | User system |
| `AIDR_E2E_VERBOSE` | Debug logging | Developer pref |

---

## Secret Rotation Procedures

### CLI Local Credential (`aidr config rotate-key`, `aidr config revoke-key`)

These commands affect **only the CLI setup credential**. They do not rotate or
revoke the managed endpoint API key used by the control plane. That separate
credential currently comes from `auth.api_key` in the runtime config or the
`api_key` field in `managed.json` after enrollment. For a compromised managed
key, use the control-plane API Keys renewal/revocation workflow and verify the
old key is rejected; do not use these CLI commands as evidence of server-side
revocation. Automatic endpoint replacement and vault-backed runtime storage
remain open production-acceptance work.
The CLI setup credential is not used to authenticate managed runtime traffic.

The local CLI setup credential is kept in the OS credential vault — Windows DPAPI,
macOS Keychain or the Linux Secret Service — and `~/.singularity-aidr/config.json`
stores only a `secret_ref` handle. The ACL-hardened plaintext file survives as a
reduced-protection fallback and is used **only when it is selected explicitly**
(`--secret-store file-acl` or `AIDR_SECRET_STORE=file-acl`); with no vault
available and no explicit fallback the CLI fails closed instead of writing the
credential in plaintext.

Older installations created before vault-backed storage may still have an
unmarked inline `apiKey`; rerunning `aidr setup` currently reuses that file rather
than migrating it. Treat that credential as plaintext until it has been rotated
or migrated deliberately. The macOS Keychain adapter writes one command through
`/usr/bin/security -q -i` standard input. Process arguments contain no credential.
New records store marked base64 UTF-8, preserving Unicode, PEM newlines and NUL
bytes; invalid UTF-8 and oversized inputs fail before invoking the native tool.
The complete ASCII command is limited to **4094 bytes before its single LF and
EOF**. With valid reference IDs of 1–128 characters, the maximum credential is
**2805–2994 UTF-8 bytes**, depending on ID length. There is no truncation or file
fallback when this limit is exceeded.

New writes atomically update the password, fixed format marker and versioned
label under the original service/account identity. The marked read uses
service/label/marker filters: Apple's finder ignores non-primary attributes when
both service and account are supplied. Missing marked records retain the legacy
raw ASCII lookup; malformed marked records fail without that fallback. A second
marked lookup handles migration during a legacy read. Serialize migration and
revocation of the same reference: separate native queries cannot establish a
stable legacy format if the item is migrated and deleted between those queries.
AIDR credential rotation uses fresh references. Do not run old and new writers
concurrently, or manually create duplicate versioned labels and markers: the OS
vault does not authenticate against its own authorized owner.
The native protocol and its line ceiling follow Apple's
[interactive command reader](https://github.com/apple-oss-distributions/Security/blob/main/SecurityTool/macOS/security.c),
[line buffer](https://github.com/apple-oss-distributions/Security/blob/main/SecurityTool/macOS/readline.c)
and [Keychain attribute lookup](https://github.com/apple-oss-distributions/Security/blob/main/SecurityTool/macOS/keychain_find.c).
The injected-runner tests verify command construction, not real macOS Keychain
access. On uninstall, AIDR removes its verified hooks only and deliberately keeps
the local configuration and vault item; run `aidr config revoke-key` separately
if the local CLI setup credential should be removed. This does not revoke managed
endpoint credentials.

```bash
# Rotate. Order matters: the new credential is written to the store, then
# config.json commits atomically, and only then is the previous credential
# revoked. A failed commit discards the new credential and leaves the previous
# one valid.
aidr config rotate-key
aidr config rotate-key --json                    # machine-readable receipt

# Revoke: remove the credential from the store and record it in the config.
aidr config revoke-key

# Select a store explicitly, or accept the labelled file fallback.
aidr setup --secret-store windows-dpapi
aidr config rotate-key --secret-store macos-keychain
aidr setup --force --secret-store file-acl       # reduced protection, recorded
```

`secret_rotated_at` / `secret_revoked_at` in `~/.singularity-aidr/config.json`
record the last outcome; the credential itself is never written there. Evidence
boundary: the macOS Keychain and Linux Secret Service adapters are covered by
tests that inject the `security` / `secret-tool` command runner, so no real
Keychain or Secret Service item has been exercised — only the Windows DPAPI path
has been run against the real OS API.

### GitHub Packages Token and Permission Rotation

The release workflow publishes only to the private `npm.pkg.github.com`
registry using the short-lived Actions `GITHUB_TOKEN`; no npmjs.org token is
accepted. Keep `packages: write` limited to the protected production/release
environment and verify the package scope is `@singularityrd`.

```bash
# 1. Confirm the production environment has package-write permission.
gh api repos/SingularityRD/aidr/actions/permissions/workflow \
  --jq '.default_workflow_permissions'

# 2. Verify a dry-run against the private registry (no package mutation).
gh workflow run "Release Promote, Rollback or Yank" \
  -f action=dry-run -f tag=vX.Y.Z-rc.0 -f rc_run_id=<successful-run-id>

# 3. If a long-lived automation token is ever required, store it as a
#    protected environment secret and rotate it through the GitHub Packages
#    token settings; never add it to .npmrc or repository files.
```

### Sentry Auth Token Rotation

**When:** On exposure; any proactive cadence must follow the approved internal
credential policy.

```bash
# 1. Generate new token on sentry.io
# Visit: https://sentry.io/settings/account/api/auth-tokens/
# Required scopes: project:write, org:read

# 2. Update the GitHub secret from a short-lived, access-restricted file
# outside the checkout. Do not pass the token through --body or a shell literal.
gh secret set SENTRY_AUTH_TOKEN < /secure/path/sentry-auth-token.txt --repo SingularityRD/aidr

# 3. Verify source map upload works on next release
```

### Payment Provider Rotation (Stripe; not operational yet)

This procedure is **not executable today**: the Stripe webhook endpoint is not
deployed and the Stripe secrets are not provisioned. Do not follow the stale
Vercel deployment steps from older copies of this runbook. If Stripe is later
approved and deployed, rotate the Edge Function secrets in the deployment that
actually hosts `supabase/functions/stripe-webhook`, perform a signed test event,
verify the resulting billing state, then revoke the old credential under the
approved change record. The rotation cadence, overlap window, and customer
notice policy are not currently approved; do not infer a quarterly or 24-hour
commitment from this template.

### Generic GitHub Actions Secret Rotation

```bash
# Replace SECRET_NAME with the actual GitHub secret name. Read from a short-lived,
# access-restricted file outside the checkout, then delete it under local policy.
gh secret set SECRET_NAME < /secure/path/secret.txt --repo SingularityRD/aidr

# List secrets (names only)
gh secret list --repo SingularityRD/aidr

# Remove secret
gh secret remove SECRET_NAME --repo SingularityRD/aidr
```

### GitHub Environment Secrets (for review deployments)

```bash
# Set secret for specific environment
gh secret set SECRET_NAME < /secure/path/secret.txt --env production --repo SingularityRD/aidr
```

---

## GitHub Actions Secrets Setup

### Required Repository Secrets

Navigate to: `https://github.com/SingularityRD/aidr/settings/secrets/actions`

| Secret Name | Value Source | Required For |
|-------------|--------------|--------------|
| `GITHUB_TOKEN` | GitHub Actions token with protected `packages: write` permission | Private GitHub Packages publishing |
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
| `SENTRY_DSN` | Optional dashboard error reporting; Node runtime also requires `SENTRY_ENABLED=true`/`1` |
| `STRIPE_SECRET_KEY` | Live payments (not provisioned yet) |
| `STRIPE_WEBHOOK_SECRET` | Webhook validation (not provisioned yet) |
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

Use Keychain Access or an approved interactive secret manager to add the real
value. Do not pass a live secret as the `security -w` argument: command arguments
can be exposed in process inspection and shell history. A retrieved value is
shown only through the process environment in the example below; avoid shell
tracing and clear the variable as soon as the dependent command finishes.

```bash
# Retrieve only for the shortest required process lifetime; do not echo it.
export ANTHROPIC_API_KEY=$(security find-generic-password -s "aidr-anthropic-key" -w)
unset ANTHROPIC_API_KEY
```

#### 1Password CLI

```bash
# Store in 1Password, then:
export ANTHROPIC_API_KEY=$(op read "op://Private/Anthropic/credential")
```

#### direnv (per-directory)

Keep `.envrc` out of Git and verify it is ignored before adding any local secret.
Prefer a vault-backed value; never commit the file or paste real values into
example commands.

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
| `SENTRY_ENVIRONMENT` | production |
| `SENTRY_TRACES_SAMPLE_RATE` | 0.1 |
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
   CI uses the checksum-pinned official Gitleaks v8.30.1 release. On Windows x64, download
   [`gitleaks_8.30.1_windows_x64.zip`](https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip),
   verify the archive SHA-256 is `D29144DEFF3A68AA93CED33DDDF84B7FDC26070ADD4AA0F4513094C8332AFC4E`
   **before** extracting it, and point the local gate at the extracted executable. The gate
   also verifies that executable's SHA-256 is
   `17157E2EE8B76FC8B1D8BEE607A250E34B8A8023C8BC81822D4B5EE4D78FCB7C`:

   ```powershell
   $env:GITLEAKS_BIN = 'C:\path\to\verified\gitleaks.exe'
   & $env:GITLEAKS_BIN version # must print 8.30.1
   pnpm verify:secrets:current
   ```

   The current-tree gate includes tracked and non-ignored untracked files and has a negative
   control that must detect a fixture secret. A passing current-tree scan does **not** clear
   historical findings. A named Security owner must triage historical findings, revoke or
   rotate live credentials, and retain redacted evidence before first-customer acceptance.

### Detection

1. **GitHub Secret Scanning**
   - Enabled by default on public repos
   - Monitor: https://github.com/SingularityRD/aidr/security/secret-scanning

2. **CI/CD Detection**
   `.github/workflows/ci.yml` runs the current-tree gate with a checksum-pinned v8.30.1
   archive. The release workflow also runs a full-history scan; locally,
   `GITLEAKS_BIN=/path/to/verified/gitleaks bash scripts/pre-release-audit.sh` runs both.

3. **Local pre-commit hooks**
   Hooks are optional convenience checks; they do not replace the pinned CI and release gates.

### Response to Exposed Secret

The time bands below are suggested internal triage goals, not staffed coverage
or a customer response commitment. The incident runbook and approved customer
support schedule govern escalation; neither a clock nor an on-call route is
established by this checklist.

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
| Staging | Named access group **not held** | Approved request route **not held** |
| Production | Named access group **not held** | Verified request route **not held**; do not rely on `#infrastructure` until its ownership and access are tested |

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
| GitHub Packages | https://github.com/SingularityRD/aidr/packages | `GITHUB_TOKEN` with protected `packages: write` |
| Sentry | https://sentry.io/settings/account/api/auth-tokens/ | Auth Token |
| Anthropic | https://console.anthropic.com/settings/keys | API Key |
| Stripe | https://dashboard.stripe.com/apikeys | Secret Key |
| GitHub | https://github.com/settings/tokens | Personal Access Token |
| Supabase | https://app.supabase.com/project/_/settings/api | API Keys |

### Emergency Contacts

| Service | Support URL | Phone |
|---------|-------------|-------|
| GitHub Packages | https://support.github.com | - |
| Sentry | https://sentry.io/support | - |
| Stripe | https://support.stripe.com | +1 888-963-8442 |
| GitHub | https://support.github.com | - |
| Vercel | https://vercel.com/support | - |
