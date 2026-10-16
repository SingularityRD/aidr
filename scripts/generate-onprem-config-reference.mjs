#!/usr/bin/env node
/**
 * Generate the on-prem configuration reference from one catalog:
 *   docs/operations/onprem-config-reference.md  (operator documentation)
 *   deploy/onprem/.env.onprem.example           (annotated, secret-free example)
 *
 * The catalog describes every variable `scripts/deployment-prepare.mjs` writes
 * into the private `.env`, `.env.functions`, `.env.readiness` and
 * `.env.ingress` files, plus the optional Compose interpolation overrides an
 * operator may add. `--check` fails when either generated file drifts from the
 * catalog, or when the catalog no longer matches the preparation script, the
 * posture scanner Compose file or `.env.posture-scanner.example`.
 *
 * Usage: node scripts/generate-onprem-config-reference.mjs [--check]
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const REFERENCE_PATH = "docs/operations/onprem-config-reference.md";
export const EXAMPLE_PATH = "deploy/onprem/.env.onprem.example";

export const FILES = {
	".env": "Compose interpolation for the whole stack (Supabase, dashboard and, with --with-posture-scanner, the AI Security Posture scanner). Read by `docker compose` from the installation directory.",
	".env.functions": "Edge Functions runtime (`functions` service `env_file`). Holds the control-plane signing keys.",
	".env.readiness": "Host readiness-evidence and SIEM maintenance worker (systemd units under `maintenance/`).",
	".env.ingress": "Host device-start ingress signer (`ingress/device-start.mjs`) behind the TLS reverse proxy.",
};

// written: always | self-hosted | cloud | with-posture-scanner | override (never written; optional operator override)
// source: generated | generated-secret | derived | fixed | operator
const v = (file, name, written, source, value, description) => ({ file, name, written, source, value, description });

export const CATALOG = [
	v(".env", "COMPOSE_FILE", "always", "fixed", "compose.yml", "Compose file used when commands run from the installation directory."),
	v(".env", "SUPABASE_PUBLIC_URL", "always", "derived", "--supabase-url", "Public HTTPS API origin behind the customer ingress."),
	v(".env", "API_EXTERNAL_URL", "always", "derived", "<supabase-url>/auth/v1", "Auth callback base advertised by GoTrue."),
	v(".env", "SITE_URL", "always", "derived", "--dashboard-url", "Dashboard origin used in Auth redirects and emails."),
	v(".env", "ADDITIONAL_REDIRECT_URLS", "always", "derived", "<dashboard-url>/auth/callback,<dashboard-url>/auth/recover", "Only redirect targets Auth accepts."),
	v(".env", "DISABLE_SIGNUP", "self-hosted", "fixed", "true", "Public signup is closed; provision accounts through bootstrap."),
	v(".env", "AIDR_SIGNUP_MODE", "cloud", "fixed", "closed", "Managed-cloud signup mode (`closed` or `cloud`), mirrored by the dashboard."),
	v(".env", "ENABLE_ANONYMOUS_USERS", "always", "fixed", "false", "Anonymous Auth users are disabled."),
	v(".env", "ENABLE_PHONE_SIGNUP", "always", "fixed", "false", "Phone signup is disabled."),
	v(".env", "ENABLE_PHONE_AUTOCONFIRM", "always", "fixed", "false", "Phone numbers are never auto-confirmed."),
	v(".env", "POSTGRES_PASSWORD", "always", "generated-secret", "", "PostgreSQL superuser password."),
	v(".env", "JWT_SECRET", "always", "generated-secret", "", "HS256 secret that signs the anon and service-role JWTs."),
	v(".env", "ANON_KEY", "always", "generated-secret", "", "Public anon JWT (self-hosted); cloud mode writes a REPLACE_ placeholder for the project key."),
	v(".env", "SERVICE_ROLE_KEY", "always", "generated-secret", "", "Service-role JWT (self-hosted); cloud mode writes a REPLACE_ placeholder. Never expose to browsers."),
	v(".env", "DASHBOARD_PASSWORD", "always", "generated-secret", "", "Upstream Studio basic-auth password (Studio is served only on the loopback admin listener 127.0.0.1:8001)."),
	v(".env", "SECRET_KEY_BASE", "always", "generated-secret", "", "Realtime and Supavisor cookie/session secret."),
	v(".env", "VAULT_ENC_KEY", "always", "generated-secret", "", "Supabase Vault encryption key."),
	v(".env", "REALTIME_DB_ENC_KEY", "always", "generated-secret", "", "Realtime database encryption key."),
	v(".env", "PG_META_CRYPTO_KEY", "always", "generated-secret", "", "postgres-meta connection encryption key."),
	v(".env", "LOGFLARE_PUBLIC_ACCESS_TOKEN", "always", "generated-secret", "", "Upstream analytics public token (analytics is not started)."),
	v(".env", "LOGFLARE_PRIVATE_ACCESS_TOKEN", "always", "generated-secret", "", "Upstream analytics private token (analytics is not started)."),
	v(".env", "POOLER_TENANT_ID", "always", "generated", "aidr-<random>", "Upstream pooler tenant id (the pooler service is removed)."),
	v(".env", "MINIO_ROOT_PASSWORD", "always", "generated-secret", "", "Upstream MinIO password (only used by the optional upstream S3 profile)."),
	v(".env", "S3_PROTOCOL_ACCESS_KEY_ID", "always", "generated-secret", "", "Storage S3-protocol access key id."),
	v(".env", "S3_PROTOCOL_ACCESS_KEY_SECRET", "always", "generated-secret", "", "Storage S3-protocol secret; the doctor rejects the upstream demo value."),
	v(".env", "AIDR_METRICS_TOKEN", "always", "generated-secret", "", "Bearer token for the dashboard metrics endpoint; required by Compose."),
	v(".env", "OPENAI_API_KEY", "always", "operator", "", "Optional Studio SQL assistant key; blank disables it."),
	v(".env", "SMTP_HOST", "always", "operator", "", "SMTP relay host for Auth mail (password recovery). Once set, AIDR alert, invitation and governance digest mail use the same relay: the `SMTP_*` values reach the `functions` service through Compose interpolation and select its `smtp` mail provider."),
	v(".env", "SMTP_USER", "always", "operator", "", "SMTP user."),
	v(".env", "SMTP_PASS", "always", "operator", "", "SMTP password (secret)."),
	v(".env", "SMTP_ADMIN_EMAIL", "always", "operator", "", "Sender address for Auth mail."),
	v(".env", "SMTP_SENDER_NAME", "always", "fixed", "AIDR", "Display name for Auth mail."),
	v(".env", "FUNCTIONS_VERIFY_JWT", "always", "fixed", "false", "Edge Functions verify their own credentials; the gateway does not pre-verify JWTs."),
	v(".env", "AIDR_NOTIFICATION_DISPATCH_TOKEN", "self-hosted", "generated-secret", "", "Same value as in `.env.functions`; read only by the Compose `siem-forwarder` scheduler service, which POSTs to the `siem-forwarder` function (central SIEM forwarding). Without it the service reports unhealthy and forwards nothing."),
	v(".env", "AIDR_SIEM_FORWARD_INTERVAL_SECONDS", "override", "operator", "60", "Seconds between central SIEM forwarding runs of the `siem-forwarder` service (15-3600)."),
	v(".env", "SENTRY_DSN", "override", "operator", "", "Optional dashboard error reporting DSN; blank disables it."),
	v(".env", "SENTRY_ENVIRONMENT", "override", "operator", "production", "Sentry environment label (development installations default to `development`)."),
	v(".env", "SENTRY_TRACES_SAMPLE_RATE", "override", "operator", "0", "Sentry trace sampling rate."),
	v(".env", "AIDR_AUTH_METHODS", "override", "operator", "password", "Dashboard sign-in methods offered to users."),
	v(".env", "AIDR_OIDC_SSO", "override", "operator", "false", "`true` shows the work-email OIDC single sign-on form on the dashboard sign-in page (docs/operations/onprem-sso.md)."),
	v(".env", "AIDR_SAML_PROVIDERS", "override", "operator", "", "Dashboard SAML buttons: JSON array of `{\"providerId\",\"label\"}` for GoTrue SAML providers registered with --with-saml. Configure only one of the three AIDR_SAML_* settings."),
	v(".env", "AIDR_SAML_PROVIDER_ID", "override", "operator", "", "Single GoTrue SAML provider id offered on the sign-in page."),
	v(".env", "AIDR_SAML_DOMAIN", "override", "operator", "", "Email domain whose GoTrue SAML provider the sign-in page uses."),
	v(".env", "GOTRUE_SAML_ENABLED", "with-saml", "fixed", "true", "Turns on SAML 2.0 single sign-on in the self-hosted GoTrue (`auth` service)."),
	v(".env", "GOTRUE_SAML_PRIVATE_KEY", "with-saml", "generated-secret", "", "RSA-2048 SAML signing key (PKCS#1 DER, base64) generated on the preparing host; GoTrue publishes its certificate in the SP metadata."),
	v(".env", "AIDR_POSTGREST_DB_URI_PARAMS", "override", "operator", "keepalives=1&keepalives_idle=30&keepalives_interval=10&keepalives_count=3&tcp_user_timeout=20000", "Self-hosted only: libpq parameters appended to PostgREST's database URI. The default detects pooled connections on a dead network path (TCP keepalives for idle connections; `tcp_user_timeout` in ms for unacknowledged sends) without limiting query or request duration; see the 2026-10-11 load-soak drill addendum."),
	v(".env", "COMPOSE_PROFILES", "with-posture-scanner", "fixed", "posture-scanner", "Starts the posture scanner services with the stack; remove `posture-scanner` to keep them stopped."),
	v(".env", "POSTURE_SCANNER_SOURCE_VERSION", "with-posture-scanner", "derived", "v4.6.1-aidr.2", "Pinned scanner source tag; also the scanner server and worker image tag."),
	v(".env", "POSTURE_SCANNER_TZ", "with-posture-scanner", "fixed", "UTC", "Time zone inside the posture scanner containers."),
	v(".env", "POSTURE_SCANNER_AGENT_SHARED_SECRET", "with-posture-scanner", "generated-secret", "", "Authenticates worker registration and the internal scanner readiness route."),
	v(".env", "POSTURE_SCANNER_TRUSTED_SIGNING_KEY_ID", "with-posture-scanner", "operator", "--posture-scanner-signing-key-id", "Key id of the posture scanner release data-signing key."),
	v(".env", "POSTURE_SCANNER_TRUSTED_SIGNING_PUBLIC_KEY_SHA256", "with-posture-scanner", "derived", "SHA-256 of the SPKI DER key", "Pinned fingerprint of `posture-scanner/signing-public.pem`."),
	v(".env", "POSTURE_SCANNER_EXPECTED_DATA_BUNDLE_ID", "with-posture-scanner", "derived", "aig-data-manifest.json bundle_id", "Signed scanner data bundle the runtime must attest."),
	v(".env", "POSTURE_SCANNER_EXPECTED_SOURCE_COMMIT", "with-posture-scanner", "derived", "aig-data-manifest.json source.commit", "Scanner source commit the runtime must attest."),
	v(".env", "BRIDGE_AUTH_MODE", "with-posture-scanner", "fixed", "api_key", "Bridge authentication: `api_key` (isolated local sidecar) or `broker` (JWT)."),
	v(".env", "BRIDGE_API_KEY", "with-posture-scanner", "generated-secret", "", "Bearer key for bridge callers in `api_key` mode."),
	v(".env", "BRIDGE_METRICS_TOKEN", "override", "operator", "", "Optional bearer token for the bridge `GET /metrics` Prometheus scrape (secret); empty keeps it disabled, and a value equal to `BRIDGE_API_KEY` is refused."),
	v(".env", "BRIDGE_TASK_BACKEND", "with-posture-scanner", "fixed", "sqlite", "Task registry: `sqlite` (single host) or `postgres` (HA)."),
	v(".env", "BRIDGE_HA_REQUIRED", "with-posture-scanner", "fixed", "false", "`true` makes readiness refuse SQLite; set with the PostgreSQL backend."),
	v(".env", "BRIDGE_EGRESS_PROXY_URL", "with-posture-scanner", "fixed", "http://aig-egress:3128", "Deny-by-default egress gateway for remote scan traffic."),
	v(".env", "BRIDGE_TASK_POSTGRES_DSN", "override", "operator", "", "PostgreSQL DSN for the HA task registry (secret); requires migrations 001 and 002."),
	v(".env", "BRIDGE_JWT_SECRET", "override", "operator", "", "Broker-mode HS256 secret, at least 32 bytes (secret)."),
	v(".env", "BRIDGE_JWT_ISSUER", "override", "operator", "", "Broker-mode expected JWT issuer."),
	v(".env", "BRIDGE_JWT_AUDIENCE", "override", "operator", "", "Broker-mode expected JWT audience."),
	v(".env", "BRIDGE_JWT_REPLAY_DB", "override", "operator", "/app/state/jwt-replay.db", "SQLite JWT replay store (PostgreSQL backend uses the shared database)."),
	v(".env", "BRIDGE_AUTH_REQUIRED", "override", "operator", "true", "Inbound bridge authentication; never disable on a customer host."),
	v(".env", "BRIDGE_TENANT_REQUIRED", "override", "operator", "true", "Require `X-AIDR-Tenant-ID` on scan requests."),
	v(".env", "BRIDGE_REQUIRE_IDEMPOTENCY", "override", "operator", "true", "Require `Idempotency-Key` on submissions."),
	v(".env", "BRIDGE_RUNTIME_EGRESS_REQUIRED", "override", "operator", "true", "Refuse remote scans unless an egress proxy is configured."),
	v(".env", "BRIDGE_UPLOAD_ENABLED", "override", "operator", "true", "Enable tenant-scoped source uploads."),
	v(".env", "BRIDGE_UPLOAD_ROOT", "override", "operator", "/app/uploads", "Upload volume path inside the bridge."),
	v(".env", "BRIDGE_SOURCE_ROOT", "override", "operator", "/app/uploads", "Root that source-scan upload ids resolve beneath."),
	v(".env", "BRIDGE_TASK_DB", "override", "operator", "/app/state/tasks.db", "SQLite task registry path on the bridge state volume."),
	v(".env", "BRIDGE_CORS_ORIGINS", "override", "operator", "", "Browser origins allowed to call the bridge; blank allows none."),
	v(".env", "BRIDGE_DOCS_ENABLED", "override", "operator", "false", "Serve API docs; enable only behind a protected ingress."),
	v(".env", "BRIDGE_MAX_BODY_BYTES", "override", "operator", "52428800", "Maximum request body size."),
	v(".env", "BRIDGE_ALLOW_PRIVATE_TARGETS", "override", "operator", "false", "Allow private scan targets at submission (the egress gateway still refuses them)."),
	v(".env", "BRIDGE_VALIDATE_DNS", "override", "operator", "true", "Resolve and vet target hosts at submission; never disable for customers."),
	v(".env", "BRIDGE_LOG_LEVEL", "override", "operator", "INFO", "Bridge log level."),
	v(".env", "POSTURE_SCANNER_BIND_ADDRESS", "override", "operator", "127.0.0.1", "Host address the bridge port is published on."),
	v(".env", "POSTURE_SCANNER_BRIDGE_PORT", "override", "operator", "8099", "Host port for the authenticated bridge."),
	v(".env", "POSTURE_SCANNER_MIN_WORKERS", "override", "operator", "1", "Live workers required before the bridge reports ready."),
	v(".env", "POSTURE_SCANNER_AGENT_COUNT", "override", "operator", "1", "Scanner worker replicas; keep 1 until workers expose unique identities."),
	v(".env", "POSTURE_SCANNER_NO_PROXY", "override", "operator", "aig-server,localhost,127.0.0.1", "Destinations the worker reaches without the egress gateway."),
	v(".env", "POSTURE_SCANNER_SIGNING_PUBLIC_KEY_HOST_PATH", "override", "operator", "", "Standalone docker-compose.posture-scanner.yml only: host path of the scanner signing public key (prepared installs use `posture-scanner/signing-public.pem`)."),
	v(".env", "POSTURE_SCANNER_EGRESS_ALLOWLIST_PATH", "override", "operator", "./deploy/onprem/egress/allowlist.txt", "Standalone docker-compose.posture-scanner.yml only: egress allowlist path (prepared installs use `posture-scanner/egress/allowlist.txt`)."),
	v(".env", "POSTURE_SCANNER_BRIDGE_IMAGE_TAG", "override", "operator", "local", "Standalone docker-compose.posture-scanner.yml only: bridge image tag (prepared installs use the AIDR version)."),

	v(".env.functions", "AIDR_ALLOWED_ORIGINS", "always", "derived", "--dashboard-url", "Browser origins allowed by Edge Function CORS."),
	v(".env.functions", "AIDR_DASHBOARD_URL", "always", "derived", "--dashboard-url", "Dashboard origin used in links."),
	v(".env.functions", "AIDR_DASHBOARD_VERIFY_URL", "always", "derived", "<dashboard-url>/verify", "Device verification page."),
	v(".env.functions", "AIDR_PUBLIC_API_ORIGIN", "always", "derived", "--supabase-url", "Public API origin endpoints are enrolled against."),
	v(".env.functions", "AIDR_DEVELOPMENT_MODE", "always", "derived", "false", "`true` only for --development loopback installations."),
	v(".env.functions", "AIDR_ENTITLEMENT_SIGNING_KEY_ID", "always", "generated", "aidr-<random>", "Entitlement signing key id."),
	v(".env.functions", "AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64", "always", "generated-secret", "", "Ed25519 entitlement signing key (PKCS#8, base64)."),
	v(".env.functions", "AIDR_REVOCATION_SIGNING_KEY_ID", "always", "generated", "aidr-<random>", "Revocation list signing key id."),
	v(".env.functions", "AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64", "always", "generated-secret", "", "Ed25519 revocation signing key (PKCS#8, base64)."),
	v(".env.functions", "AIDR_DELEGATION_ISSUER", "always", "derived", "--supabase-url", "Issuer of delegated credentials; the doctor checks it matches this control plane."),
	v(".env.functions", "AIDR_DELEGATION_SIGNING_KEY_ID", "always", "generated", "aidr-delegation-<random>", "Delegated credential signing key id."),
	v(".env.functions", "AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64", "always", "generated-secret", "", "Ed25519 delegated credential signing key."),
	v(".env.functions", "AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64", "always", "generated", "", "Matching delegated credential verification key (public)."),
	v(".env.functions", "AIDR_PACK_MASTER_KEY_B64", "always", "generated-secret", "", "Master key from which each tenant's premium intel pack key is derived (HKDF-SHA256, key id `aidr-tenant-pack-v2.<tenant>.<fingerprint>`) and delivered in the signed entitlement; it encrypts nothing at rest itself. Encrypt tenant packs with `scripts/intel-pack-keys.mjs encrypt-pack --tenant-id`. Rotating it changes every tenant key id: re-encrypt tenant packs."),
	v(".env.functions", "AIDR_SHARED_PACK_KEYS", "override", "operator", "", "Keys of shared/vendor premium intel packs, `aidr-shared-pack-<label>=<base64 32-byte key>[,…]`, delivered to every premium_intel tenant (secret). The vendor supplies the key of a vendor-encrypted pack with the premium licence; `scripts/intel-pack-keys.mjs new-shared-key` creates one for operator-published packs. A malformed value delivers no shared key."),
	v(".env.functions", "AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING", "always", "fixed", "false", "Legacy self-service billing stays disabled."),
	v(".env.functions", "AIDR_PACK_DOWNLOAD_GRANT_SECRET", "always", "generated-secret", "", "HMAC secret for short-lived pack download grants."),
	v(".env.functions", "AIDR_APPROVAL_SIGNING_WRAP_KEY_B64", "always", "generated-secret", "", "Wraps the per-tenant dashboard approval signing keys (32 bytes, base64); without it dashboard approvals fail closed."),
	v(".env.functions", "AIDR_COMPLIANCE_SIGNING_KEY_ID", "always", "generated", "aidr-compliance-<random>", "Key id stamped into signed compliance evidence packs."),
	v(".env.functions", "AIDR_COMPLIANCE_SIGNING_PRIVATE_KEY_PKCS8_B64", "always", "generated-secret", "", "Ed25519 compliance report signing key (PKCS#8, base64), separate from the entitlement key; the public half is recorded for auditors in `deployment.json` (`compliance_signing.public_key_pem`; Helm: `compliance-signing-public.pem`). Without it reports carry a sha256 digest only."),
	v(".env.functions", "AIDR_BILLING_PROVIDER", "always", "operator", "", "Billing provider; blank for invoice/sales-led on-prem contracts."),
	v(".env.functions", "AIDR_LICENSE_PUBLIC_KEYS_B64", "always", "derived", "base64 of deploy/onprem/license-public-keys.json", "Trust root for signed license imports in the dashboard and Operator console (`aidr-license-public-keys-v1`, base64). Install the vendor-published registry before preparing; an empty registry refuses every import. Replacing it lets whoever writes it sign any seat count."),
	v(".env.functions", "AIDR_LICENSE_CUSTOMER_ID", "override", "operator", "", "Optional: refuse a license whose signed `customer_id` differs (2..32 characters of [a-z0-9-])."),
	v(".env.functions", "AIDR_DEVICE_START_INGRESS_SECRET", "always", "generated-secret", "", "Shared with `.env.ingress`; authenticates the device-start signer."),
	v(".env.functions", "AIDR_NOTIFICATION_ENCRYPTION_KEYS", "always", "generated-secret", "", "Alert channel keyring `<key id>:<base64 32-byte key>[,…]`; the first key encrypts channel destinations, every listed key decrypts."),
	v(".env.functions", "AIDR_NOTIFICATION_DISPATCH_TOKEN", "always", "generated-secret", "", "Bearer token the notification dispatcher timer presents to `notification-dispatch` (at least 32 characters). Each run also enqueues agent-offline and governance alerts."),
	v(".env.functions", "AIDR_RUNTIME_CAPABILITIES_BY_TENANT", "always", "operator", "{}", "Exact per-tenant runtime capability grants (`runtime_detectors`, `behavioral_learning_v1`) as a JSON map read from the preparing shell; `{}` grants none. `behavioral_learning_v1` requires `runtime_detectors`."),
	v(".env.functions", "AIDR_OIDC_INTERNAL_IDP_HOSTS", "always", "operator", "--oidc-internal-idp-hosts", "Exact `host[:port]` list (fully qualified names, comma separated) of internal identity providers the `oidc-sso` function may reach on private addresses (RFC 1918, CGNAT, IPv6 ULA). Blank keeps the public-only egress policy; a malformed value makes `oidc-sso` refuse every request."),
	v(".env.functions", "AIDR_OIDC_CLIENT_SECRET_BINDINGS", "override", "operator", "", "JSON binding of each OIDC client secret reference to one tenant and issuer (docs/production-readiness/oidc-sso-admin.md); the secret itself goes in `AIDR_OIDC_CLIENT_SECRET_<REF>`."),
	v(".env.functions", "AIDR_MAIL_PROVIDER", "override", "operator", "", "Outbound mail for e-mail alert channels, invitations and the governance digest: `smtp` (the organisation's relay from the `SMTP_*` values in `.env`), `resend` or `none`. Blank selects `smtp` when `SMTP_HOST` is set and no Resend key is configured, `resend` when `RESEND_API_KEY` and `AIDR_MAIL_FROM` are set, otherwise no e-mail delivery (other channels still work)."),
	v(".env.functions", "AIDR_SMTP_SECURITY", "override", "operator", "", "SMTP connection security: `starttls` (default; refuses a relay that does not offer STARTTLS), `tls` (implicit TLS, the default for port 465) or `none` (plaintext, only without `SMTP_USER`). Certificates are always verified."),
	v(".env.functions", "AIDR_SMTP_CA_PEM_B64", "override", "operator", "", "Base64 of a PEM bundle with the internal CA that issued the SMTP relay certificate; it replaces the system roots for that connection."),
	v(".env.functions", "AIDR_SIEM_ALLOW_PRIVATE_NETWORKS", "override", "operator", "false", "`true` lets SIEM destinations opt in to RFC 1918 / ULA / CGNAT collectors (typical on-prem QRadar, Wazuh, Splunk). Loopback, link-local and metadata addresses stay refused."),
	v(".env.functions", "RESEND_API_KEY", "override", "operator", "", "Resend API key for `AIDR_MAIL_PROVIDER=resend` (secret)."),
	v(".env.functions", "AIDR_MAIL_FROM", "override", "operator", "", "Sender address for AIDR e-mail (alerts, invitations, governance digest). With SMTP it defaults to `SMTP_SENDER_NAME <SMTP_ADMIN_EMAIL>`."),
	v(".env.functions", "AIDR_TENANT_INFLIGHT_CAPACITY", "override", "operator", "10", "Fair-share admission on `ingest` and `policy`: requests the deployment may have in flight, counted from before the API-key lookup. The count is kept as database leases shared by both functions, every edge worker and every replica (one acquire and one release RPC per request; a lease left by a killed worker expires after 60 s). The default matches the kit's 10-connection PostgREST pool; size it to the total PostgREST pool. Past it requests get 503 `service_overloaded` with `Retry-After`. A malformed value, or a failed lease RPC, refuses the request with 503 `tenant_limiter_unavailable` and is logged."),
	v(".env.functions", "AIDR_TENANT_INFLIGHT_MAX", "override", "operator", "7", "Most in-flight requests one tenant may hold; defaults to 75% of the capacity (7 at the default) and must not exceed it. Once total in-flight reaches it, a tenant above its fair share (capacity ÷ active tenants, at least the floor) gets 429 `tenant_overloaded` with `Retry-After` while tenants under their share are admitted."),
	v(".env.functions", "AIDR_TENANT_INFLIGHT_FAIR_SHARE_FLOOR", "override", "operator", "2", "Smallest fair share any tenant keeps under pressure (at most `AIDR_TENANT_INFLIGHT_MAX`)."),
	v(".env.functions", "AIDR_TENANT_INFLIGHT_RETRY_AFTER_SECONDS", "override", "operator", "1", "`Retry-After` seconds on `tenant_overloaded` and `service_overloaded` answers (1–60)."),

	v(".env.readiness", "AIDR_DEPLOYMENT_DIR", "always", "fixed", "/srv/aidr", "Installation directory the host workers operate on."),
	v(".env.readiness", "AIDR_HEALTH_STATE_DIR", "always", "fixed", "/srv/aidr/health", "Evidence files mounted read-only into the dashboard."),
	v(".env.readiness", "AIDR_SIGNING_KEY_EXPIRES_AT", "always", "generated", "prepared_at + 365 days", "Entitlement signing key rotation deadline (readiness evidence)."),
	v(".env.readiness", "AIDR_DELEGATION_SIGNING_KEY_EXPIRES_AT", "always", "generated", "prepared_at + 365 days", "Delegation signing key rotation deadline."),
	v(".env.readiness", "AIDR_TELEMETRY_QUEUE_ROOTS", "always", "derived", "--telemetry-queue-root", "Fleet telemetry queue roots under /var/lib/aidr-telemetry."),
	v(".env.readiness", "AIDR_DRAIN_SIEM", "always", "fixed", "true", "The maintenance worker drains queued SIEM deliveries."),

	v(".env.ingress", "AIDR_DEVICE_START_INGRESS_SECRET", "always", "generated-secret", "", "Same value as in `.env.functions`."),
	v(".env.ingress", "AIDR_DEVICE_START_PROXY_TOKEN", "always", "generated-secret", "", "Token the reverse proxy presents to the signer; independent of the ingress secret."),
	v(".env.ingress", "AIDR_DEVICE_START_UPSTREAM_URL", "always", "derived", "http://127.0.0.1:8000/functions/v1/device-start", "Edge Function the signer forwards to (cloud: provider HTTPS origin)."),
	v(".env.ingress", "AIDR_DEVICE_START_ANON_KEY", "self-hosted", "derived", "ANON_KEY", "Anon key the signer presents upstream."),
	v(".env.ingress", "AIDR_DEVICE_START_LISTEN_HOST", "always", "fixed", "127.0.0.1", "Signer listen address."),
	v(".env.ingress", "AIDR_DEVICE_START_TRUSTED_PEERS", "always", "fixed", "127.0.0.1,::1", "Exact peer addresses allowed to reach the signer."),
	v(".env.ingress", "AIDR_DEVICE_START_LISTEN_PORT", "always", "fixed", "8191", "Signer listen port."),
];

const SOURCE_LABEL = {
	generated: "generated",
	"generated-secret": "generated secret",
	derived: "derived from options",
	fixed: "fixed by preparation",
	operator: "operator",
};
const WRITTEN_LABEL = {
	always: "always",
	"self-hosted": "self-hosted only",
	cloud: "cloud only",
	"with-posture-scanner": "`--with-posture-scanner` only",
	"with-saml": "`--with-saml` only",
	override: "not written; optional override",
};

const escapeCell = (value) => String(value).replaceAll("|", "\\|");

export function renderReference(catalog = CATALOG) {
	const lines = [
		"# On-prem configuration reference",
		"",
		"<!-- Generated by scripts/generate-onprem-config-reference.mjs; edit the catalog there, then run `pnpm onprem:config-reference`. -->",
		"",
		"`scripts/deployment-prepare.mjs` writes four private files (mode `0600`) into the",
		"installation directory. Preparation generates every secret; none is printed and",
		"none belongs in source control. Rerunning preparation is not an upgrade: keep the",
		"directory and its secrets. `deploy/onprem/.env.onprem.example` lists the same",
		"variables as a secret-free annotated example.",
		"",
		"Column meaning: **Written** says when preparation writes the variable;",
		"**Source** says who decides the value. Variables marked *operator* may be",
		"edited in place, followed by `docker compose up -d` (Compose files) or a restart",
		"of the host unit (`.env.readiness`, `.env.ingress`). Do not edit generated",
		"secrets by hand; rotate them with the documented procedures. Keys inherited",
		"unchanged from the pinned Supabase `self-hosted/v0.8.1` `docker/.env.example`",
		"(for example `POSTGRES_HOST`, `POSTGRES_DB`, `API_GW_HTTP_PORT`) are not repeated here.",
		"",
	];
	for (const [file, purpose] of Object.entries(FILES)) {
		lines.push(`## \`${file}\``, "", purpose, "", "| Variable | Written | Source | Value / default | Purpose |", "| --- | --- | --- | --- | --- |");
		for (const entry of catalog.filter((item) => item.file === file)) {
			const value = entry.source === "generated-secret" ? "*(secret)*" : entry.value === "" ? "*(blank)*" : `\`${escapeCell(entry.value)}\``;
			lines.push(`| \`${entry.name}\` | ${WRITTEN_LABEL[entry.written]} | ${SOURCE_LABEL[entry.source]} | ${value} | ${escapeCell(entry.description)} |`);
		}
		lines.push("");
	}
	lines.push(
		"## Compose-level settings outside the environment files",
		"",
		"- Resource budgets: `--profile small|medium|large` from `deploy/onprem/resource-profile.json`.",
		"- Restart, log rotation and extra health checks: `deploy/onprem/compose.onprem.overlay.yml`.",
		"- Posture scanner egress allowlist: `posture-scanner/egress/allowlist.txt` in a `--with-posture-scanner` installation.",
		"- Installations prepared before the posture scanner rename keep working: every `POSTURE_SCANNER_*` Compose setting falls back to the name earlier releases wrote to `.env`.",
		"",
	);
	return lines.join("\n");
}

export function renderExample(catalog = CATALOG) {
	const lines = [
		"# AIDR on-prem configuration example (reference only).",
		"# Generated by scripts/generate-onprem-config-reference.mjs; do not edit by hand.",
		"#",
		"# scripts/deployment-prepare.mjs generates the real private files with fresh",
		"# secrets. Never copy a secret into this file. See",
		"# docs/operations/onprem-config-reference.md for every variable.",
	];
	for (const file of Object.keys(FILES)) {
		lines.push("", `# ---- ${file} ----`);
		for (const entry of catalog.filter((item) => item.file === file)) {
			const hint = `${SOURCE_LABEL[entry.source]}; ${WRITTEN_LABEL[entry.written].replaceAll("`", "")}`;
			const value = entry.source === "generated-secret" || entry.source === "derived" || entry.source === "generated" ? "" : entry.value;
			const derived = entry.source === "derived" || entry.source === "generated" ? ` (${entry.value})` : "";
			lines.push(`# ${hint}${derived}`);
			lines.push(`${entry.written === "override" ? "# " : ""}${entry.name}=${value}`);
		}
	}
	return `${lines.join("\n")}\n`;
}

/** Cross-checks that keep the catalog honest against the files it documents. */
export function catalogProblems(catalog = CATALOG) {
	const problems = [];
	const seen = new Set();
	for (const entry of catalog) {
		const key = `${entry.file}:${entry.name}`;
		if (seen.has(key)) problems.push(`duplicate catalog entry ${key}`);
		seen.add(key);
		if (!FILES[entry.file]) problems.push(`${entry.name} names an unknown file ${entry.file}`);
		if (!WRITTEN_LABEL[entry.written] || !SOURCE_LABEL[entry.source]) problems.push(`${entry.name} has an invalid written/source value`);
	}
	const prepare = readFileSync(join(root, "scripts/deployment-prepare.mjs"), "utf8");
	for (const entry of catalog.filter((item) => item.written !== "override")) {
		if (!new RegExp(`\\b${entry.name}\\b`).test(prepare)) problems.push(`${entry.file} ${entry.name} is catalogued but scripts/deployment-prepare.mjs no longer writes it`);
	}
	const documented = new Set(catalog.filter((item) => item.file === ".env").map((item) => item.name));
	// A legacy AIG_<X> name is accepted in Compose only as the fallback of a documented POSTURE_SCANNER_<X>.
	const legacyFallback = (name) => name.startsWith("AIG_") && documented.has(`POSTURE_SCANNER_${name.slice(4)}`);
	const scannerCompose = readFileSync(join(root, "docker-compose.posture-scanner.yml"), "utf8");
	for (const [, name] of scannerCompose.matchAll(/\$\{([A-Z][A-Z0-9_]*)/g)) {
		if (!documented.has(name) && !legacyFallback(name)) problems.push(`docker-compose.posture-scanner.yml interpolates ${name}, which the reference does not document`);
	}
	for (const [, name, fallback] of scannerCompose.matchAll(/\$\{POSTURE_SCANNER_([A-Z0-9_]+):-(\$\{AIG_[A-Z0-9_]+)?/g)) {
		if (fallback !== `\${AIG_${name}`) problems.push(`docker-compose.posture-scanner.yml: POSTURE_SCANNER_${name} must fall back to AIG_${name} so existing installations keep working`);
	}
	const scannerExample = readFileSync(join(root, ".env.posture-scanner.example"), "utf8");
	for (const [, name] of scannerExample.matchAll(/^#?\s*([A-Z][A-Z0-9_]*)=/gm)) {
		if (!documented.has(name)) problems.push(`.env.posture-scanner.example names ${name}, which the reference does not document`);
	}
	return problems;
}

function main(argv) {
	const check = argv.includes("--check");
	const unknown = argv.filter((argument) => argument !== "--check");
	if (unknown.length) throw new Error(`unknown argument: ${unknown[0]}`);
	const problems = catalogProblems();
	const outputs = [[REFERENCE_PATH, renderReference()], [EXAMPLE_PATH, renderExample()]];
	if (check) {
		for (const [path, content] of outputs) {
			let current = null;
			try { current = readFileSync(join(root, path), "utf8"); } catch { /* reported below */ }
			if (current !== content) problems.push(`${path} is stale; run pnpm onprem:config-reference`);
		}
		if (problems.length) {
			for (const problem of problems) console.error(`ERROR: ${problem}`);
			process.exitCode = 1;
			return;
		}
		console.log(`On-prem configuration reference is current (${CATALOG.length} variables).`);
		return;
	}
	if (problems.length) {
		for (const problem of problems) console.error(`ERROR: ${problem}`);
		process.exitCode = 1;
		return;
	}
	for (const [path, content] of outputs) writeFileSync(join(root, path), content, "utf8");
	console.log(`Wrote ${REFERENCE_PATH} and ${EXAMPLE_PATH} (${CATALOG.length} variables).`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	try {
		main(process.argv.slice(2));
	} catch (error) {
		console.error(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 1;
	}
}
