// Generated from docs/production-readiness/privacy-data-flow-matrix.json; do not edit.
// Regenerate: node scripts/sync-compliance-data-flows.mjs --write

export interface ComplianceDataFlow {
	readonly flow_id: string;
	readonly data_class: string;
	readonly fields: readonly string[];
	readonly purpose: string;
	readonly trigger: string;
	readonly destination: string;
	readonly destination_domain: string;
	readonly region: string;
	readonly subprocessor: string;
	readonly lawful_basis: string;
	readonly retention: string;
	readonly deletion: string;
	readonly access: string;
	readonly transfer_mechanism: string;
	readonly status: string;
	readonly unknowns: readonly string[];
}

export const COMPLIANCE_DATA_FLOW_MATRIX: {
	readonly source: string;
	readonly source_sha256: string;
	readonly matrix_id: string;
	readonly matrix_status: string;
	readonly matrix_updated_at: string;
	readonly deployment_scope: string;
	readonly flows: readonly ComplianceDataFlow[];
	readonly limitations: readonly string[];
} = {
	"source": "docs/production-readiness/privacy-data-flow-matrix.json",
	"source_sha256": "aebf04d0366716c99853c15dfbae47ede2b53e8fe5b81c207e8f653bb76fcee7",
	"matrix_id": "aidr-privacy-data-flow-matrix",
	"matrix_status": "open",
	"matrix_updated_at": "2026-10-06",
	"deployment_scope": "Source inventory only: aidr self-hosted/Supabase, separately deployed aidr-landing Clerk/Firestore/Polar, optional privacy text service and MCP gateway; no deployed customer scope selected or accepted",
	"flows": [
		{
			"flow_id": "DF-001",
			"data_class": "local detection and evidence",
			"fields": [
				"tool inputs",
				"extracted URLs and paths",
				"verdicts",
				"incident records"
			],
			"purpose": "local evaluation and evidence recording",
			"trigger": "tool evaluation or local audit configuration",
			"destination": "Runtime process and configured local JSONL audit/incident files; remote paths recorded separately",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "Runtime OS user; actual host ACLs, backup readers and operator access require host evidence",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-002",
			"data_class": "managed telemetry",
			"fields": [
				"installation and runtime identifiers",
				"verdict",
				"artifact hashes or summaries",
				"incident fields"
			],
			"purpose": "optional managed event synchronization",
			"trigger": "managed mode with audit synchronization enabled",
			"destination": "Configured managed ingest API and tenant event/incident database after a durable installation-bound local queue",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "Device credential for ingest, tenant-scoped database/API access and privileged deployment operators; actual grants require live evidence",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-003",
			"data_class": "central discovery metadata",
			"fields": [
				"tenant and collector identifiers",
				"cycle identifier",
				"origin",
				"reachability and error code"
			],
			"purpose": "optional central discovery collection",
			"trigger": "configured discovery collection or upload",
			"destination": "Configured discovery API and tenant-scoped discovery tables; collector origins reject paths, query strings and embedded credentials",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "Authenticated tenant collector and configured dashboard tenant roles; actual grants require live evidence",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-004",
			"data_class": "deep-scan input and result",
			"fields": [
				"scan type",
				"target and options",
				"agent config and optional prompt",
				"configured evaluation model/base URL/token",
				"findings and task state"
			],
			"purpose": "optional deep scanning",
			"trigger": "operator-configured scan request",
			"destination": "Configured AIG_BRIDGE_URL (source default http://localhost:8099), then configured AIG task service and any selected scan/model provider",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "Configured authenticated bridge caller, tenant task authorization, bridge/AIG service operators; upstream provider access unresolved",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-005",
			"data_class": "URL reputation lookup",
			"fields": [
				"eligible extracted URL",
				"product/runtime version",
				"optional authentication header"
			],
			"purpose": "optional URL reputation lookup",
			"trigger": "URL reputation feature enabled",
			"destination": "Configured url_check.endpoint; source default https://aidr-proxy.svc.singularityrd.com/url-check. Eligible URL lookup may disclose hostname/path; credentials/fragments and non-opted-in query URLs are withheld",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-006",
			"data_class": "file and package reputation lookup",
			"fields": [
				"SHA-256 file/package hashes",
				"package name/version",
				"registry response metadata",
				"optional configured reputation authentication"
			],
			"purpose": "optional file and package reputation lookup",
			"trigger": "file or package reputation feature enabled",
			"destination": "Configured file reputation endpoint and public registry metadata APIs (registry.npmjs.org and pypi.org); signed local feed may be selected separately",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-007",
			"data_class": "version check metadata",
			"fields": [
				"AIDR/runtime version",
				"OS/version and architecture",
				"optional installation ID",
				"optional authentication header"
			],
			"purpose": "optional version update check",
			"trigger": "configured session-start or update check",
			"destination": "Source default https://aidr-proxy.svc.singularityrd.com/v1/version-check; skipped for development versions or AIDR_SKIP_VERSION_CHECK=1",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-008",
			"data_class": "runtime diagnostics",
			"fields": [
				"scrubbed event attributes",
				"bounded request status and duration",
				"local audit context"
			],
			"purpose": "optional runtime reliability and security diagnostics",
			"trigger": "Explicit runtime SENTRY_ENABLED and DSN, or operator-configured monitoring",
			"destination": "Configured runtime Sentry sink only when explicitly enabled with DSN; deployment health probes use separately configured service endpoints",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-009",
			"data_class": "browser diagnostics",
			"fields": [
				"redacted browser events/traces/breadcrumbs",
				"query-free request URL and HTTP method",
				"route/error metadata; attached user/body/header fields omitted"
			],
			"purpose": "optional browser reliability and security diagnostics",
			"trigger": "browser diagnostic sink explicitly configured",
			"destination": "Configured browser Sentry DSN; absent DSN skips initialization, sendDefaultPii=false and trace sample rate defaults to zero",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-010",
			"data_class": "response webhook data",
			"fields": [
				"quarantine identifiers",
				"original path",
				"hash and size",
				"threat identifier"
			],
			"purpose": "optional operator-configured response notification",
			"trigger": "configured response webhook or alert",
			"destination": "Operator-configured response webhook/Slack destination; source does not select an operated channel",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-011",
			"data_class": "exports and support artifacts",
			"fields": [
				"tenant audit records",
				"allowlisted diagnostic summary",
				"export metadata"
			],
			"purpose": "customer-selected export or consent-gated support workflow",
			"trigger": "explicit export or support-bundle operation",
			"destination": "Tenant audit-export Storage object and temporary signed download URL; support tool writes a consent-gated local metadata bundle and does not upload it",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "Source audit-export expiry/reaper and offboarding use exact-path authorization, absence observation and ACK; local support bundle removal and recipient deletion need ticket evidence; provider physical erasure/backups not certified",
			"access": "Authorized tenant audit exporter, expiring signed-URL holder, privileged Storage operators and explicitly consented support recipient",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-012",
			"data_class": "persistence and disaster recovery",
			"fields": [
				"managed events and incidents",
				"credentials",
				"queues",
				"database and object backups"
			],
			"purpose": "configured persistence, backup, and recovery workflow",
			"trigger": "managed persistence or operator-selected backup operation",
			"destination": "Configured local queue/vault and database/Storage; encrypted backup plus separately configured offsite destination",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "Tenant offboarding and scheduled retention include hold checks and application receipts; local/remote backup expiry, replicas and provider erasure require separate evidence",
			"access": "Runtime OS user, approved deployment/backup operators and selected provider administrators; actual roles/key custody unresolved",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-013",
			"data_class": "authentication and identity",
			"fields": [
				"email",
				"auth user identifier",
				"session and factor state",
				"SAML provider identity"
			],
			"purpose": "user sign-in, MFA, SSO and recovery",
			"trigger": "customer sign-in or identity-security action",
			"destination": "Configured Supabase Auth and configured customer SAML/OIDC IdP",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "Authenticated user/factor-qualified tenant identity; owner actions rechecked server-side; Auth/IdP operator access requires provider evidence",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-014",
			"data_class": "authentication email delivery",
			"fields": [
				"recipient email",
				"one-time sign-in or recovery link",
				"delivery metadata"
			],
			"purpose": "deliver sign-in and recovery messages",
			"trigger": "one-time sign-in or account recovery request",
			"destination": "Supabase Auth configured SMTP/email delivery service and recipient mailbox; provider is selected by runtime configuration",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-015",
			"data_class": "trial legal acceptance record",
			"fields": [
				"actor and tenant identifiers",
				"Terms and Privacy versions, hashes and URLs",
				"approval reference",
				"audit timestamp"
			],
			"purpose": "record exact legal-document acceptance before a trial starts",
			"trigger": "verified user starts a configured cloud trial",
			"destination": "control-plane admin audit log",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "Source uses tenant security-audit retention and hold/offboarding handling; default/allowed periods are in retention-holds.md. Actual customer policy and backup periods require approval",
			"deletion": "Hold-aware tenant offboarding/retention; provider backups and legally required evidence exceptions need separate disposition",
			"access": "Trial actor and tenant-scoped audit readers; privileged operators; actual deployed access review open",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-016",
			"data_class": "payment and entitlement evidence",
			"fields": [
				"user and tenant identifiers",
				"seat count and selected plan",
				"provider customer, session, invoice, payment and refund identifiers"
			],
			"purpose": "optional hosted checkout, settlement and entitlement reconciliation",
			"trigger": "explicitly enabled payment provider and customer purchase or refund",
			"destination": "Selected enabled Supabase billing provider checkout/portal/webhook and tenant billing/settlement ledger; legacy Stripe/Paddle routes alone do not select the sold provider",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "Source retains immutable settlement/idempotency evidence and uses tenant commercial-record policy; actual financial record obligation and expiry require Finance/Legal decision",
			"deletion": "unknown",
			"access": "Authenticated tenant billing actions, separately authorized Finance operators and verified provider webhooks; provider administrators require access review",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"deletion",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-017",
			"data_class": "enterprise directory provisioning",
			"fields": [
				"user email and display name",
				"external identity and group identifiers",
				"group memberships",
				"provisioning token"
			],
			"purpose": "optional customer directory synchronization and role mapping",
			"trigger": "customer-configured SCIM or directory group operation",
			"destination": "Configured Supabase SCIM/directory API, tenant membership/role mappings and customer-selected Entra/other directory provider; separate managed Clerk path is DF-020",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "Scoped provisioning token, permitted owner/admin directory actions and privileged operators; actual provider consent/grants unresolved",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-018",
			"data_class": "cloud edge proxy traffic",
			"fields": [
				"request URL and query",
				"HTTP headers and body",
				"client IP for device-start",
				"upstream response"
			],
			"purpose": "optional cloud dashboard asset and control-plane API delivery",
			"trigger": "request to a configured Cloudflare-hosted product origin",
			"destination": "Optional Cloudflare Worker product ingress, configured Supabase/API upstream and dashboard assets; Cloudflare placement/log retention require runtime/provider evidence",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-019",
			"data_class": "manual team invitation handoff",
			"fields": [
				"recipient email",
				"team and role",
				"one-time invitation URL",
				"expiry"
			],
			"purpose": "create an invitation for an operator to deliver through a separately chosen channel",
			"trigger": "team owner or admin creates or resends an invitation",
			"destination": "operator browser and an unknown manual delivery channel",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "Source bounded reaper deletes expired unaccepted invitations only after identity_membership retention, active-tenant and no-hold checks; accepted invitation/membership and delivery-provider data follow separate records",
			"access": "Tenant owner/admin invitation issuer and intended one-time-link recipient; manually selected transport provider unresolved",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-020",
			"data_class": "managed web identity and organizations",
			"fields": [
				"Clerk user/session/organization and current role identifiers",
				"reciprocal organization-to-existing-tenant binding",
				"policy requester and distinct approver identifiers"
			],
			"purpose": "Managed dashboard authentication, tenant access and dual-admin policy approval",
			"trigger": "Managed Clerk sign-in or tenant request",
			"destination": "Configured Clerk instance and Firestore organization/tenant mapping; no managed SCIM endpoint implied",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "Current Clerk organization memberships rechecked for tenant requests; current administrators for policy writes; privileged operators and provider account access require review",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-021",
			"data_class": "managed web control-plane persistence",
			"fields": [
				"installation and machine identifiers",
				"minimized event/incident fields",
				"signed policy and entitlement metadata",
				"export and response delivery metadata"
			],
			"purpose": "Managed ingestion, policy, billing/agent administration and audit exports",
			"trigger": "Enrolled agent or authenticated tenant API operation",
			"destination": "Configured Firebase/Firestore project and selected server hosting; browser reads use tenant-scoped API",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "Installation-scoped agent keys, current Clerk tenant roles and privileged Firebase/server operators; live Firestore rules acceptance open",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-022",
			"data_class": "managed web payments",
			"fields": [
				"customer email and existing tenant ID",
				"Polar product and seat quantity",
				"subscription/order/customer/payment metadata",
				"verified webhook and entitlement evidence"
			],
			"purpose": "Configured recurring payment and finite managed entitlement reconciliation",
			"trigger": "Enabled approved product checkout or verified provider webhook",
			"destination": "Configured Polar sandbox/production account and Firestore billing records; not the Supabase legacy payment path",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "Configured provider credential and verified webhook; tenant billing authorization; actual provider access and contracts require Finance review",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-023",
			"data_class": "landing contact submission and bot prevention",
			"fields": [
				"contact name/email/company/message",
				"submission timing/honeypot",
				"rate-limit subject",
				"optional Turnstile token and remote IP"
			],
			"purpose": "Customer-selected sales contact delivery and abuse prevention",
			"trigger": "Same-origin contact POST with valid bounded input; challenge only if configured",
			"destination": "Configured contact webhook; optional challenges.cloudflare.com Turnstile validation; optional shared Firestore rate-limit record",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "Configured contact recipient and server operators; restricted credentials; recipient retention/access requires approval",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-024",
			"data_class": "private text-service provider egress",
			"fields": [
				"tenant/user/device/provider identifiers and signed grant",
				"bounded text input and sanitized output",
				"redaction/vault audit metadata",
				"provider response or withhold status"
			],
			"purpose": "Protect the explicitly routed text request and response with provisioned policy, approved NER and durable session broker",
			"trigger": "Approved application sends POST /v1/egress through configured client mTLS and signed user/device/provider authorization",
			"destination": "One fixed configured OpenAI Responses or Gemini generateContent provider, administrator-provisioned local session SQLite and approved local NER worker; no all-egress claim",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "Enrolled device certificate, signed user/device/provider grant, approved broker session; service account/provider operators and vault key custody require actual host acceptance",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"transfer_mechanism"
			]
		},
		{
			"flow_id": "DF-025",
			"data_class": "MCP gateway routed tool traffic",
			"fields": [
				"tenant/client/server/tool identifiers",
				"bounded tool arguments and result",
				"configured upstream MCP authentication",
				"audit/attestation metadata"
			],
			"purpose": "Authenticate and inspect explicitly routed supported MCP requests/responses",
			"trigger": "Authorized configured MCP client uses loopback gateway/stdio route",
			"destination": "Fixed configured MCP server endpoints and local audit state; binary/server-initiated method coverage must match accepted profile",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "Tenant-bound client and server/tool/method allowlists plus configured upstream credentials; actual upstream processor roles remain open",
			"transfer_mechanism": "unknown",
			"status": "inventory",
			"unknowns": [
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"transfer_mechanism"
			]
		}
	],
	"limitations": [
		"This is a source-grounded engineering inventory and a fill-in template, not a measurement of a deployed environment.",
		"Unknown values are intentionally preserved; they must not be converted into a no-data or local-only conclusion.",
		"The validator checks schema shape, duplicate identifiers, explicit unknown declarations, and acceptance-state consistency only.",
		"The 2026-10-06 source expansion records 25 flows, including the sibling managed web app and narrow privacy/MCP routes. Optional flows are not automatically enabled. Source references are not runtime measurement or approval."
	]
};
