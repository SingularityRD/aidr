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
	"source_sha256": "75eaa765039560ba38037ee90c5d800fa13c65dde68c7d942ee02617ef1d24a5",
	"matrix_id": "aidr-privacy-data-flow-matrix",
	"matrix_status": "open",
	"matrix_updated_at": "unknown",
	"deployment_scope": "unknown",
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
			"destination": "local runtime and configured local files",
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
				"transfer_mechanism",
				"evidence[0]"
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
			"destination": "unknown",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "unknown",
			"unknowns": [
				"destination",
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism",
				"evidence[0]",
				"status"
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
			"destination": "unknown",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "unknown",
			"unknowns": [
				"destination",
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism",
				"evidence[0]",
				"status"
			]
		},
		{
			"flow_id": "DF-004",
			"data_class": "deep-scan input and result",
			"fields": [
				"scan type",
				"target",
				"scan options",
				"result"
			],
			"purpose": "optional deep scanning",
			"trigger": "operator-configured scan request",
			"destination": "unknown",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "unknown",
			"unknowns": [
				"destination",
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism",
				"evidence[0]",
				"status"
			]
		},
		{
			"flow_id": "DF-005",
			"data_class": "URL reputation lookup",
			"fields": [
				"extracted URL",
				"product and runtime version",
				"optional authentication"
			],
			"purpose": "optional URL reputation lookup",
			"trigger": "URL reputation feature enabled",
			"destination": "unknown",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "unknown",
			"unknowns": [
				"destination",
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism",
				"evidence[0]",
				"status"
			]
		},
		{
			"flow_id": "DF-006",
			"data_class": "file and package reputation lookup",
			"fields": [
				"SHA-256 hashes",
				"package names",
				"registry metadata"
			],
			"purpose": "optional file and package reputation lookup",
			"trigger": "file or package reputation feature enabled",
			"destination": "unknown",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "unknown",
			"unknowns": [
				"destination",
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism",
				"evidence[0]",
				"status"
			]
		},
		{
			"flow_id": "DF-007",
			"data_class": "version check metadata",
			"fields": [
				"AIDR and runtime versions",
				"OS and architecture",
				"installation identifier"
			],
			"purpose": "optional version update check",
			"trigger": "configured session-start or update check",
			"destination": "unknown",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "unknown",
			"unknowns": [
				"destination",
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism",
				"evidence[0]",
				"status"
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
			"trigger": "runtime diagnostic sink explicitly configured",
			"destination": "unknown",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "unknown",
			"unknowns": [
				"destination",
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism",
				"evidence[0]",
				"status"
			]
		},
		{
			"flow_id": "DF-009",
			"data_class": "browser diagnostics",
			"fields": [
				"browser events",
				"traces",
				"breadcrumbs and route context"
			],
			"purpose": "optional browser reliability and security diagnostics",
			"trigger": "browser diagnostic sink explicitly configured",
			"destination": "unknown",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "unknown",
			"unknowns": [
				"destination",
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism",
				"evidence[0]",
				"status"
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
			"destination": "unknown",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "unknown",
			"unknowns": [
				"destination",
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism",
				"evidence[0]",
				"status"
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
			"destination": "unknown",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "unknown",
			"unknowns": [
				"destination",
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism",
				"evidence[0]",
				"status"
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
			"destination": "unknown",
			"destination_domain": "unknown",
			"region": "unknown",
			"subprocessor": "unknown",
			"lawful_basis": "unknown",
			"retention": "unknown",
			"deletion": "unknown",
			"access": "unknown",
			"transfer_mechanism": "unknown",
			"status": "unknown",
			"unknowns": [
				"destination",
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism",
				"evidence[0]",
				"status"
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
			"destination": "unknown",
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
				"destination",
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism",
				"evidence[0]"
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
			"destination": "unknown",
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
				"destination",
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism",
				"evidence[0]"
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
				"transfer_mechanism",
				"evidence[0]"
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
			"destination": "unknown",
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
				"destination",
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism",
				"evidence[0]"
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
			"destination": "unknown",
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
				"destination",
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism",
				"evidence[0]"
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
			"destination": "unknown",
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
				"destination",
				"destination_domain",
				"region",
				"subprocessor",
				"lawful_basis",
				"retention",
				"deletion",
				"access",
				"transfer_mechanism",
				"evidence[0]"
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
				"transfer_mechanism",
				"evidence[0]"
			]
		}
	],
	"limitations": [
		"This is a source-grounded engineering inventory and a fill-in template, not a measurement of a deployed environment.",
		"Unknown values are intentionally preserved; they must not be converted into a no-data or local-only conclusion.",
		"The validator checks schema shape, duplicate identifiers, explicit unknown declarations, and acceptance-state consistency only."
	]
};
