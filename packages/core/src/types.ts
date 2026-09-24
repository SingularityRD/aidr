/**
 * Zod schemas and inferred TypeScript types for Singularity AIDR.
 * Single source of truth for all data structures.
 */

import { z } from "zod";

// ── Logger interface (dependency injection) ─────────────────────────

export interface Logger {
	debug(msg: string, data?: Record<string, unknown>): void;
	info(msg: string, data?: Record<string, unknown>): void;
	warn(msg: string, data?: Record<string, unknown>): void;
	error(msg: string, data?: Record<string, unknown>): void;
}

/** No-op logger for when no logger is provided. */
export const nullLogger: Logger = {
	debug() {},
	info() {},
	warn() {},
	error() {},
};

/** Get a logger instance (currently returns nullLogger). */
function getLogger(): Logger {
	return nullLogger;
}

// ── Artifact ────────────────────────────────────────────────────────

export const ArtifactTypeSchema = z.enum(["url", "command", "file_path", "content"]);

export const ArtifactSchema = z.object({
	type: ArtifactTypeSchema,
	value: z.string(),
	context: z.string().optional(),
});

export type Artifact = z.infer<typeof ArtifactSchema>;

// ── Threat ──────────────────────────────────────────────────────────

export const SeveritySchema = z.enum(["critical", "high", "medium", "low"]);
export const ActionSchema = z.enum(["block", "require_approval", "log"]);

export const ThreatSchema = z.object({
	id: z.string(),
	category: z.string(),
	severity: SeveritySchema,
	confidence: z.number().min(0).max(1, "Confidence must be between 0 and 1"),
	action: ActionSchema,
	pattern: z.string(),
	match_on: z.union([z.string(), z.array(z.string())]),
	title: z.string(),
	expires_at: z.string().nullable().optional(),
	revoked: z.boolean().optional().default(false),
});

/** Raw threat from YAML (before compilation). */
export type ThreatData = z.infer<typeof ThreatSchema>;

/** Loaded threat with compiled regex and normalized match_on. */
export interface Threat {
	id: string;
	category: string;
	severity: "critical" | "high" | "medium" | "low";
	confidence: number;
	action: "block" | "require_approval" | "log";
	pattern: string;
	compiledPattern: RegExp;
	matchOn: Set<string>;
	title: string;
	expiresAt: Date | null;
	revoked: boolean;
}

// ── Heuristic match ─────────────────────────────────────────────────

export interface HeuristicMatch {
	threat: Threat;
	artifact: string;
	matchValue: string;
}

// ── URL Check ───────────────────────────────────────────────────────

export interface UrlCheckFinding {
	severityName: string;
	typeName: string;
}

export interface UrlCheckResult {
	url: string;
	isMalicious: boolean;
	findings: UrlCheckFinding[];
	flags: string[];
	/** Millisecond timestamp after which the checked source data must not be reused. */
	cacheValidUntil?: number;
}

// ── Verdict ─────────────────────────────────────────────────────────

export const DecisionSchema = z.enum(["allow", "deny", "ask"]);
export const VerdictSeveritySchema = z.enum(["info", "warning", "critical"]);

export type Decision = z.infer<typeof DecisionSchema>;
export type VerdictSeverity = z.infer<typeof VerdictSeveritySchema>;

/**
 * Verified `user -> agent -> tool -> resource` lineage carried by an
 * `aidr-delegation+jwt` credential.
 *
 * Attached to a verdict only after the credential verified against this exact
 * call, so its presence is itself the evidence that a delegated authorization
 * was checked. The compact bearer token is deliberately not part of this shape.
 */
export interface DelegationLineage {
	issuer: string;
	tenantId: string;
	subjectUserId: string;
	agentId: string;
	tool: { serverId: string; name: string };
	resource: { type: string; id: string };
	audience: string;
	scopes: string[];
	tokenId: string;
	delegationDepth: number;
	expiresAt: number;
	parentTokenId?: string;
}

export interface Verdict {
	decision: Decision;
	category: string;
	confidence: number;
	severity: VerdictSeverity;
	source: string;
	artifacts: string[];
	matchedThreatId: string | null;
	reasons: string[];
	/** Verified delegation lineage; absent when the call carried no credential. */
	delegation?: DelegationLineage;
}

// ── Package check ──────────────────────────────────────────────────

export interface PackageCheckResult {
	packageName: string;
	registry: "npm" | "pypi" | "unknown";
	verdict: "clean" | "not_found" | "suspicious_age" | "malicious" | "unknown";
	confidence: number;
	details: string;
	fileCheckSeverity?: string;
	ageDays?: number;
}

// ── AMSI Check ─────────────────────────────────────────────────────

export interface AmsiCheckResult {
	content: string;
	contentName: string;
	amsiResult: number;
	isDetected: boolean;
	isBlockedByAdmin: boolean;
}

export interface PolicyMatch {
	policyId: string;
	title: string;
	category: string;
	action: "block" | "require_approval" | "log";
	severity: "critical" | "high" | "medium" | "low";
	confidence: number;
	artifact: string;
}

export interface SignalSources {
	heuristicMatches: HeuristicMatch[];
	policyMatches?: PolicyMatch[];
	urlCheckResults: UrlCheckResult[];
	packageCheckResults?: PackageCheckResult[];
	amsiCheckResults?: AmsiCheckResult[];
}

// ── Cache ───────────────────────────────────────────────────────────

export interface CachedVerdict {
	verdict: Decision;
	severity: VerdictSeverity;
	reasons: string[];
	source: string;
}

export interface CachedEntry extends CachedVerdict {
	checkedAt: string;
	expiresAt: string;
	/** Required on cached URL allows so they cannot outlive their source reputation row. */
	sourceFreshUntil?: string;
	aidrVersion?: string;
}

export interface CacheStore {
	urls: Record<string, CachedEntry>;
	commands: Record<string, CachedEntry>;
	packages: Record<string, CachedEntry>;
}

// ── Config ──────────────────────────────────────────────────────────

export const SensitivitySchema = z.enum(["paranoid", "balanced", "relaxed"]);

const OperatingModeSchema = z.enum(["local", "managed"]);

export const AuthConfigSchema = z.object({
	/**
	 * API key used to authenticate to Singularity AIDR managed services (control plane, premium packs).
	 */
	api_key: z.string().optional(),
	api_key_ref: z
		.object({
			store: z.enum(["windows-dpapi", "macos-keychain", "linux-secret-service"]),
			id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/),
			created_at: z.string().datetime(),
		})
		.optional(),
	/**
	 * Optional one-time enrollment token used to bootstrap managed mode (exchanged for an API key).
	 */
	enrollment_token: z.string().optional(),
	enrollment_token_ref: z
		.object({
			store: z.enum(["windows-dpapi", "macos-keychain", "linux-secret-service"]),
			id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/),
			created_at: z.string().datetime(),
		})
		.optional(),
});

export const ControlPlaneConfigSchema = z.object({
	/**
	 * Enables managed control plane features (dashboard telemetry, agent seat enforcement).
	 * Fail-open: if cloud calls fail, protection can continue offline within grace.
	 */
	enabled: z.boolean().default(true),
	/**
	 * Base URL for the control plane ingest API (no trailing slash).
	 * Example: "https://aidr.example.com"
	 */
	endpoint: z.string().default(""),
	/** Explicitly allow plaintext HTTP to a loopback endpoint for local development. */
	allow_insecure_loopback: z.boolean().default(false),
	/** Request timeout for control-plane calls. */
	timeout_seconds: z.number().default(0.5),
	/** Send runtime verdict events to the control plane for the dashboard. */
	send_audit_logs: z.boolean().default(true),
	/** Also send clean (allow) verdicts. */
	send_clean_verdicts: z.boolean().default(false),
	/** Also send incident events (if the runtime emits them). */
	sync_incidents: z.boolean().default(false),
	/**
	 * Grace period for managed mode when the control plane is unreachable.
	 * Used to avoid flapping between "online" and "offline" states.
	 */
	grace_period_hours: z.number().default(72),
	/**
	 * Remote telemetry redaction mode.
	 * - none: send raw artifacts/summaries (least private)
	 * - hash: replace sensitive fields with sha256 digests (default)
	 * - full: omit sensitive fields entirely (most private)
	 */
	redact_mode: z.enum(["none", "hash", "full"]).default("hash"),
	remote_policy_cache_path: z.string().default("~/.singularity-aidr/remote-policy-cache"),
	remote_policy_cache_enabled: z.boolean().default(true),
	/** Enrolled endpoints must retain central controls or block when unavailable. */
	remote_policy_required: z.boolean().default(false),
	/** Maximum stale-policy grace after its normal refresh expiry; never renewed offline. */
	remote_policy_offline_grace_seconds: z.number().int().min(0).max(604800).default(3600),
});

const PolicyFilesystemSchema = z.object({
	enabled: z.boolean().default(false),
	allowed_write_roots: z.array(z.string()).default([]),
	deny_write_patterns: z.array(z.string()).default([]),
	outside_root_action: z.enum(["block", "require_approval"]).default("require_approval"),
});

const PolicyNetworkSchema = z.object({
	enabled: z.boolean().default(false),
	allow_domains: z.array(z.string()).default([]),
	deny_domains: z.array(z.string()).default([]),
	deny_private_ips: z.boolean().default(true),
	deny_action: z.enum(["block", "require_approval"]).default("block"),
	outside_allow_action: z.enum(["block", "require_approval"]).default("require_approval"),
});

const PolicyShellSchema = z.object({
	enabled: z.boolean().default(false),
	deny_patterns: z.array(z.string()).default([]),
	deny_action: z.enum(["block", "require_approval"]).default("block"),
});

const PolicyMcpSchema = z.object({
	enabled: z.boolean().default(false),
	default_action: z.enum(["block", "require_approval", "allow"]).default("require_approval"),
	inventory_paths: z.array(z.string()).default([]),
	allow_servers: z.array(z.string()).default([]),
	deny_servers: z.array(z.string()).default([]),
	require_approval_servers: z.array(z.string()).default([]),
	risky_server_action: z.enum(["block", "require_approval", "allow"]).optional(),
	deny_tools: z.array(z.string()).default([]),
	allow_tools: z.array(z.string()).default([]),
	require_approval_tools: z.array(z.string()).default([]),
	unknown_server_action: z.enum(["block", "require_approval", "allow"]).default("require_approval"),
});

const PolicyConfigSchema = z.object({
	enabled: z.boolean().default(false),
	filesystem: PolicyFilesystemSchema.default({}),
	network: PolicyNetworkSchema.default({}),
	shell: PolicyShellSchema.default({}),
	mcp: PolicyMcpSchema.default({}),
	runtime_defaults: z.record(z.string(), z.unknown()).default({}),
	ai_infrastructure: z
		.object({
			enabled: z.boolean().default(false),
			targets: z.array(z.string().url()).max(200).default([]),
			report_path: z.string().default("~/.singularity-aidr/infra-scan.json"),
			max_age_seconds: z.number().int().min(1).max(604800).default(3600),
			critical_action: z.enum(["block", "require_approval"]).default("block"),
			unverified_action: z.enum(["allow", "block", "require_approval"]).default("require_approval"),
		})
		.default({}),
});

export const IntelConfigSchema = z.object({
	enabled: z.boolean().default(false),
	url_denylist_path: z.string().default("~/.singularity-aidr/intel/url_denylist.txt"),
});

export const IntegrityConfigSchema = z.object({
	enabled: z.boolean().default(false),
	/**
	 * Optional public keys (PEM) used to verify signed manifests and intel packs.
	 * If empty, development verification is skipped; commercial startup is rejected.
	 */
	public_keys_pem: z.array(z.string()).default([]),
	/**
	 * When true, connectors may verify their on-disk assets at session start.
	 * This should be enabled in commercial builds.
	 */
	verify_on_start: z.boolean().default(true),
});

export const IntelPacksConfigSchema = z.object({
	enabled: z.boolean().default(false),
	/**
	 * Root directory containing signed intel packs.
	 * Default keeps all intel under the AIDR directory.
	 */
	packs_dir: z.string().default("~/.singularity-aidr/intel/packs"),
	/**
	 * Trusted public keys file (JSON: { key_id: public_key_pem }).
	 * Used to verify intel pack signatures.
	 */
	trusted_keys_path: z.string().default("~/.singularity-aidr/intel/trusted-keys.json"),
	/**
	 * Enforce signature verification for packs when keys are configured.
	 * Fail-open if keys are missing.
	 */
	verify_signatures: z.boolean().default(true),
	/** Cache TTL for reloading packs from disk. */
	cache_ttl_seconds: z.number().default(60),
	/**
	 * Allow using an expired but correctly signed pack within this grace window.
	 * Set to 0 for strict expiry.
	 */
	expired_grace_hours: z.number().default(72),
});

const LicensingConfigSchema = z.object({
	enabled: z.boolean().default(true),
	/**
	 * Public keys (PEM or base64 SPKI) used to verify signed entitlement snapshots and revocation feeds.
	 * If empty, commercial licensing verification is skipped (development mode).
	 */
	public_keys_pem: z.array(z.string()).default([]),
	/**
	 * When true in managed mode, an invalid or missing signature will lock premium features.
	 * Core local protections continue regardless (fail-open).
	 */
	require_signed_entitlements: z.boolean().default(true),
	/**
	 * Enable best-effort revocation feed consumption.
	 * Revocations can disable premium packs and invalidate cached entitlements.
	 */
	revocations_enabled: z.boolean().default(true),
	revocations_cache_path: z.string().default("~/.singularity-aidr/revocations.json"),
	revocations_refresh_seconds: z.number().default(3600),
});

export const IncidentConfigSchema = z.object({
	enabled: z.boolean().default(true),
	/**
	 * Local store mode.
	 * - jsonl: append-only log in ~/.singularity-aidr/audit.jsonl (default)
	 * - sqlite: future; requires a sqlite backend
	 */
	store: z.enum(["jsonl", "sqlite"]).default("jsonl"),
	/**
	 * If true, correlate repeated suspicious events into a single incident record.
	 * This is lightweight and local-first.
	 */
	correlation_enabled: z.boolean().default(true),
});

const ResponseConfigSchema = z.object({
	emit_incidents: z.boolean().default(true),
	/**
	 * Response actions taken when the runtime blocks a tool call.
	 *
	 * These are OFF by default. A guardrail that silently moves or copies a
	 * user's files on its own initiative is more dangerous than one that only
	 * blocks, so every action here is an explicit opt-in.
	 *
	 * Snapshot semantics: the connector decides a tool call BEFORE it executes,
	 * so the target of a blocked write still holds its previous contents. We take
	 * a COPY into the response vault and never move or delete the original - the
	 * blocked action did not happen, so the file must be left exactly as it was.
	 */
	actions: z
		.object({
			/** Copy the existing target of a blocked write/edit/delete into the vault. */
			snapshot_on_deny: z.boolean().default(false),
			/** Where snapshots are written. */
			snapshot_dir: z.string().default("~/.singularity-aidr/response-vault"),
			/**
			 * Only snapshot when the verdict severity is at least this level, so a
			 * low-severity deny cannot fill the vault. These are the runtime's own
			 * verdict severities (`VerdictSeverity`), not the threat-rule severities.
			 */
			snapshot_min_severity: z.enum(["info", "warning", "critical"]).default("warning"),
			/** Skip files larger than this (bytes). Default 10 MiB. */
			snapshot_max_bytes: z
				.number()
				.int()
				.positive()
				.default(10 * 1024 * 1024),
			/**
			 * Snapshot the target of a DESTRUCTIVE operation that is about to be
			 * ALLOWED, so the operation can actually be rolled back if it goes wrong.
			 *
			 * Snapshot-on-deny (above) cannot be rolled back into anything useful: the
			 * blocked call never ran, so the file was never changed. The dangerous case
			 * is the opposite one - a destructive command the runtime decided to allow.
			 * That call runs, and without a pre-operation copy there is nothing to
			 * restore.
			 *
			 * OFF by default: this copies user files during a path that the runtime
			 * decided was safe, which is exactly the kind of unilateral action that must
			 * be an explicit operator choice.
			 */
			snapshot_before_destructive: z.boolean().default(false),
			/**
			 * Path prefixes a pre-operation snapshot may copy. This is a second,
			 * independent gate: even with `snapshot_before_destructive` on, an EMPTY
			 * list snapshots nothing. Guarding the whole filesystem was never the
			 * intent - the operator names the trees that are expensive to lose.
			 *
			 * Entries are matched as path prefixes (after `~` expansion); an entry
			 * ending in `/**` or `/*` matches everything under it.
			 */
			protect_paths: z.array(z.string()).default([]),
			/** Directory holding pre-operation (rollback) snapshots. */
			snapshot_root_dir: z.string().default("~/.singularity-aidr/snapshots"),
			/**
			 * How long a pre-operation snapshot is kept so it stays restorable.
			 * 0 disables pruning. Retention is applied when a rollback snapshot is
			 * taken, so stale copies cannot accumulate without bound.
			 */
			snapshot_retention_days: z.number().int().min(0).default(7),
		})
		.default({}),
	/**
	 * Tamper-evident response chain.
	 *
	 * `logging.path` (audit.jsonl) is a plain append-only log: edit it and nothing
	 * detects the change. Response records additionally go to the signed chain in
	 * `response-audit.ts` (Ed25519 signature + SHA-256 hash chain), which is what
	 * makes "the runtime did X" defensible after the fact.
	 *
	 * OFF by default: it provisions a signing key on disk and never silently
	 * downgrades - if signing cannot happen, no record is written and the caller is
	 * told, rather than an unsigned line being passed off as signed.
	 */
	audit: z
		.object({
			/** Write response records to the signed chain. */
			signed_chain: z.boolean().default(false),
			/** Where the signed chain lives. Confined to the AIDR state directory. */
			path: z.string().default("~/.singularity-aidr/response-audit.jsonl"),
			/** Purge signed records older than this many days. 0 keeps everything. */
			retention_days: z.number().int().min(0).default(0),
			/**
			 * Emit a signed deletion manifest before retention purges records, so the
			 * purge itself is evidence rather than an unexplained gap in the chain.
			 */
			retain_deletion_evidence: z.boolean().default(true),
		})
		.default({}),
});

export const UrlCheckConfigSchema = z.object({
	endpoint: z.string().optional(),
	/** Explicitly allow plaintext HTTP to a loopback endpoint for local development. */
	allow_insecure_loopback: z.boolean().default(false),
	/** Explicit opt-in to sending URL query parameters to the reputation provider. */
	include_query_parameters: z.boolean().default(false),
	timeout_seconds: z.number().default(5.0),
	/** Explicit opt-in; unavailable checks are surfaced for human review. */
	enabled: z.boolean().default(false),
});

const EncryptionConfigSchema = z.object({
	/** Enable transparent encryption of cache and audit files. */
	enabled: z.boolean().default(false),
});

export const CacheConfigSchema = z.object({
	enabled: z.boolean().default(true),
	ttl_malicious_seconds: z.number().default(3600),
	ttl_clean_seconds: z.number().default(86400),
	path: z.string().default("~/.singularity-aidr/cache.json"),
	encryption: EncryptionConfigSchema.default({}).optional(),
});

export const AllowlistConfigSchema = z.object({
	path: z.string().default("~/.singularity-aidr/allowlist.json"),
});

export const LoggingConfigSchema = z.object({
	enabled: z.boolean().default(true),
	log_clean: z.boolean().default(false),
	path: z.string().default("~/.singularity-aidr/audit.jsonl"),
	max_bytes: z
		.number()
		.int()
		.min(0)
		.default(5 * 1024 * 1024),
	max_files: z.number().int().min(0).default(3),
});

export const FileCheckConfigSchema = z.object({
	endpoint: z.string().optional(),
	/** Explicitly allow plaintext HTTP to a loopback endpoint for local development. */
	allow_insecure_loopback: z.boolean().default(false),
	timeout_seconds: z.number().default(5.0),
	/** Explicit opt-in to sending file SHA-256 hashes to a reputation provider. */
	enabled: z.boolean().default(false),
});

const VersionCheckConfigSchema = z.object({
	/** Version checks transmit runtime metadata and installation ID; require explicit opt-in. */
	enabled: z.boolean().default(false),
});

export const PackageCheckConfigSchema = z.object({
	/** Explicit opt-in to sending package names to public registries. */
	enabled: z.boolean().default(false),
	timeout_seconds: z.number().default(5.0),
});

const AmsiCheckConfigSchema = z.object({
	enabled: z.boolean().default(true),
});

/**
 * @deprecated NVD lookup is no longer wired into the runtime.
 * @public
 */
export const NvdConfigSchema = z.object({
	api_key: z.string().optional(),
	timeout_seconds: z.number().default(30),
	cache_path: z.string().default("~/.singularity-aidr/nvd-cache.json"),
	cache_ttl_hours: z.number().default(6),
	enabled: z.boolean().default(true),
	keywords: z
		.array(z.string())
		.default([
			"AI",
			"artificial intelligence",
			"machine learning",
			"LLM",
			"large language model",
			"agent",
			"chatbot",
			"OpenClaw",
			"Claude",
			"Claude Code",
			"Cursor",
			"code assistant",
			"AI agent",
			"autonomous agent",
			"MCP",
			"Model Context Protocol",
		]),
});

export const ConfigSchema = z.object({
	// Default to local enforcement so a fresh install protects on the first tool
	// call. Managed mode adds the control plane, signed entitlements and premium
	// intel packs; it is an explicit opt-in and must never be a precondition for
	// baseline detection. See docs/configuration.md ("Modes").
	mode: OperatingModeSchema.default("local"),
	auth: AuthConfigSchema.default({}),
	control_plane: ControlPlaneConfigSchema.default({}),
	policy: PolicyConfigSchema.default({}),
	intel: IntelConfigSchema.default({}),
	intel_packs: IntelPacksConfigSchema.default({}),
	integrity: IntegrityConfigSchema.default({}),
	licensing: LicensingConfigSchema.default({}),
	incident: IncidentConfigSchema.default({}),
	response: ResponseConfigSchema.default({}),
	url_check: UrlCheckConfigSchema.default({}),
	file_check: FileCheckConfigSchema.default({}),
	version_check: VersionCheckConfigSchema.default({}),
	package_check: PackageCheckConfigSchema.default({}),
	amsi_check: AmsiCheckConfigSchema.default({}),
	/** @deprecated Accepted for configuration compatibility; not used at runtime. */
	nvd_check: NvdConfigSchema.default({}),
	heuristics_enabled: z.boolean().default(true),
	cache: CacheConfigSchema.default({}),
	allowlist: AllowlistConfigSchema.default({}),
	logging: LoggingConfigSchema.default({}),
	sensitivity: SensitivitySchema.default("balanced"),
	disabled_threats: z.array(z.string()).default([]),
});

export type AuthConfig = z.infer<typeof AuthConfigSchema>;
type OptionalInsecureLoopback<T extends { allow_insecure_loopback: boolean }> = Omit<
	T,
	"allow_insecure_loopback"
> & { allow_insecure_loopback?: boolean };
type OptionalUrlCheckDefaults<
	T extends {
		allow_insecure_loopback: boolean;
		include_query_parameters: boolean;
	},
> = Omit<T, "allow_insecure_loopback" | "include_query_parameters"> & {
	allow_insecure_loopback?: boolean;
	include_query_parameters?: boolean;
};

export type ControlPlaneConfig = OptionalInsecureLoopback<z.infer<typeof ControlPlaneConfigSchema>>;
type PolicyConfig = z.infer<typeof PolicyConfigSchema>;
type PolicyMcpConfig = z.infer<typeof PolicyMcpSchema>;
export type IntelConfig = z.infer<typeof IntelConfigSchema>;
export type IntelPacksConfig = z.infer<typeof IntelPacksConfigSchema>;
export type IntegrityConfig = z.infer<typeof IntegrityConfigSchema>;
type LicensingConfig = z.infer<typeof LicensingConfigSchema>;
export type IncidentConfig = z.infer<typeof IncidentConfigSchema>;
type ResponseConfig = z.infer<typeof ResponseConfigSchema>;
type ResponseActionsConfig = ResponseConfig["actions"];
export type ResponseAuditConfig = ResponseConfig["audit"];
export type UrlCheckConfig = OptionalUrlCheckDefaults<z.infer<typeof UrlCheckConfigSchema>>;
export type FileCheckConfig = OptionalInsecureLoopback<z.infer<typeof FileCheckConfigSchema>>;
export type PackageCheckConfig = z.infer<typeof PackageCheckConfigSchema>;
export type AmsiCheckConfig = z.infer<typeof AmsiCheckConfigSchema>;
/**
 * @deprecated NVD lookup is no longer wired into the runtime.
 * @public
 */
export type NvdConfig = z.infer<typeof NvdConfigSchema>;
type EncryptionConfig = z.infer<typeof EncryptionConfigSchema>;
export type CacheConfig = z.infer<typeof CacheConfigSchema>;
export type AllowlistConfig = z.infer<typeof AllowlistConfigSchema>;
export type LoggingConfig = z.infer<typeof LoggingConfigSchema>;
export type Config = z.infer<typeof ConfigSchema>;

// ── Allowlist ───────────────────────────────────────────────────────

export interface AllowlistEntry {
	addedAt: string;
	reason: string;
	originalVerdict: string;
}

export interface Allowlist {
	urls: Record<string, AllowlistEntry>;
	commands: Record<string, AllowlistEntry>;
	filePaths: Record<string, AllowlistEntry>;
}

// ── Trusted domains ─────────────────────────────────────────────────

export interface TrustedDomain {
	domain: string;
	reason: string;
}

// ── Plugin scanner ──────────────────────────────────────────────────

export interface PluginInfo {
	key: string;
	installPath: string;
	version: string;
	lastUpdated: string;
}

export interface PluginFinding {
	threatId: string;
	title: string;
	severity: string;
	confidence: number;
	action: string;
	artifact: string;
	sourceFile: string;
}

export interface PluginScanResult {
	plugin: PluginInfo;
	findings: PluginFinding[];
	/**
	 * Reputation legs that were unavailable or intentionally withheld, with the reason.
	 *
	 * Present so a caller can distinguish "the URL/file reputation checks ran and
	 * found nothing" from "they never ran". Before this field existed the two
	 * were indistinguishable: the clients were constructed without an API key, the
	 * resulting 401 was swallowed by `catch { /* Fail open *\/ }`, and the scan
	 * reported a clean plugin. A leg that cannot run must never be presented as a
	 * clean result.
	 *
	 * Not part of the persisted cache (`CachedPluginScanResult` stores findings
	 * only), so adding this cannot invalidate cached scan data.
	 */
	unavailableChecks?: PluginScanUnavailableCheck[];
}

export interface PluginScanUnavailableCheck {
	/** Which verification check is incomplete or unavailable. */
	check: "url_reputation" | "file_reputation" | "plugin_files";
	/** Why it could not run, in operator-readable form. */
	reason: string;
	/** How many artifacts or paths went unchecked. */
	uncheckedCount: number;
}

// ── Plugin scan cache ───────────────────────────────────────────────

export interface CachedPluginScanResult {
	pluginKey: string;
	version: string;
	scannedAt: string;
	findings: PluginFindingData[];
}

export interface PluginFindingData {
	threat_id: string;
	title: string;
	severity: string;
	confidence: number;
	action: string;
	artifact: string;
	source_file: string;
}

export interface PluginScanCache {
	configHash: string;
	entries: Record<string, CachedPluginScanResult>;
}

// ── Agent runtime ──────────────────────────────────────────────────

/**
 * Supported agent runtimes. Every value here has a connector that enforces
 * locally through this core; an unsupported runtime must not be listed, because
 * telemetry and policy treat membership as "this connector is real".
 */
export type AgentRuntime = "claude-code" | "openclaw" | "opencode" | "cursor" | "vscode" | "codex";
