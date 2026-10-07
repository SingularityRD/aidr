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
	/** File-edit view rules only (see `agent-safety/edit-views.ts`). */
	diff: z.enum(["added", "removed", "value_decreased"]).optional(),
	/** File-edit view rules only: the net number of matching lines required. */
	min_matches: z.number().int().min(1).max(1000).optional(),
});

/** Raw threat from YAML (before compilation). */
export type ThreatData = z.infer<typeof ThreatSchema>;

/**
 * Security framework items a rule maps to (see `threats/mappings/frameworks.yaml`).
 * IDs carry no edition suffix and are sorted: `LLM01`, `ASI02`, `AML.T0051.001`.
 */
export interface FrameworkRefs {
	/** OWASP Top 10 for LLM Applications 2025. */
	owaspLlm: string[];
	/** OWASP Top 10 for Agentic Applications 2026. */
	owaspAgentic: string[];
	/** MITRE ATLAS techniques and sub-techniques. */
	mitreAtlas: string[];
}

/** Serialized (snake_case) form of {@link FrameworkRefs} used in audit/SIEM JSON. */
export interface FrameworkRefsJson {
	owasp_llm: string[];
	owasp_agentic: string[];
	mitre_atlas: string[];
}

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
	/**
	 * File-edit view rules only (`match_on: test_code | ci_config |
	 * quality_config | source_code`): compare the lines an edit adds with the
	 * lines it removes. `added` / `removed` fire on a net change of at least
	 * `minMatches` matching lines; `value_decreased` fires when the number in the
	 * pattern's first capture group went down for the same setting.
	 */
	diff?: "added" | "removed" | "value_decreased";
	/** Net matching lines an `added` / `removed` rule needs (default 1). */
	minMatches?: number;
	/** Rule file the threat was loaded from (e.g. `commands.yaml`). */
	sourceFile?: string;
	/** Framework mapping; absent when the rule directory ships no mapping for it. */
	frameworks?: FrameworkRefs;
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
/** The 4-level severity a threat rule or policy declares. */
export type RuleSeverity = "critical" | "high" | "medium" | "low";

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
	/**
	 * The severity the matched rule (or policy) itself declares. `severity` is
	 * the 3-level user-facing bucket (a `high` rule maps to `warning`); messages
	 * that name the rule show this label so the two never disagree. Absent when
	 * no rule or policy decided the verdict.
	 */
	ruleSeverity?: RuleSeverity;
	/**
	 * Framework items of the matched rule (OWASP LLM 2025, OWASP Agentic 2026,
	 * MITRE ATLAS). Enrichment only: absent when no rule matched or the rule has
	 * no mapping, and never an input to the decision.
	 */
	frameworks?: FrameworkRefs;
	/** Verified delegation lineage; absent when the call carried no credential. */
	delegation?: DelegationLineage;
	/**
	 * Replacement tool input produced by DLP redaction. Present only on an
	 * `allow` verdict, and only when the caller declared that it can rewrite the
	 * tool input (`ToolEvaluationContext.supportsInputRewrite`). A connector that
	 * receives it MUST execute the tool with this input instead of the original,
	 * or block the call; running the original input would disclose the redacted
	 * values.
	 */
	transformedInput?: Record<string, unknown>;
	/**
	 * The agent permission profile rule that restricted this call. Present only
	 * when a profile made the decision stricter than threat detection alone.
	 */
	agentProfile?: AgentProfileVerdictRef;
	/**
	 * Advisory secure-code findings on the code this call writes (see
	 * `code-guard.ts`). In the default `secure_code.action: "warn"` mode they
	 * never change the decision: a connector surfaces them through its notice
	 * channel (or records them in the audit log only, when the host has none).
	 * Titles and locations only — never the matched source text.
	 */
	warnings?: VerdictWarning[];
}

/** Which profile rule restricted a call (names only, never tool input). */
export interface AgentProfileVerdictRef {
	profile: string;
	source: "managed" | "local";
	rule: string;
}

/** One advisory finding attached to a verdict. */
export interface VerdictWarning {
	source: "secure_code";
	ruleId: string;
	title: string;
	category: string;
	severity: "critical" | "high" | "medium" | "low";
	/** File the tool call writes; empty when the host did not name one. */
	filePath: string;
	language: string;
	/** 1-based line in the written file, when the tool input makes it knowable. */
	line?: number;
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
	/**
	 * HMAC-SHA256 over the entry, its kind and its key, under the per-installation
	 * cache key (see `cache.ts`). Entries without a valid MAC are ignored on load.
	 */
	mac?: string;
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
	/**
	 * Ed25519 public keys (PEM or base64 SPKI) that verify the signed runtime policy
	 * (`policy_signed`). When empty, `licensing.public_keys_pem` is used instead. When
	 * neither is configured, signature verification is skipped and only the
	 * `policy_sha256` digest over TLS protects the policy. When any key is configured,
	 * unsigned, tampered, wrong-signer, expired, revoked-key and rolled-back policies are rejected.
	 */
	policy_public_keys_pem: z.array(z.string()).optional(),
	/** Explicitly allow plaintext HTTP to a loopback endpoint for local development. */
	allow_insecure_loopback: z.boolean().default(false),
	/** Request timeout for control-plane calls. */
	timeout_seconds: legTimeoutSchema(0.5),
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
	/** An operator-installed response worker must retain its authenticated control state. */
	response_worker_required: z.boolean().default(false),
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
			/**
			 * Upper bound on the total size of the pre-operation snapshot store. When a
			 * new snapshot pushes the store past it, the OLDEST snapshots are pruned
			 * first. 0 disables the size bound (retention days still apply).
			 */
			snapshot_max_total_bytes: z
				.number()
				.int()
				.min(0)
				.default(256 * 1024 * 1024),
		})
		.default({}),
	/**
	 * File quarantine: a file an agent tool call WROTE or DOWNLOADED that the
	 * content scan then classifies as malicious is moved into a per-user vault
	 * (owner-only, never executable, renamed so it cannot be launched by
	 * extension) together with its hash, original path, reason and time.
	 *
	 * OFF by default: it moves a file the agent just produced, which is a
	 * unilateral action on the user's workspace and must be an explicit opt-in.
	 * Release and delete are operator-only (`aidr quarantine release|delete`, TTY
	 * confirmation); no agent tool can call them.
	 */
	quarantine: z
		.object({
			enabled: z.boolean().default(false),
			/** Vault location. Confined to the AIDR state directory. */
			dir: z.string().default("~/.singularity-aidr/quarantine"),
			/** Items older than this are deleted on the next quarantine. 0 keeps them. */
			retention_days: z.number().int().min(0).default(30),
			/** Vault size bound; the OLDEST items are deleted first. 0 disables it. */
			max_total_bytes: z
				.number()
				.int()
				.min(0)
				.default(512 * 1024 * 1024),
			/**
			 * Files larger than this are not scanned (and so never quarantined); the
			 * skip is reported, never treated as clean.
			 */
			max_scan_bytes: z
				.number()
				.int()
				.positive()
				.default(2 * 1024 * 1024),
			/** Lowest rule severity that counts as malicious. Only `block` rules qualify. */
			min_severity: z.enum(["medium", "high", "critical"]).default("high"),
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

/**
 * Hook budget for remote detection legs. The strictest host is Codex, which
 * kills a PreToolUse hook after 10 s and then FAILS OPEN; a killed hook never
 * gets to deny. Process start-up, config/rule loading and local detection need
 * their share, so remote legs get a fixed slice of that budget: each leg is
 * capped at MAX_LEG_TIMEOUT_SECONDS and all of a call's remote legs together
 * at LEG_TOTAL_BUDGET_SECONDS (enforced by the evaluator). A leg that runs out
 * of time is an unavailable leg, never a clean result.
 */
export const MAX_LEG_TIMEOUT_SECONDS = 3;
export const LEG_TOTAL_BUDGET_SECONDS = 6;
export const DEFAULT_LEG_TIMEOUT_SECONDS = 2;

/**
 * Clamp a configured leg timeout into (0, MAX_LEG_TIMEOUT_SECONDS]. A
 * non-positive or non-finite value falls back to `fallback`. Clamping (rather
 * than rejecting the whole config, which fails closed on every call) keeps an
 * existing `timeout_seconds: 5` working within the budget.
 */
export function clampLegTimeoutSeconds(
	value: number | undefined,
	fallback = DEFAULT_LEG_TIMEOUT_SECONDS,
): number {
	const seconds =
		typeof value === "number" && Number.isFinite(value) && value > 0 ? value : fallback;
	return Math.min(seconds, MAX_LEG_TIMEOUT_SECONDS);
}

function legTimeoutSchema(defaultSeconds: number) {
	return z
		.number()
		.default(defaultSeconds)
		.transform((value) => clampLegTimeoutSeconds(value, defaultSeconds));
}

export const UrlCheckConfigSchema = z.object({
	endpoint: z.string().optional(),
	/** Explicitly allow plaintext HTTP to a loopback endpoint for local development. */
	allow_insecure_loopback: z.boolean().default(false),
	/** Explicit opt-in to sending URL query parameters to the reputation provider. */
	include_query_parameters: z.boolean().default(false),
	timeout_seconds: legTimeoutSchema(DEFAULT_LEG_TIMEOUT_SECONDS),
	/** Explicit opt-in; unavailable checks are surfaced for human review. */
	enabled: z.boolean().default(false),
});

const EncryptionConfigSchema = z.object({
	/** Legacy host-bound cache encoding; use an OS vault/disk encryption against local attackers. */
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
	/**
	 * RESOLVED, not configured: whether every record is hash-chained and Ed25519
	 * signed. `loadConfig` sets it from the top-level `audit` block (see
	 * `AuditConfigSchema`) so every writer that only receives `logging` honours it.
	 */
	signed_chain: z.boolean().optional(),
	/** RESOLVED from `audit.key_storage`. */
	chain_key_storage: z.enum(["os-vault", "file"]).optional(),
	/** RESOLVED from `audit.epoch_hours`. */
	chain_epoch_hours: z.number().int().min(1).max(720).optional(),
});

/**
 * Tamper-evident verdict log (`audit.jsonl`).
 *
 * With `signed_chain` every record gets a `_chain` field: a sequence number, the
 * previous record's hash, its own SHA-256 hash and an Ed25519 signature.
 * `aidr audit verify` reports the first broken, missing or reordered record.
 *
 * Default: OFF in local mode, ON in managed mode when `signed_chain` is not set
 * explicitly, and always ON in a commercial build (which is managed-only and also
 * forces integrity verification on). See docs/configuration.md.
 *
 * Keys: a long-lived ROOT key lives in the OS credential vault (`key_storage:
 * os-vault`, the default, the same store as the operator approval key) and only
 * certifies short-lived EPOCH keys; the epoch key that signs records is kept in an
 * owner-only file so a hook does not pay a vault round trip per call. A stolen
 * epoch key can forge records only inside its own window (`epoch_hours`).
 */
export const AuditConfigSchema = z.object({
	signed_chain: z.boolean().optional(),
	key_storage: z.enum(["os-vault", "file"]).default("os-vault"),
	epoch_hours: z.number().int().min(1).max(720).default(24),
});

export const FileCheckConfigSchema = z.object({
	endpoint: z.string().optional(),
	/** Explicitly allow plaintext HTTP to a loopback endpoint for local development. */
	allow_insecure_loopback: z.boolean().default(false),
	timeout_seconds: legTimeoutSchema(DEFAULT_LEG_TIMEOUT_SECONDS),
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
	timeout_seconds: legTimeoutSchema(DEFAULT_LEG_TIMEOUT_SECONDS),
	/**
	 * Slopsquatting window: a package first published fewer than this many days
	 * ago is held for review when its adoption is also low. Packages younger than
	 * seven days are always held. `0` disables the low-adoption signal.
	 */
	new_package_days: z.number().int().min(0).max(3650).default(30),
	/** npm weekly downloads below this count are "low adoption" inside the window. */
	low_adoption_weekly_downloads: z.number().int().min(0).default(1000),
	/**
	 * Published versions at or below this count are "low adoption" when download
	 * counts are unavailable (PyPI, or the npm downloads API did not answer).
	 */
	low_adoption_max_versions: z.number().int().min(0).default(3),
	/** Ask the npm downloads API about young packages (sends the package name). */
	adoption_lookup: z.boolean().default(true),
});

/**
 * Data and context poisoning protection: integrity of agent instruction, memory
 * and configuration files, scanning of what is written into them, and memory /
 * RAG write inspection. Every switch is on by default; see
 * docs/poisoning-protection.md.
 */
export const PoisoningProtectionConfigSchema = z.object({
	/** Master switch for the runtime context-poisoning detector. */
	enabled: z.boolean().default(true),
	/**
	 * What a write to an agent instruction, memory, configuration, MCP, IDE
	 * automation, repository hook or shell start-up file needs: `ask`
	 * (out-of-band approval), `deny`, or `off` (no path signal; the written
	 * content is still scanned).
	 */
	agent_control_files: z.enum(["ask", "deny", "off"]).default("ask"),
	/** Scan the text written into those files for hidden or injected instructions. */
	content_scan: z.boolean().default(true),
	/** Scan the arguments of MCP tools that write to agent memory or a vector store. */
	memory_write_scan: z.boolean().default(true),
});

const AmsiCheckConfigSchema = z.object({
	enabled: z.boolean().default(true),
});

export const PromptProtectionModeSchema = z.enum(["off", "warn", "block"]);

/**
 * Inspection of the user's own prompt before it reaches the model (Claude Code
 * `UserPromptSubmit`). `block` stops the prompt, `warn` lets it through with a
 * notice to the user and the model, `off` skips that category.
 */
/**
 * Content-safety categories for user prompts. Each is `off | warn | block`,
 * except `sexual_minors`, which is always `block`: any other value is accepted
 * for compatibility and has no effect.
 */
export const PromptContentSafetySchema = z.object({
	/** Requests to author malware (ransomware, stealers, keyloggers, AV/EDR evasion). */
	malware: PromptProtectionModeSchema.default("warn"),
	/** Requests to build credential-phishing kits or fake login pages. */
	phishing_kit: PromptProtectionModeSchema.default("warn"),
	/** Requests to produce weapons or chemical, biological, radiological or nuclear agents. */
	weapons_cbrn: PromptProtectionModeSchema.default("block"),
	/** Self-harm intent or method seeking; the notice points to support, not to a violation. */
	self_harm: PromptProtectionModeSchema.default("warn"),
	/** Requests to generate hate speech, harassment or threats against people. */
	hate_harassment: PromptProtectionModeSchema.default("warn"),
	/** Sexual content involving minors: always blocked. */
	sexual_minors: PromptProtectionModeSchema.default("block").transform(() => "block" as const),
});

export const PromptProtectionConfigSchema = z.object({
	/** Credentials, tokens and private keys. */
	secrets: PromptProtectionModeSchema.default("block"),
	/** Personal data: email addresses, phone numbers, SSNs, payment card numbers. */
	pii: PromptProtectionModeSchema.default("warn"),
	/** Jailbreak attempts: instruction overrides, persona/role-play overrides, encoded payloads. */
	jailbreak: PromptProtectionModeSchema.default("warn"),
	/** Content-safety categories (pattern-based policy aid, not a model-grade classifier). */
	content_safety: PromptContentSafetySchema.default({}),
});

/**
 * Secure-code guardrails for code an agent writes (Write, Edit, MultiEdit,
 * apply_patch, NotebookEdit and heredoc file writes). Only the lines the call
 * adds are inspected, gated by file language. `warn` (default) lets the call
 * through with a notice to the user and the model; `ask` holds it for review.
 */
export const SecureCodeConfigSchema = z.object({
	enabled: z.boolean().default(true),
	action: z.enum(["warn", "ask"]).default("warn"),
});

/**
 * AI model supply chain. The shipped trusted hubs and publisher organisations
 * live in `allowlists/model-sources/*.yaml`; these lists add to them. A model
 * download is trusted only when every source it names is on a list.
 */
export const AiSupplyChainConfigSchema = z.object({
	/** Extra Hugging Face organisations/users whose repositories are trusted (case-insensitive). */
	trusted_model_orgs: z.array(z.string()).default([]),
	/** Extra HTTPS hosts trusted for direct model-weight downloads (suffix match on a dot boundary). */
	trusted_model_hosts: z.array(z.string()).default([]),
});

/**
 * Session toxic-flow ("lethal trifecta") and behavioral chain detection. See
 * docs/toxic-flow.md. On by default; `action: "auto"` asks in balanced/relaxed
 * and denies in paranoid.
 */
const ToxicFlowConfigSchema = z.object({
	enabled: z.boolean().default(true),
	/** `auto` follows `sensitivity`; `monitor` records and logs without blocking. */
	action: z.enum(["auto", "ask", "deny", "monitor"]).default("auto"),
	/** How long a step keeps counting toward a chain. */
	window_minutes: z.number().int().min(1).max(1440).default(60),
	/** Distinct sensitive files/credential stores in the window that trigger `bulk_sensitive_access`. */
	bulk_sensitive_threshold: z.number().int().min(2).max(64).default(5),
	/** Extra destination domains (suffix match) a plain request to is not external communication. */
	trusted_domains: z.array(z.string().min(1).max(253)).max(500).default([]),
	/** MCP server ids whose output is not untrusted content (in addition to `policy.mcp.allow_servers`). */
	trusted_mcp_servers: z.array(z.string().min(1).max(128)).max(200).default([]),
	/** Git remote names a push to is not external communication. */
	trusted_git_remotes: z.array(z.string().min(1).max(128)).max(50).default(["origin"]),
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

/**
 * The operator approval channel (`aidr pending` / `aidr approve`).
 *
 * `key_storage` is where the approval HMAC key and the single-use ledger live:
 * `os-vault` (default) keeps them in the OS credential vault and DISABLES
 * approvals when there is none; `file` is an explicit opt-in to an owner-only key
 * file that every process of the same user can read. The
 * `AIDR_OPERATOR_APPROVAL_KEY_STORAGE` environment variable overrides it.
 */
const OperatorApprovalsConfigSchema = z.object({
	key_storage: z.enum(["os-vault", "file"]).default("os-vault"),
	/**
	 * Managed mode only: an `ask` can be released ONLY by a dashboard approval (an
	 * authenticated admin in the AIDR dashboard). The local `aidr approve` channel
	 * is not consulted and hosts with a native confirmation dialog (Claude Code,
	 * VS Code) block instead of asking. Ignored in local mode.
	 */
	dashboard_only: z.boolean().default(false),
});

/**
 * Session-level runaway guardrails for autonomous agents (loops, tool-call rate
 * spikes, optional per-session budgets). Every signal is an `ask`: the session
 * is paused until a human reviews it. See docs/agent-safety.md.
 *
 * `max_*` values are the most the guard allows before pausing; `0` switches that
 * individual check off. Budgets are off by default.
 */
export const RunawayConfigSchema = z.object({
	enabled: z.boolean().default(true),
	/** Sliding window for loop and repeated-failure detection. */
	window_seconds: z.number().int().min(10).max(86_400).default(600),
	/** The same tool call back-to-back, with nothing else in between. */
	max_consecutive_identical_calls: z.number().int().min(0).max(1000).default(8),
	/** The same tool call anywhere in the window. */
	max_identical_calls: z.number().int().min(0).max(1000).default(25),
	/** Near-identical calls (numbers, ids and whitespace ignored) in the window. */
	max_similar_calls: z.number().int().min(0).max(1000).default(50),
	/** Recorded failures of the same call with no file edit in between. */
	max_repeated_failures: z.number().int().min(0).max(1000).default(3),
	/** Tool calls in any rolling 60 seconds. */
	max_calls_per_minute: z.number().int().min(0).max(1000).default(120),
	/** Optional session budgets (0 = unlimited). */
	max_tool_calls: z.number().int().min(0).default(0),
	max_session_minutes: z.number().int().min(0).default(0),
	max_files_written: z.number().int().min(0).max(2000).default(0),
	/** Session state older than this is discarded. */
	state_ttl_hours: z.number().min(1).max(720).default(24),
	/** At most this many session state files are kept. */
	max_sessions: z.number().int().min(1).max(10_000).default(512),
});

export const AgentSafetyConfigSchema = z.object({
	runaway: RunawayConfigSchema.default({}),
});

export const ConfigSchema = z.object({
	// Default to local enforcement so a fresh install protects on the first tool
	// call. Managed mode adds the control plane, signed entitlements and premium
	// intel packs; it is an explicit opt-in and must never be a precondition for
	// baseline detection. See docs/configuration.md ("Modes").
	mode: OperatingModeSchema.default("local"),
	auth: AuthConfigSchema.default({}),
	control_plane: ControlPlaneConfigSchema.default({}),
	/** Explicit mandatory privacy profile; ordinary tool hooks do not own model transport. */
	privacy: z
		.object({ required: z.boolean().default(false) })
		.strict()
		.optional(),
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
	poisoning_protection: PoisoningProtectionConfigSchema.default({}),
	amsi_check: AmsiCheckConfigSchema.default({}),
	prompt_protection: PromptProtectionConfigSchema.default({}),
	secure_code: SecureCodeConfigSchema.default({}),
	ai_supply_chain: AiSupplyChainConfigSchema.default({}),
	toxic_flow: ToxicFlowConfigSchema.default({}),
	/** @deprecated Accepted for configuration compatibility; not used at runtime. */
	nvd_check: NvdConfigSchema.default({}),
	heuristics_enabled: z.boolean().default(true),
	cache: CacheConfigSchema.default({}),
	allowlist: AllowlistConfigSchema.default({}),
	logging: LoggingConfigSchema.default({}),
	audit: AuditConfigSchema.default({}),
	sensitivity: SensitivitySchema.default("balanced"),
	disabled_threats: z.array(z.string()).default([]),
	operator_approvals: OperatorApprovalsConfigSchema.default({}),
	agent_safety: AgentSafetyConfigSchema.default({}),
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
export type PoisoningProtectionConfig = z.infer<typeof PoisoningProtectionConfigSchema>;
export type AmsiCheckConfig = z.infer<typeof AmsiCheckConfigSchema>;
export type PromptProtectionMode = z.infer<typeof PromptProtectionModeSchema>;
export type PromptContentSafetyConfig = z.infer<typeof PromptContentSafetySchema>;
export type PromptContentSafetyCategory = keyof PromptContentSafetyConfig;
/**
 * Prompt protection policy as scanPrompt consumes it. `jailbreak` and
 * `content_safety` are optional so a caller that predates them keeps the
 * documented defaults (see DEFAULT_PROMPT_SAFETY in prompt-safety.ts).
 */
export interface PromptProtectionConfig {
	secrets: PromptProtectionMode;
	pii: PromptProtectionMode;
	jailbreak?: PromptProtectionMode;
	content_safety?: Partial<Record<PromptContentSafetyCategory, PromptProtectionMode>>;
}
export type SecureCodeConfig = z.infer<typeof SecureCodeConfigSchema>;
export type AiSupplyChainConfig = z.infer<typeof AiSupplyChainConfigSchema>;
export type ToxicFlowConfig = z.infer<typeof ToxicFlowConfigSchema>;
/**
 * @deprecated NVD lookup is no longer wired into the runtime.
 * @public
 */
export type NvdConfig = z.infer<typeof NvdConfigSchema>;
type EncryptionConfig = z.infer<typeof EncryptionConfigSchema>;
export type CacheConfig = z.infer<typeof CacheConfigSchema>;
export type AllowlistConfig = z.infer<typeof AllowlistConfigSchema>;
export type LoggingConfig = z.infer<typeof LoggingConfigSchema>;
export type AuditConfig = z.infer<typeof AuditConfigSchema>;
export type QuarantineSettings = ResponseConfig["quarantine"];
export type Config = z.infer<typeof ConfigSchema>;
export type RunawayConfig = z.infer<typeof RunawayConfigSchema>;

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
	/** `threat_rules`: bundled rule files did not load or verify, so rule matching was partial. */
	check: "url_reputation" | "file_reputation" | "plugin_files" | "threat_rules";
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
