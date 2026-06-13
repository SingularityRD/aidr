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
export function getLogger(): Logger {
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
}

// ── Verdict ─────────────────────────────────────────────────────────

export const DecisionSchema = z.enum(["allow", "deny", "ask"]);
export const VerdictSeveritySchema = z.enum(["info", "warning", "critical"]);

export type Decision = z.infer<typeof DecisionSchema>;
export type VerdictSeverity = z.infer<typeof VerdictSeveritySchema>;

export interface Verdict {
	decision: Decision;
	category: string;
	confidence: number;
	severity: VerdictSeverity;
	source: string;
	artifacts: string[];
	matchedThreatId: string | null;
	reasons: string[];
}

// ── Package check ──────────────────────────────────────────────────

export interface PackageCheckResult {
	packageName: string;
	registry: "npm" | "pypi";
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
	aidrVersion?: string;
}

export interface CacheStore {
	urls: Record<string, CachedEntry>;
	commands: Record<string, CachedEntry>;
	packages: Record<string, CachedEntry>;
}

// ── Config ──────────────────────────────────────────────────────────

export const SensitivitySchema = z.enum(["paranoid", "balanced", "relaxed"]);

export const OperatingModeSchema = z.enum(["local", "managed"]);

export const AuthConfigSchema = z.object({
	/**
	 * API key used to authenticate to Singularity AIDR managed services (control plane, premium packs).
	 */
	api_key: z.string().optional(),
	/**
	 * Optional one-time enrollment token used to bootstrap managed mode (exchanged for an API key).
	 */
	enrollment_token: z.string().optional(),
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
	endpoint: z.string().default("https://aidr-control.svc.singularityrd.com"),
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
});

export const PolicyFilesystemSchema = z.object({
	enabled: z.boolean().default(false),
	allowed_write_roots: z.array(z.string()).default([]),
	deny_write_patterns: z.array(z.string()).default([]),
	outside_root_action: z.enum(["block", "require_approval"]).default("require_approval"),
});

export const PolicyNetworkSchema = z.object({
	enabled: z.boolean().default(false),
	allow_domains: z.array(z.string()).default([]),
	deny_domains: z.array(z.string()).default([]),
	deny_private_ips: z.boolean().default(true),
	deny_action: z.enum(["block", "require_approval"]).default("block"),
	outside_allow_action: z.enum(["block", "require_approval"]).default("require_approval"),
});

export const PolicyShellSchema = z.object({
	enabled: z.boolean().default(false),
	deny_patterns: z.array(z.string()).default([]),
	deny_action: z.enum(["block", "require_approval"]).default("block"),
});

export const PolicyMcpSchema = z.object({
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

export const PolicyConfigSchema = z.object({
	enabled: z.boolean().default(false),
	filesystem: PolicyFilesystemSchema.default({}),
	network: PolicyNetworkSchema.default({}),
	shell: PolicyShellSchema.default({}),
	mcp: PolicyMcpSchema.default({}),
	runtime_defaults: z.record(z.string(), z.unknown()).default({}),
});

export const IntelConfigSchema = z.object({
	enabled: z.boolean().default(false),
	url_denylist_path: z.string().default("~/.singularity-aidr/intel/url_denylist.txt"),
});

export const IntegrityConfigSchema = z.object({
	enabled: z.boolean().default(false),
	/**
	 * Optional public keys (PEM) used to verify signed manifests and intel packs.
	 * If empty, integrity verification is skipped (fail-open).
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

export const LicensingConfigSchema = z.object({
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

export const ResponseConfigSchema = z.object({
	emit_incidents: z.boolean().default(true),
});

export const UrlCheckConfigSchema = z.object({
	endpoint: z.string().optional(),
	timeout_seconds: z.number().default(5.0),
	enabled: z.boolean().default(true),
});

export const EncryptionConfigSchema = z.object({
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
	timeout_seconds: z.number().default(5.0),
	enabled: z.boolean().default(true),
});

export const PackageCheckConfigSchema = z.object({
	enabled: z.boolean().default(true),
	timeout_seconds: z.number().default(5.0),
});

export const AmsiCheckConfigSchema = z.object({
	enabled: z.boolean().default(true),
});

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
	mode: OperatingModeSchema.default("managed"),
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
	package_check: PackageCheckConfigSchema.default({}),
	amsi_check: AmsiCheckConfigSchema.default({}),
	nvd_check: NvdConfigSchema.default({}),
	heuristics_enabled: z.boolean().default(true),
	cache: CacheConfigSchema.default({}),
	allowlist: AllowlistConfigSchema.default({}),
	logging: LoggingConfigSchema.default({}),
	sensitivity: SensitivitySchema.default("balanced"),
	disabled_threats: z.array(z.string()).default([]),
});

export type AuthConfig = z.infer<typeof AuthConfigSchema>;
export type ControlPlaneConfig = z.infer<typeof ControlPlaneConfigSchema>;
export type PolicyConfig = z.infer<typeof PolicyConfigSchema>;
export type PolicyMcpConfig = z.infer<typeof PolicyMcpSchema>;
export type IntelConfig = z.infer<typeof IntelConfigSchema>;
export type IntelPacksConfig = z.infer<typeof IntelPacksConfigSchema>;
export type IntegrityConfig = z.infer<typeof IntegrityConfigSchema>;
export type LicensingConfig = z.infer<typeof LicensingConfigSchema>;
export type IncidentConfig = z.infer<typeof IncidentConfigSchema>;
export type ResponseConfig = z.infer<typeof ResponseConfigSchema>;
export type UrlCheckConfig = z.infer<typeof UrlCheckConfigSchema>;
export type FileCheckConfig = z.infer<typeof FileCheckConfigSchema>;
export type PackageCheckConfig = z.infer<typeof PackageCheckConfigSchema>;
export type NvdConfig = z.infer<typeof NvdConfigSchema>;
export type AmsiCheckConfig = z.infer<typeof AmsiCheckConfigSchema>;
export type EncryptionConfig = z.infer<typeof EncryptionConfigSchema>;
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

export type AgentRuntime = "claude-code" | "openclaw" | "opencode" | "cursor" | "vscode";
