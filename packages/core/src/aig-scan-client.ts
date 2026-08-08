/**
 * AIG Scan Client — on-demand deep scan client for the AIG sidecar.
 *
 * Communicates with the AIG Bridge service (FastAPI sidecar) to trigger
 * deep scans of MCP servers, infrastructure, agents, and jailbreak evaluations.
 *
 * Connection to the AIG sidecar is configured via the AIG_BRIDGE_URL
 * environment variable (default: http://localhost:8000).
 */

// ── Types ───────────────────────────────────────────────────────────────────

export type AigScanType = "infra" | "mcp" | "agent" | "jailbreak";

/** Task states emitted by the bridge/task registry. */
export type AigTaskStatus =
	| "pending"
	| "reserved"
	| "queued"
	| "running"
	| "completed"
	| "failed"
	| "cancelled"
	| "expired"
	| "unknown";

export interface AigModelConfig {
	model: string;
	token: string;
	base_url: string;
}

export interface AigInfraScanOptions {
	scan_depth?: "quick" | "standard" | "full";
	timeout?: number;
	headers?: Record<string, string>;
	model?: AigModelConfig;
	[key: string]: unknown;
}

export interface AigMcpScanOptions {
	target_type?: "url" | "source";
	headers?: Record<string, string>;
	categories?: string[];
	eval_model?: AigModelConfig;
	[key: string]: unknown;
}

export interface AigAgentScanOptions {
	agent_id?: string;
	agent_config?: Record<string, unknown>;
	eval_model?: AigModelConfig;
	language?: string;
	prompt?: string;
	[key: string]: unknown;
}

export interface AigJailbreakScanOptions {
	model: string;
	token: string;
	base_url: string;
	test_suites: string[];
	eval_model?: AigModelConfig;
	language?: string;
	[key: string]: unknown;
}

/** Backwards-compatible options bag with typed fields for each bridge route. */
export interface AigScanOptions {
	scan_depth?: "quick" | "standard" | "full";
	target_type?: "url" | "source";
	headers?: Record<string, string>;
	categories?: string[];
	eval_model?: AigModelConfig;
	model?: string;
	token?: string;
	base_url?: string;
	test_suites?: string[];
	agent_id?: string;
	agent_config?: Record<string, unknown>;
	language?: string;
	prompt?: string;
	[key: string]: unknown;
}

export interface AigScanRequest {
	scan_type: AigScanType;
	target?: string;
	options?: AigScanOptions;
	/** Optional retry key forwarded to the bridge for exactly-once submission. */
	idempotency_key?: string;
	/** Tenant scope used by authenticated bridge deployments. */
	tenant_id?: string;
}

export interface AigFinding {
	id: string;
	type: string;
	severity: string;
	title: string;
	description: string;
	recommendation?: string;
}

export interface AigScanResult {
	scan_id: string;
	status: AigTaskStatus;
	findings: AigFinding[];
	summary: {
		total: number;
		critical: number;
		high: number;
		medium: number;
		low: number;
	};
}

export interface BridgeScanResponse {
	task_id: string;
	status: AigTaskStatus;
	estimated_seconds?: number;
}

export interface BridgeHealthResponse {
	status: string;
	version: string;
	aig_server: string;
	scan_ready: boolean;
}

// ── Configuration ───────────────────────────────────────────────────────────

function getBridgeUrl(): string {
	return (process.env.AIG_BRIDGE_URL || "http://localhost:8099").replace(/\/+$/, "");
}

const DEFAULT_TIMEOUT_MS = 30_000;
const TASK_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TASK_STATUSES = new Set<AigTaskStatus>([
	"pending",
	"reserved",
	"queued",
	"running",
	"completed",
	"failed",
	"cancelled",
	"expired",
	"unknown",
]);

function isTaskStatus(value: unknown): value is AigTaskStatus {
	return typeof value === "string" && TASK_STATUSES.has(value as AigTaskStatus);
}

function asBoundedString(value: unknown, fallback = "", max = 4096): string {
	if (typeof value !== "string") return fallback;
	return value.length > max ? value.slice(0, max) : value;
}

function redactValue(value: unknown, depth = 0): unknown {
	if (depth > 5) return "[TRUNCATED]";
	if (typeof value === "string") return asBoundedString(value, "", 2048)
		.replace(/(bearer\s+|sk-[A-Za-z0-9_-]{8,})[^\s,]*/gi, "$1[REDACTED]")
		.replace(/((?:token|secret|password|api[-_]?key)\s*[:=]\s*)[^\s,;]+/gi, "$1[REDACTED]");
	if (Array.isArray(value)) return value.slice(0, 50).map((item) => redactValue(item, depth + 1));
	if (!value || typeof value !== "object") return value;
	const result: Record<string, unknown> = {};
	for (const [key, item] of Object.entries(value as Record<string, unknown>).slice(0, 100)) {
		if (/token|secret|password|authorization|api[-_]?key|cookie|credential/i.test(key)) result[key] = "[REDACTED]";
		else result[key] = redactValue(item, depth + 1);
	}
	return result;
}

function parseBridgeScanResponse(value: unknown): BridgeScanResponse {
	if (!value || typeof value !== "object") throw new AigBridgeError("AIG bridge returned an invalid task response");
	const response = value as Record<string, unknown>;
	if (typeof response.task_id !== "string" || !TASK_ID_RE.test(response.task_id)) {
		throw new AigBridgeError("AIG bridge returned an invalid task id");
	}
	if (!isTaskStatus(response.status)) throw new AigBridgeError("AIG bridge returned an invalid task status");
	return {
		task_id: response.task_id,
		status: response.status,
		...(typeof response.estimated_seconds === "number" ? { estimated_seconds: response.estimated_seconds } : {}),
	};
}

function requireText(value: unknown, field: string): string {
	if (typeof value !== "string" || !value.trim() || value.length > 8_192) {
		throw new AigBridgeError(`AIG ${field} is required`);
	}
	return value.trim();
}

// ── Helpers ─────────────────────────────────────────────────────────────────

export class AigBridgeError extends Error {
	constructor(
		message: string,
		public readonly statusCode?: number,
		public readonly body?: unknown,
	) {
		super(message);
		this.name = "AigBridgeError";
	}
}

async function bridgeRequest<T>(
	path: string,
	options: RequestInit = {},
	timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<T> {
	const url = `${getBridgeUrl()}${path}`;
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);

	try {
		const configuredApiKey = process.env.AIG_BRIDGE_API_KEY || process.env.BRIDGE_API_KEY;
		const tenantId = process.env.AIG_TENANT_ID || process.env.AIDR_TENANT_ID;
		const requestHeaders = new Headers(options.headers);
		requestHeaders.set("Content-Type", "application/json");
		if (configuredApiKey) requestHeaders.set("Authorization", `Bearer ${configuredApiKey}`);
		if (tenantId) requestHeaders.set("X-AIDR-Tenant-ID", tenantId);
		const response = await fetch(url, {
			...options,
			signal: controller.signal,
			headers: requestHeaders,
		});

		if (!response.ok) {
			let body: unknown;
			try {
				body = redactValue(await response.json());
			} catch {
				body = redactValue(await response.text().catch(() => null));
			}
			throw new AigBridgeError(`AIG bridge returned ${response.status}`, response.status, body);
		}

		return (await response.json()) as T;
	} finally {
		clearTimeout(timer);
	}
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Check if the AIG Bridge sidecar is available and ready to accept scan requests.
 */
export async function isAigAvailable(): Promise<boolean> {
	try {
		const health = await bridgeRequest<unknown>("/api/v1/health", {}, 5_000);
		return Boolean(health && typeof health === "object" && (health as Record<string, unknown>).scan_ready === true);
	} catch {
		return false;
	}
}

/**
 * Queue a scan on the AIG Bridge sidecar.
 *
 * The scan type determines which endpoint is called:
 *   - "infra"     → POST /api/v1/scan/infra
 *   - "mcp"       → POST /api/v1/scan/mcp
 *   - "agent"     → POST /api/v1/scan/agent
 *   - "jailbreak" → POST /api/v1/evaluate/jailbreak
 *
 * Returns the task_id for polling results.
 */
export async function triggerAigScan(request: AigScanRequest): Promise<string> {
	const { scan_type, target, options } = request;
	const requestHeaders: Record<string, string> = {};
	if (request.idempotency_key) requestHeaders["Idempotency-Key"] = request.idempotency_key;
	if (request.tenant_id) requestHeaders["X-AIDR-Tenant-ID"] = request.tenant_id;

	switch (scan_type) {
		case "infra": {
			const infraTarget = requireText(target, "infrastructure target");
			const res = parseBridgeScanResponse(await bridgeRequest<unknown>("/api/v1/scan/infra", {
				method: "POST",
				headers: requestHeaders,
				body: JSON.stringify({
					targets: [infraTarget],
					scan_type: options?.scan_depth || "full",
					options: options || {},
				}),
			}));
			return res.task_id;
		}
		case "mcp": {
			const mcpTarget = requireText(target, "MCP target");
			const targetType = options?.target_type === "source" ? "source" : "url";
			const categories = Array.isArray(options?.categories)
				? options.categories.filter((item): item is string => typeof item === "string")
				: [];
			const res = parseBridgeScanResponse(await bridgeRequest<unknown>("/api/v1/scan/mcp", {
				method: "POST",
				headers: requestHeaders,
				body: JSON.stringify({
					target_type: targetType,
					target: mcpTarget,
					headers: options?.headers || {},
					categories,
					eval_model: options?.eval_model,
				}),
			}));
			return res.task_id;
		}
		case "agent": {
			const agentId =
				typeof options?.agent_id === "string"
					? options.agent_id
					: target || undefined;
			const agentConfig =
				options?.agent_config && typeof options.agent_config === "object"
					? options.agent_config
					: undefined;
			const res = parseBridgeScanResponse(await bridgeRequest<unknown>("/api/v1/scan/agent", {
				method: "POST",
				headers: requestHeaders,
				body: JSON.stringify({
					...(agentConfig ? { agent_config: agentConfig } : { agent_id: agentId }),
					eval_model: options?.eval_model,
					language: typeof options?.language === "string" ? options.language : "en",
					prompt: typeof options?.prompt === "string" ? options.prompt : "",
				}),
			}));
			return res.task_id;
		}
		case "jailbreak": {
			const model = requireText(options?.model, "jailbreak model");
			const token = requireText(options?.token, "jailbreak token");
			const baseUrl = requireText(typeof options?.base_url === "string" ? options.base_url : target, "jailbreak base URL");
			const configuredSuites = Array.isArray(options?.test_suites)
				? options.test_suites.filter((item): item is string => typeof item === "string")
				: ["jailbreak"];
			const testSuites = configuredSuites.length > 0 ? configuredSuites : ["jailbreak"];
			const res = parseBridgeScanResponse(await bridgeRequest<unknown>("/api/v1/evaluate/jailbreak", {
				method: "POST",
				headers: requestHeaders,
				body: JSON.stringify({
					target: requireText(target || baseUrl, "jailbreak target"),
					model,
					token,
					base_url: baseUrl,
					test_suites: testSuites,
					language: typeof options?.language === "string" ? options.language : "en",
				}),
			}));
			return res.task_id;
		}
	}
}

/**
 * Poll scan results from the AIG Bridge sidecar.
 *
 * The scan_type determines which endpoint is polled:
 *   - "infra"     → GET /api/v1/scan/infra/{task_id}
 *   - "mcp"       → GET /api/v1/scan/mcp/{task_id}
 *   - "agent"     → GET /api/v1/scan/agent/{task_id}
 *   - "jailbreak" → GET /api/v1/evaluate/jailbreak/{task_id}
 *
 * Returns null if the task is still running or not found.
 */
export async function getAigScanResult(
	scanId: string,
	scanType?: AigScanType,
): Promise<AigScanResult | null> {
	try {
		if (!TASK_ID_RE.test(scanId)) throw new AigBridgeError("Invalid AIG task id");
		const encodedScanId = encodeURIComponent(scanId);
		let endpoint: string;
		switch (scanType) {
			case "infra":
				endpoint = `/api/v1/scan/infra/${encodedScanId}`;
				break;
			case "mcp":
				endpoint = `/api/v1/scan/mcp/${encodedScanId}`;
				break;
			case "agent":
				endpoint = `/api/v1/scan/agent/${encodedScanId}`;
				break;
			case "jailbreak":
				endpoint = `/api/v1/evaluate/jailbreak/${encodedScanId}`;
				break;
			default:
				// Try MCP endpoint first, then infra as a fallback
				endpoint = `/api/v1/scan/mcp/${encodedScanId}`;
				break;
		}

		const raw = await bridgeRequest<Record<string, unknown>>(endpoint, {}, 10_000);

		// Normalize the response from various bridge response shapes
		return normalizeScanResult(raw, scanId);
	} catch (err) {
		if (err instanceof AigBridgeError && err.statusCode === 404) {
			return null;
		}
		throw err;
	}
}

// ── Internal response normalization ─────────────────────────────────────────

function normalizeScanResult(raw: Record<string, unknown>, scanId: string): AigScanResult | null {
	const status = isTaskStatus(raw.status) ? raw.status : "unknown";

	const rawFindings = raw.findings || raw.results || raw.data;
	const findings: AigFinding[] = Array.isArray(rawFindings)
		? rawFindings.map(normalizeFinding)
		: [];

	const summary = raw.summary && typeof raw.summary === "object" ? raw.summary as Record<string, unknown> : {
		total: findings.length,
		critical: findings.filter((f) => f.severity === "critical").length,
		high: findings.filter((f) => f.severity === "high").length,
		medium: findings.filter((f) => f.severity === "medium").length,
		low: findings.filter((f) => f.severity === "low").length,
	};

	return {
		scan_id: scanId,
		status,
		findings,
		summary: {
			total: boundedCount(summary.total, findings.length),
			critical: boundedCount(summary.critical, 0),
			high: boundedCount(summary.high, 0),
			medium: boundedCount(summary.medium, 0),
			low: boundedCount(summary.low, 0),
		},
	};
}

function boundedCount(value: unknown, fallback: number): number {
	return typeof value === "number" && Number.isFinite(value) && value >= 0
		? Math.min(Math.floor(value), 1_000_000)
		: fallback;
}

function normalizeFinding(raw: unknown): AigFinding {
	const item = raw && typeof raw === "object" ? raw as Record<string, unknown> : {};
	const recommendation = item.recommendation ?? item.remediation ?? item.fix;
	return {
		id: asBoundedString(item.id ?? item.cve_id ?? item.finding_id, "", 256),
		type: asBoundedString(item.type ?? item.category, "unknown", 256),
		severity: asBoundedString(item.severity ?? item.risk, "medium", 64).toLowerCase(),
		title: asBoundedString(item.title ?? item.name ?? item.cve_id, "Unknown finding", 512),
		description: asBoundedString(item.description ?? item.detail, "", 4096),
		...(typeof recommendation === "string" ? { recommendation: asBoundedString(recommendation, "", 4096) } : {}),
	};
}
