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

export interface AigScanRequest {
	scan_type: AigScanType;
	target?: string;
	options?: Record<string, unknown>;
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
	status: "pending" | "running" | "completed" | "failed";
	findings: AigFinding[];
	summary: {
		total: number;
		critical: number;
		high: number;
		medium: number;
		low: number;
	};
}

interface BridgeScanResponse {
	task_id: string;
	status: string;
	estimated_seconds?: number;
}

interface BridgeHealthResponse {
	status: string;
	version: string;
	aig_server: string;
	scan_ready: boolean;
}

// ── Configuration ───────────────────────────────────────────────────────────

function getBridgeUrl(): string {
	return (process.env.AIG_BRIDGE_URL || "http://localhost:8000").replace(/\/+$/, "");
}

const DEFAULT_TIMEOUT_MS = 30_000;

// ── Helpers ─────────────────────────────────────────────────────────────────

class AigBridgeError extends Error {
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
		const response = await fetch(url, {
			...options,
			signal: controller.signal,
			headers: {
				"Content-Type": "application/json",
				...options.headers,
			},
		});

		if (!response.ok) {
			let body: unknown;
			try {
				body = await response.json();
			} catch {
				body = await response.text().catch(() => null);
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
		const health = await bridgeRequest<BridgeHealthResponse>("/api/v1/health", {}, 5_000);
		return health.scan_ready === true;
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

	switch (scan_type) {
		case "infra": {
			const res = await bridgeRequest<BridgeScanResponse>("/api/v1/scan/infra", {
				method: "POST",
				body: JSON.stringify({
					targets: target ? [target] : [],
					scan_type: options?.scan_depth || "full",
					options: options || {},
				}),
			});
			return res.task_id;
		}
		case "mcp": {
			const res = await bridgeRequest<BridgeScanResponse>("/api/v1/scan/mcp", {
				method: "POST",
				body: JSON.stringify({
					mcp_server_url: target || "",
					options: options || {},
				}),
			});
			return res.task_id;
		}
		case "agent": {
			const res = await bridgeRequest<BridgeScanResponse>("/api/v1/scan/agent", {
				method: "POST",
				body: JSON.stringify({
					target: target || "",
					options: options || {},
				}),
			});
			return res.task_id;
		}
		case "jailbreak": {
			const res = await bridgeRequest<BridgeScanResponse>("/api/v1/evaluate/jailbreak", {
				method: "POST",
				body: JSON.stringify({
					prompt: target || "",
					options: options || {},
				}),
			});
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
		let endpoint: string;
		switch (scanType) {
			case "infra":
				endpoint = `/api/v1/scan/infra/${scanId}`;
				break;
			case "mcp":
				endpoint = `/api/v1/scan/mcp/${scanId}`;
				break;
			case "agent":
				endpoint = `/api/v1/scan/agent/${scanId}`;
				break;
			case "jailbreak":
				endpoint = `/api/v1/evaluate/jailbreak/${scanId}`;
				break;
			default:
				// Try MCP endpoint first, then infra as a fallback
				endpoint = `/api/v1/scan/mcp/${scanId}`;
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
	const status = (raw.status as string) || "running";

	const rawFindings = raw.findings || raw.results || raw.data;
	const findings: AigFinding[] = Array.isArray(rawFindings)
		? rawFindings.map(normalizeFinding)
		: [];

	const summary = (raw.summary as Record<string, number>) || {
		total: findings.length,
		critical: findings.filter((f) => f.severity === "critical").length,
		high: findings.filter((f) => f.severity === "high").length,
		medium: findings.filter((f) => f.severity === "medium").length,
		low: findings.filter((f) => f.severity === "low").length,
	};

	return {
		scan_id: scanId,
		status: status as AigScanResult["status"],
		findings,
		summary: {
			total: summary.total ?? findings.length,
			critical: summary.critical ?? 0,
			high: summary.high ?? 0,
			medium: summary.medium ?? 0,
			low: summary.low ?? 0,
		},
	};
}

function normalizeFinding(raw: unknown): AigFinding {
	const item = raw as Record<string, unknown>;
	return {
		id: (item.id || item.cve_id || item.finding_id || "") as string,
		type: (item.type || item.category || "unknown") as string,
		severity: (item.severity || item.risk || "medium") as string,
		title: (item.title || item.name || item.cve_id || "Unknown finding") as string,
		description: (item.description || item.detail || "") as string,
		recommendation: (item.recommendation || item.remediation || item.fix || undefined) as
			| string
			| undefined,
	};
}
