export type BoundedJsonResult =
	| { ok: true; value: unknown; bytes: number }
	| { ok: false; status: 400 | 413; error: "invalid_json" | "request_too_large" };

export type BoundedTextResult =
	| { ok: true; value: string; bytes: number }
	| { ok: false; status: 400 | 413; error: "invalid_text" | "request_too_large" };

export type RateLimitResult =
	| { ok: true; remaining: number; retryAfterSeconds: number }
	| {
			ok: false;
			status: 429 | 503;
			error: "rate_limited" | "rate_limit_unavailable";
			remaining: number;
			retryAfterSeconds: number;
	  };

type RpcResult = { data: unknown; error: unknown };
type RpcClient = {
	rpc(name: string, parameters: Record<string, unknown>): PromiseLike<RpcResult>;
};

const textDecoder = new TextDecoder("utf-8", { fatal: true });

function contentLength(message: Request | Response): number | null {
	const raw = message.headers.get("content-length");
	if (raw === null) return null;
	if (!/^\d+$/.test(raw)) return Number.POSITIVE_INFINITY;
	const parsed = Number(raw);
	return Number.isSafeInteger(parsed) ? parsed : Number.POSITIVE_INFINITY;
}

/**
 * Reads UTF-8 body text without ever retaining more than maxBytes of data.
 * Content-Length is only an early rejection hint; streamed bytes are always
 * counted because peers and proxies can omit or misstate that header.
 */
export async function readBoundedText(
	message: Request | Response,
	maxBytes: number,
): Promise<BoundedTextResult> {
	if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
		throw new TypeError("maxBytes must be a positive safe integer");
	}
	const declared = contentLength(message);
	if (declared !== null && declared > maxBytes) {
		return { ok: false, status: 413, error: "request_too_large" };
	}

	const reader = message.body?.getReader();
	if (!reader) return { ok: false, status: 400, error: "invalid_text" };
	const chunks: Uint8Array[] = [];
	let bytes = 0;
	try {
		while (true) {
			const part = await reader.read();
			if (part.done) break;
			bytes += part.value.byteLength;
			if (bytes > maxBytes) {
				// A stream's cancel callback can remain pending indefinitely. The
				// oversized request must still receive a bounded 413 response.
				void reader.cancel("request_too_large").catch(() => undefined);
				return { ok: false, status: 413, error: "request_too_large" };
			}
			chunks.push(part.value);
		}
	} catch {
		return { ok: false, status: 400, error: "invalid_text" };
	} finally {
		reader.releaseLock();
	}

	const joined = new Uint8Array(bytes);
	let offset = 0;
	for (const chunk of chunks) {
		joined.set(chunk, offset);
		offset += chunk.byteLength;
	}
	try {
		return { ok: true, value: textDecoder.decode(joined), bytes };
	} catch {
		return { ok: false, status: 400, error: "invalid_text" };
	}
}

export async function readBoundedJson(
	message: Request | Response,
	maxBytes: number,
): Promise<BoundedJsonResult> {
	const text = await readBoundedText(message, maxBytes);
	if (!text.ok) {
		return {
			ok: false,
			status: text.status,
			error: text.error === "request_too_large" ? text.error : "invalid_json",
		};
	}
	try {
		return { ok: true, value: JSON.parse(text.value), bytes: text.bytes };
	} catch {
		return { ok: false, status: 400, error: "invalid_json" };
	}
}

function rpcRow(value: unknown): Record<string, unknown> | null {
	if (Array.isArray(value) && value.length !== 1) return null;
	const row = Array.isArray(value) ? value[0] : value;
	return row && typeof row === "object" && !Array.isArray(row)
		? (row as Record<string, unknown>)
		: null;
}

/**
 * Consumes both a per-subject and a per-tenant quota through one atomic RPC.
 * Storage or contract failures are availability failures, never implicit allow.
 */
export async function consumeTenantRateLimit(
	database: unknown,
	input: {
		tenantId: string;
		subject: string;
		endpoint: string;
		perSubject: number;
		perTenant: number;
		cost?: number;
		now?: number;
	},
): Promise<RateLimitResult> {
	const now = input.now ?? Date.now();
	const cost = input.cost ?? 1;
	if (
		!input.tenantId ||
		!input.subject ||
		!/^[-a-z0-9_.:/]{1,64}$/i.test(input.endpoint) ||
		![input.perSubject, input.perTenant, cost].every(
			(value) => Number.isSafeInteger(value) && value > 0 && value <= 1_000_000,
		) ||
		input.perSubject > input.perTenant ||
		!Number.isFinite(now)
	) {
		return {
			ok: false,
			status: 503,
			error: "rate_limit_unavailable",
			remaining: 0,
			retryAfterSeconds: 60,
		};
	}

	const windowStart = Math.floor(now / 60_000);
	const retryAfterSeconds = Math.max(1, 60 - Math.floor((now % 60_000) / 1000));
	let result: RpcResult;
	try {
		result = await (database as RpcClient).rpc("consume_tenant_rate_limit", {
			p_tenant_id: input.tenantId,
			p_subject: input.subject,
			p_endpoint: input.endpoint,
			p_window_start: windowStart,
			p_subject_limit: input.perSubject,
			p_tenant_limit: input.perTenant,
			p_cost: cost,
		});
	} catch {
		return {
			ok: false,
			status: 503,
			error: "rate_limit_unavailable",
			remaining: 0,
			retryAfterSeconds,
		};
	}
	if (!result || typeof result !== "object" || result.error) {
		return {
			ok: false,
			status: 503,
			error: "rate_limit_unavailable",
			remaining: 0,
			retryAfterSeconds,
		};
	}
	const row = rpcRow(result.data);
	if (
		!row ||
		typeof row.allowed !== "boolean" ||
		typeof row.remaining !== "number" ||
		!Number.isSafeInteger(row.remaining) ||
		row.remaining < 0
	) {
		return {
			ok: false,
			status: 503,
			error: "rate_limit_unavailable",
			remaining: 0,
			retryAfterSeconds,
		};
	}
	if (!row.allowed) {
		return {
			ok: false,
			status: 429,
			error: "rate_limited",
			remaining: row.remaining,
			retryAfterSeconds,
		};
	}
	return { ok: true, remaining: row.remaining, retryAfterSeconds };
}

export function rateLimitHeaders(result: RateLimitResult): Record<string, string> {
	const headers: Record<string, string> = {
		"RateLimit-Remaining": String(result.remaining),
	};
	if (!result.ok) headers["Retry-After"] = String(result.retryAfterSeconds);
	return headers;
}
