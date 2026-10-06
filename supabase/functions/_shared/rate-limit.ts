// Fixed-window application rate limiter over the service-role-only
// `public.increment_rate_limit` RPC and `public.rate_limits` table.
//
// The window is one minute. A storage failure is reported as `unavailable`
// and callers must fail closed: these buckets protect unauthenticated or
// credential-bearing endpoints, so an unreadable counter must not become an
// unlimited allowance.

export type RateLimitResult =
	| { status: "allowed" }
	| { status: "limited"; retryAfterSeconds: number }
	| { status: "unavailable"; retryAfterSeconds: number };

const RATE_LIMIT_WINDOW_MS = 60_000;

// Structural subset of the Supabase client: keeps this module free of SDK imports.
export interface RateLimitDb {
	rpc(name: string, args: Record<string, unknown>): PromiseLike<{ error: unknown }>;
	from(table: string): {
		select(columns: string): {
			eq(column: string, value: string | number): {
				eq(column: string, value: string | number): {
					maybeSingle(): PromiseLike<{ data: unknown; error: unknown }>;
				};
			};
		};
	};
}

export function validRateLimit(limit: number, max = 100_000): boolean {
	return Number.isSafeInteger(limit) && limit >= 1 && limit <= max;
}

function retryAfterSeconds(now: number): number {
	return Math.max(1, Math.ceil((RATE_LIMIT_WINDOW_MS - (now % RATE_LIMIT_WINDOW_MS)) / 1000));
}

export async function consumeRateLimit(
	db: RateLimitDb,
	key: string,
	limit: number,
	now = Date.now(),
): Promise<RateLimitResult> {
	const unavailable: RateLimitResult = { status: "unavailable", retryAfterSeconds: 5 };
	if (!validRateLimit(limit, 1_000_000) || !Number.isFinite(now)) return unavailable;
	const windowStart = Math.floor(now / RATE_LIMIT_WINDOW_MS);
	try {
		const increment = await db.rpc("increment_rate_limit", { p_key: key, p_window_start: windowStart, p_delta: 1 });
		if (increment.error) return unavailable;
		const { data, error } = await db.from("rate_limits").select("count").eq("key", key).eq("window_start", windowStart).maybeSingle();
		const count = data && typeof data === "object" && "count" in data ? (data as { count: unknown }).count : null;
		if (error || typeof count !== "number" || !Number.isSafeInteger(count) || count < 1) return unavailable;
		return count > limit ? { status: "limited", retryAfterSeconds: retryAfterSeconds(now) } : { status: "allowed" };
	} catch {
		return unavailable;
	}
}
