// Alert dispatcher: drains the notification outbox.
//
// POST with `Authorization: Bearer <AIDR_NOTIFICATION_DISPATCH_TOKEN>`. Invoked
// once a minute by the deployment's scheduler, never by a browser:
//   * Supabase Cloud: pg_cron + pg_net (docs/control-plane.md, "Alert integrations")
//   * Compose on-prem: aidr-notification-dispatch.timer (deploy/maintenance)
//   * Kubernetes: the chart's notification-dispatch CronJob (deploy/helm/aidr)
//
// Each run first enqueues the scheduled alerts (agent offline/recovered,
// overdue AI register reviews, expiring governance exceptions) through
// enqueue_scheduled_notifications, then claims due deliveries under a lease (SKIP LOCKED, so overlapping
// runs never send the same row twice unless a lease expires), delivers them
// with SSRF checks, signatures and a 10 s timeout, records the outcome with
// exponential backoff, and prunes terminal deliveries past retention.
// Delivery is at-least-once; every message carries its delivery id as the
// idempotency key.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { ConfigurationError, configFailure, type EnvReader, loadConfig, readConfigValue } from "../_shared/config.ts";
import { createMailer, type Mailer } from "../_shared/mailer.ts";
import { DispatchError, runNotificationDispatch } from "../_shared/notification-delivery.ts";
import { denoDnsResolver, type DnsResolver, parseKeyring } from "../_shared/notification-targets.ts";
import { getRequestId } from "../_shared/response.ts";

const REQUIRED_ENV = [
	"SUPABASE_URL",
	"SUPABASE_SERVICE_ROLE_KEY",
	"AIDR_NOTIFICATION_DISPATCH_TOKEN",
	"AIDR_NOTIFICATION_ENCRYPTION_KEYS",
] as const;
export const MIN_DISPATCH_TOKEN_LENGTH = 32;

const readRuntimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node contract tests use process.env when Deno is unavailable.
	}
	return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[name];
};

type DatabaseClient = ReturnType<typeof createClient<any, "public">>;

export interface NotificationDispatchDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => DatabaseClient;
	now?: () => number;
	random?: () => number;
	fetch?: typeof fetch;
	resolveDns?: DnsResolver;
	mailer?: Mailer;
}

function json(req: Request, status: number, body: Record<string, unknown>): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			"Content-Type": "application/json",
			"Cache-Control": "no-store",
			"X-Request-ID": getRequestId(req),
		},
	});
}

async function sameSecret(presented: string, expected: string): Promise<boolean> {
	const digest = async (value: string) =>
		new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
	const [a, b] = await Promise.all([digest(presented), digest(expected)]);
	let diff = 0;
	for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
	return diff === 0;
}

const SCHEDULED_KEYS = [
	"agent_offline",
	"agent_recovered",
	"governance_review_overdue",
	"governance_exception_expiring",
	"capped",
] as const;
export const SCHEDULED_SCAN_LIMIT = 500;

/**
 * Enqueue the time-based alerts. This is a detection internal: a failure is
 * logged and reported as `scheduled: null` (never as "nothing due") and the
 * run still drains the outbox, so event alerts are never held hostage by it.
 */
export async function enqueueScheduledNotifications(db: {
	rpc(name: string, args: Record<string, unknown>): PromiseLike<{ data: unknown; error: unknown }>;
}): Promise<Record<string, number> | { skipped: true } | null> {
	try {
		const { data, error } = await db.rpc("enqueue_scheduled_notifications", { p_limit: SCHEDULED_SCAN_LIMIT });
		const row = data as Record<string, unknown> | null;
		if (error || !row || typeof row !== "object") throw new Error("scheduled_scan_failed");
		if (row.skipped === true) return { skipped: true };
		const counts: Record<string, number> = {};
		for (const key of SCHEDULED_KEYS) {
			const value = row[key];
			if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new Error("scheduled_scan_failed");
			counts[key] = value;
		}
		return counts;
	} catch {
		console.error("[notification-dispatch] scheduled scan failed", JSON.stringify({ code: "scheduled_scan_failed" }));
		return null;
	}
}

export function createNotificationDispatchHandler(deps: NotificationDispatchDeps = {}) {
	const runtimeEnv = deps.env ?? readRuntimeEnv;
	const now = deps.now ?? Date.now;
	const makeClient = deps.client ?? ((url, key) => createClient(url, key, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	}));

	return async function handle(req: Request): Promise<Response> {
		if (req.method !== "POST") return json(req, 405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) {
			return configFailure("notification-dispatch", config.error, (status, body) => json(req, status, body));
		}
		const expected = config.values.AIDR_NOTIFICATION_DISPATCH_TOKEN.trim();
		if (expected.length < MIN_DISPATCH_TOKEN_LENGTH) {
			return configFailure(
				"notification-dispatch",
				new ConfigurationError({ invalid: ["AIDR_NOTIFICATION_DISPATCH_TOKEN"] }),
				(status, body) => json(req, status, body),
			);
		}
		const keyring = await parseKeyring(config.values.AIDR_NOTIFICATION_ENCRYPTION_KEYS);
		if (!keyring) {
			return configFailure(
				"notification-dispatch",
				new ConfigurationError({ invalid: ["AIDR_NOTIFICATION_ENCRYPTION_KEYS"] }),
				(status, body) => json(req, status, body),
			);
		}

		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token || !(await sameSecret(token, expected))) return json(req, 401, { error: "invalid_dispatch_token" });

		try {
			const db = makeClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY);
			const scheduled = await enqueueScheduledNotifications(db as never);
			const summary = await runNotificationDispatch(db as never, {
				keyring,
				dashboardUrl: readConfigValue(runtimeEnv, "AIDR_DASHBOARD_URL"),
				fetch: deps.fetch ?? fetch,
				resolveDns: deps.resolveDns ?? denoDnsResolver,
				mailer: deps.mailer ?? createMailer(runtimeEnv),
				now,
				random: deps.random ?? Math.random,
			});
			const { data: pruned, error: pruneError } = await db.rpc("prune_notification_deliveries", { p_limit: 1000 });
			const prunedCount = (pruned as { deleted?: unknown } | null)?.deleted;
			return json(req, 200, {
				ok: true,
				claimed: summary.claimed,
				delivered: summary.delivered,
				retrying: summary.retrying,
				dead: summary.dead,
				lease_lost: summary.leaseLost,
				pruned: !pruneError && Number.isSafeInteger(prunedCount) ? prunedCount : null,
				scheduled,
			});
		} catch (error) {
			const code = error instanceof DispatchError ? error.code : "dispatch_failed";
			console.error("[notification-dispatch] run failed", JSON.stringify({ code }));
			return json(req, 503, { error: "notification_dispatch_unavailable", code });
		}
	};
}

const notificationDispatch = createNotificationDispatchHandler();
Deno.serve(notificationDispatch);
