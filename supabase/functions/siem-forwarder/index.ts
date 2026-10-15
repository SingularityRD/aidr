// Central SIEM forwarder: drains the SIEM outbox (migration 20261014000130).
//
// POST with `Authorization: Bearer <AIDR_NOTIFICATION_DISPATCH_TOKEN>` (the
// deployment's background-delivery token, shared with the alert dispatcher).
// Invoked by the deployment's scheduler, never by a browser:
//   * Kubernetes: the chart's siem-forwarder CronJob (deploy/helm/aidr)
//   * Compose on-prem: the `siem-forwarder` service (scripts/deployment-prepare.mjs)
//   * Supabase Cloud: pg_cron + pg_net (docs/contracts/siem-forwarding.md)
//
// Each run claims due deliveries per destination under a lease (SKIP LOCKED),
// forwards them in batches (syslog TCP/TLS/UDP with CEF/LEEF/JSON, Splunk HEC,
// Elastic, Microsoft Sentinel, signed webhook), records each outcome with
// exponential backoff (dead letter after max attempts) and prunes terminal
// rows past retention. Delivery is at-least-once.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { ConfigurationError, configFailure, type EnvReader, loadConfig, readConfigValue } from "../_shared/config.ts";
import { denoDnsResolver, type DnsResolver, parseKeyring } from "../_shared/notification-targets.ts";
import { type PlanEntitlementDb, requireFeature } from "../_shared/plan-entitlements.ts";
import { getRequestId } from "../_shared/response.ts";
import { runSiemForwarding, SiemForwardError } from "../_shared/siem-forwarding.ts";
import { denoSocketTransport, type SocketTransport } from "../_shared/socket-transport.ts";

const REQUIRED_ENV = [
	"SUPABASE_URL",
	"SUPABASE_SERVICE_ROLE_KEY",
	"AIDR_NOTIFICATION_DISPATCH_TOKEN",
	"AIDR_NOTIFICATION_ENCRYPTION_KEYS",
] as const;
export const MIN_FORWARDER_TOKEN_LENGTH = 32;

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

export interface SiemForwarderDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => DatabaseClient;
	now?: () => number;
	random?: () => number;
	resolveDns?: DnsResolver;
	transport?: SocketTransport;
}

/** `AIDR_SIEM_ALLOW_PRIVATE_NETWORKS=true` lets destinations opt in to RFC 1918 collectors. */
export function privateNetworksAllowed(env: EnvReader): boolean {
	return readConfigValue(env, "AIDR_SIEM_ALLOW_PRIVATE_NETWORKS").trim().toLowerCase() === "true";
}

/** Plan check used by the forwarder: a downgrade dead-letters, a lookup failure retries. */
export function siemEntitlement(db: PlanEntitlementDb) {
	return async (tenantId: string): Promise<"ok" | "denied" | "unavailable"> => {
		const decision = await requireFeature(db, tenantId, "siem_export");
		if (decision.ok) return "ok";
		return decision.status === 402 ? "denied" : "unavailable";
	};
}

function json(req: Request, status: number, body: Record<string, unknown>): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Request-ID": getRequestId(req) },
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

export function createSiemForwarderHandler(deps: SiemForwarderDeps = {}) {
	const runtimeEnv = deps.env ?? readRuntimeEnv;
	const now = deps.now ?? Date.now;
	const makeClient = deps.client ?? ((url, key) => createClient(url, key, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	}));

	return async function handle(req: Request): Promise<Response> {
		if (req.method !== "POST") return json(req, 405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) return configFailure("siem-forwarder", config.error, (status, body) => json(req, status, body));
		const expected = config.values.AIDR_NOTIFICATION_DISPATCH_TOKEN.trim();
		if (expected.length < MIN_FORWARDER_TOKEN_LENGTH) {
			return configFailure(
				"siem-forwarder",
				new ConfigurationError({ invalid: ["AIDR_NOTIFICATION_DISPATCH_TOKEN"] }),
				(status, body) => json(req, status, body),
			);
		}
		const keyring = await parseKeyring(config.values.AIDR_NOTIFICATION_ENCRYPTION_KEYS);
		if (!keyring) {
			return configFailure(
				"siem-forwarder",
				new ConfigurationError({ invalid: ["AIDR_NOTIFICATION_ENCRYPTION_KEYS"] }),
				(status, body) => json(req, status, body),
			);
		}
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token || !(await sameSecret(token, expected))) return json(req, 401, { error: "invalid_dispatch_token" });

		try {
			const db = makeClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY);
			const summary = await runSiemForwarding(db as never, {
				keyring,
				transport: deps.transport ?? denoSocketTransport,
				resolveDns: deps.resolveDns ?? denoDnsResolver,
				allowPrivateNetworks: privateNetworksAllowed(runtimeEnv),
				entitled: siemEntitlement(db as unknown as PlanEntitlementDb),
				now,
				random: deps.random ?? Math.random,
			});
			const { data: pruned, error: pruneError } = await db.rpc("prune_siem_deliveries", { p_limit: 5000 });
			const prunedCount = (pruned as { deleted?: unknown } | null)?.deleted;
			return json(req, 200, {
				ok: true,
				claimed: summary.claimed,
				delivered: summary.delivered,
				retrying: summary.retrying,
				dead: summary.dead,
				lease_lost: summary.leaseLost,
				pruned: !pruneError && Number.isSafeInteger(prunedCount) ? prunedCount : null,
			});
		} catch (error) {
			const code = error instanceof SiemForwardError ? error.code : "forward_failed";
			console.error("[siem-forwarder] run failed", JSON.stringify({ code }));
			return json(req, 503, { error: "siem_forwarder_unavailable", code });
		}
	};
}

const siemForwarder = createSiemForwarderHandler();
Deno.serve(siemForwarder);
