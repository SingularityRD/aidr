// Scheduled governance summary (docs/ai-governance-frameworks.md).
//
// POST { action: "dispatch", apply: boolean, limit?: 1..200 }
//   Bearer: the deployment's service credential (SUPABASE_SERVICE_ROLE_KEY),
//   compared in constant time. Called by the hourly maintenance run
//   (scripts/deployment-maintenance.mjs). Claims due schedules, sends one
//   counts-only e-mail per recipient through the deployment mailer and records
//   the outcome, which advances the schedule (a failed send is retried by a
//   later run, at most three attempts per period). `apply: false` only counts
//   the due schedules.
//
// POST { action: "send_test", tenant_id }
//   Bearer: an owner/admin session. Identity barrier, active membership,
//   active workspace and a tenant rate limit apply. Sends the summary for the
//   last cadence window to the configured recipients and records a receipt.
//
// Recipients are always the workspace's own owners (and admins): addresses
// are resolved server-side and never accepted from a request. Every step
// fails closed; a summary that cannot be read is never mailed as zeros.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, type EnvReader, loadConfig } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import {
	dashboardLinkBase,
	deliveryStatus,
	digestIdempotencyKey,
	GovernanceDigestError,
	governanceDigestEmail,
	parseDigestClaims,
	parseDigestTestContext,
	parseGovernanceSummary,
	secretsEqual,
} from "../_shared/governance-digest.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { createMailer, type Mailer } from "../_shared/mailer.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** A test send mails every owner/admin: keep it rare. */
export const GOVERNANCE_TEST_RATE_LIMIT = Object.freeze({ perSubject: 2, perTenant: 4 });
export const GOVERNANCE_DISPATCH_DEFAULT_LIMIT = 50;

const readRuntimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node contract tests use process.env when Deno is unavailable.
	}
	return globalThis.process?.env?.[name];
};

type DatabaseClient = ReturnType<typeof createClient>;

export interface GovernanceDigestDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => DatabaseClient;
	mailer?: Mailer;
	now?: () => number;
}

type Request_ =
	| { action: "dispatch"; apply: boolean; limit: number }
	| { action: "send_test"; tenantId: string };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseRequest(value: unknown): Request_ | null {
	if (!isRecord(value)) return null;
	if (value.action === "dispatch") {
		if (Object.keys(value).some((key) => !["action", "apply", "limit"].includes(key))) return null;
		if (typeof value.apply !== "boolean") return null;
		const limit = value.limit ?? GOVERNANCE_DISPATCH_DEFAULT_LIMIT;
		if (typeof limit !== "number" || !Number.isSafeInteger(limit) || limit < 1 || limit > 200) return null;
		return { action: "dispatch", apply: value.apply, limit };
	}
	if (value.action === "send_test") {
		if (Object.keys(value).some((key) => !["action", "tenant_id"].includes(key))) return null;
		if (typeof value.tenant_id !== "string" || !UUID.test(value.tenant_id)) return null;
		return { action: "send_test", tenantId: value.tenant_id.toLowerCase() };
	}
	return null;
}

/** Sends to each recipient in turn; returns how many the provider accepted. */
async function sendAll(
	mailer: Mailer,
	recipients: string[],
	message: (to: string) => Promise<Parameters<Mailer["send"]>[0]>,
): Promise<number> {
	let delivered = 0;
	for (const to of recipients) {
		const result = await mailer.send(await message(to));
		if (result.ok) delivered += 1;
	}
	return delivered;
}

async function dispatch(
	req: Request,
	db: DatabaseClient,
	mailer: Mailer,
	dashboardUrl: string | null,
	input: { apply: boolean; limit: number },
): Promise<Response> {
	const { data, error } = await db.rpc("claim_due_governance_digests", { p_limit: input.limit, p_apply: input.apply });
	if (error) return corsJson(req, 503, { error: "governance_digest_unavailable" });
	let claims;
	try {
		claims = parseDigestClaims(data);
	} catch (cause) {
		if (cause instanceof GovernanceDigestError) {
			console.error("[governance-digest] claim rejected", JSON.stringify({ path: cause.path }));
			return corsJson(req, 503, { error: "governance_digest_invalid" });
		}
		throw cause;
	}
	const outcome = { sent: 0, partial: 0, failed: 0, no_transport: 0, no_recipients: 0, errors: 0 };
	for (const claim of claims.claims) {
		let status: keyof typeof outcome;
		let delivered = 0;
		if (claim.recipients.length === 0) {
			status = "no_recipients";
		} else if (mailer.provider === "none") {
			status = "no_transport";
		} else {
			const summaryRead = await db.rpc("governance_digest_summary", {
				p_tenant_id: claim.tenantId,
				p_from: claim.periodFrom,
				p_to: claim.periodTo,
			});
			let summary = null;
			try {
				summary = summaryRead.error ? null : parseGovernanceSummary(summaryRead.data);
			} catch (cause) {
				if (!(cause instanceof GovernanceDigestError)) throw cause;
				console.error("[governance-digest] summary rejected", JSON.stringify({ path: cause.path }));
			}
			if (summary) {
				const scope = `${claim.tenantId}/${Date.parse(claim.periodFrom)}`;
				const current = summary;
				delivered = await sendAll(mailer, claim.recipients, async (to) =>
					governanceDigestEmail({
						to,
						workspaceName: claim.tenantName,
						cadence: claim.cadence,
						summary: current,
						dashboardUrl,
						idempotencyKey: await digestIdempotencyKey(scope, to),
						test: false,
					}),
				);
			}
			status = deliveryStatus(claim.recipients.length, delivered);
		}
		const { error: completeError } = await db.rpc("complete_governance_digest", {
			p_tenant_id: claim.tenantId,
			p_claim_id: claim.claimId,
			p_status: status,
			p_recipients: claim.recipients.length,
			p_delivered: delivered,
		});
		if (completeError) outcome.errors += 1;
		else outcome[status] += 1;
	}
	return corsJson(req, 200, {
		ok: true,
		applied: claims.applied,
		due: claims.due,
		processed: claims.claims.length,
		mail_transport: mailer.provider,
		...outcome,
	});
}

async function sendTest(
	now: () => number,
	req: Request,
	db: DatabaseClient,
	mailer: Mailer,
	dashboardUrl: string | null,
	token: string,
	tenantId: string,
): Promise<Response> {
	const { data: auth, error: authError } = await db.auth.getUser(token);
	if (authError || !auth.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
	const userId = auth.user.id;
	const barrier = await checkIdentityBarrier(db, token, userId, tenantId);
	if (!barrier.ok) return corsJson(req, barrier.status, { error: barrier.error });

	const [{ data: member, error: memberError }, { data: tenant, error: tenantError }] = await Promise.all([
		db.from("tenant_members").select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle(),
		db.from("tenants").select("id,status").eq("id", tenantId).maybeSingle(),
	]);
	if (memberError || tenantError) return corsJson(req, 503, { error: "authorization_unavailable" });
	const role = String((member as { role?: unknown } | null)?.role ?? "");
	if (!membershipActive(member as { role?: string; expires_at?: string | null } | null, now()) ||
		!["owner", "admin", "member", "viewer"].includes(role) || !tenant ||
		(tenant as { status?: unknown }).status === "closed") {
		return corsJson(req, 403, { error: "workspace_forbidden" });
	}
	if (role !== "owner" && role !== "admin") return corsJson(req, 403, { error: "governance_role_insufficient" });
	if ((tenant as { status?: unknown }).status !== "active") return corsJson(req, 409, { error: "workspace_not_active" });

	const rate = await consumeTenantRateLimit(db, {
		tenantId,
		subject: userId,
		endpoint: "governance-digest:test",
		...GOVERNANCE_TEST_RATE_LIMIT,
	});
	if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
	const headers = rateLimitHeaders(rate);

	const contextRead = await db.rpc("governance_digest_test_context", { p_tenant_id: tenantId, p_actor_user_id: userId });
	if (contextRead.error) {
		if (contextRead.error.code === "42501") return corsJson(req, 403, { error: "workspace_forbidden" }, headers);
		return corsJson(req, 503, { error: "governance_digest_unavailable" }, headers);
	}
	let context;
	try {
		context = parseDigestTestContext(contextRead.data);
	} catch (cause) {
		if (cause instanceof GovernanceDigestError) return corsJson(req, 503, { error: "governance_digest_invalid" }, headers);
		throw cause;
	}

	let status: "sent" | "partial" | "failed" | "no_transport" | "no_recipients";
	let delivered = 0;
	if (context.recipients.length === 0) {
		status = "no_recipients";
	} else if (mailer.provider === "none") {
		status = "no_transport";
	} else {
		const summaryRead = await db.rpc("governance_digest_summary", {
			p_tenant_id: tenantId,
			p_from: context.periodFrom,
			p_to: context.periodTo,
		});
		if (summaryRead.error) return corsJson(req, 503, { error: "governance_digest_unavailable" }, headers);
		let summary;
		try {
			summary = parseGovernanceSummary(summaryRead.data);
		} catch (cause) {
			if (cause instanceof GovernanceDigestError) return corsJson(req, 503, { error: "governance_digest_invalid" }, headers);
			throw cause;
		}
		const scope = `test/${tenantId}/${Math.floor(now() / 60_000)}`;
		delivered = await sendAll(mailer, context.recipients, async (to) =>
			governanceDigestEmail({
				to,
				workspaceName: context.tenantName,
				cadence: context.cadence,
				summary,
				dashboardUrl,
				idempotencyKey: await digestIdempotencyKey(scope, to),
				test: true,
			}),
		);
		status = deliveryStatus(context.recipients.length, delivered);
	}
	const { error: receiptError } = await db.rpc("record_governance_digest_test", {
		p_tenant_id: tenantId,
		p_actor_user_id: userId,
		p_cadence: context.cadence,
		p_period_from: context.periodFrom,
		p_period_to: context.periodTo,
		p_status: status,
		p_recipients: context.recipients.length,
		p_delivered: delivered,
	});
	if (receiptError) return corsJson(req, 503, { error: "governance_digest_audit_unavailable" }, headers);
	if (status === "no_transport") return corsJson(req, 409, { error: "mail_not_configured" }, headers);
	return corsJson(req, 200, {
		ok: true,
		status,
		recipients: context.recipients.length,
		delivered,
	}, headers);
}

export function createGovernanceDigestHandler(deps: GovernanceDigestDeps = {}) {
	const runtimeEnv = deps.env ?? readRuntimeEnv;
	const now = deps.now ?? Date.now;
	const makeClient = deps.client ?? ((url, key) => createClient(url, key, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	}));

	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) {
			return configFailure("governance-digest", config.error, (status, body) => corsJson(req, status, body));
		}
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });
		const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
		if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
		const request = parseRequest(parsed.value);
		if (!request) return corsJson(req, 400, { error: "invalid_request" });

		const serviceCaller = await secretsEqual(token, config.values.SUPABASE_SERVICE_ROLE_KEY);
		// The scheduled path needs the deployment credential; a user session can
		// only request a test send for its own workspace.
		if (request.action === "dispatch" && !serviceCaller) {
			return corsJson(req, 403, { error: "service_credential_required" });
		}
		if (request.action === "send_test" && serviceCaller) {
			return corsJson(req, 403, { error: "user_session_required" });
		}
		try {
			const db = makeClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY);
			const mailer = deps.mailer ?? createMailer(runtimeEnv);
			const dashboardUrl = dashboardLinkBase(runtimeEnv("AIDR_DASHBOARD_URL"));
			if (request.action === "dispatch") return await dispatch(req, db, mailer, dashboardUrl, request);
			return await sendTest(now, req, db, mailer, dashboardUrl, token, request.tenantId);
		} catch {
			return corsJson(req, 503, { error: "governance_digest_unavailable" });
		}
	};
}

const governanceDigest = createGovernanceDigestHandler();
Deno.serve(governanceDigest);
