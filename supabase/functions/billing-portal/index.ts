/**
 * Self-service billing portal (BIL-03 / T33).
 *
 * The portal is a thin, fully server-authorized surface over the settlement
 * ledger. It exists because the dashboard must never hold the provider secret
 * key, and because a "customer id" or "tenant id" supplied by a browser must
 * never decide whose subscription is being read or changed.
 *
 * Request shape (all actions require a browser session bearer token):
 *
 *   GET  /billing-portal                      -> ledger + projected seats
 *   POST /billing-portal  {action:"apply_settlement", receipt:{...}}
 *   POST /billing-portal  {action:"request_seats", request_id, seats, sku}
 *   POST /billing-portal  {action:"cancel", request_id}
 *   POST /billing-portal  {action:"refund", request_id, amount_minor}
 *
 * Guarantees this handler enforces itself (independent of the RPCs):
 *
 *   - `tenant_id` from the body is ignored. It is re-resolved from the Auth
 *     session plus `tenant_members` and cross-checked against the header.
 *   - `customer_id` is never read from the request. It is resolved by the
 *     provider adapter from the stored tenant linkage.
 *   - `AIDR_DASHBOARD_URL` must parse as HTTPS; return URLs are additionally
 *     constrained by `resolveReturnUrl` in settlement.ts.
 *   - Any database, provider or hash failure answers 503 and never a partial
 *     success, and never writes a seat projection.
 */

import { createClient } from "npm:@supabase/supabase-js@2";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { membershipActive, sha256 } from "../_shared/runtime-policy.ts";
import {
	createBillingProvider,
	FixtureBillingProvider,
	ProviderNotConfiguredError,
	ProviderUnavailableError,
	type BillingProvider,
} from "./provider.ts";
import {
	evaluateRefund,
	evaluateSeatChange,
	isUuid,
	projectEntitlement,
	reconcileSeat,
	resolveReturnUrl,
	settlementHashInput,
	settlementReceiptHash,
	sumLineAmounts,
	parseSettlementLine,
	parseSettlementReceipt,
	type SettlementLine,
	type SettlementReceipt,
} from "./settlement.ts";

const REQUIRED_ENV = [
	"SUPABASE_URL",
	"SUPABASE_SERVICE_ROLE_KEY",
	"AIDR_DASHBOARD_URL",
] as const;

const MAX_BODY_BYTES = 16384;
const SEAT_SKU = /^[a-z][a-z0-9_.-]{1,63}$/;

export interface BillingPortalDeps {
	/** Overrides the provider selection; used by the contract suite. */
	provider?: BillingProvider | null;
	/** Overrides `crypto.subtle` hashing; used by the contract suite. */
	hash?: (value: string) => Promise<string>;
	/** Overrides the service-role client; used by the contract suite. */
	db?: ReturnType<typeof createClient>;
}

interface HandlerContext {
	db: ReturnType<typeof createClient>;
	token: string;
	userId: string;
	tenantId: string;
	dashboardUrl: string;
	provider: BillingProvider | null;
	hash: (value: string) => Promise<string>;
}

interface LedgerRow {
	settlement_id: string;
	request_id: string;
	provider: string;
	provider_customer_id: string;
	provider_subscription_id: string | null;
	status: string;
	currency: string;
	lines: unknown;
	total_amount_minor: number;
	quote_reference: string | null;
	settled_amount_minor: number;
	refunded_amount_minor: number;
	occurred_at: string;
	recorded_at: string;
	sequence: number;
	hash_input: string;
	receipt_hash: string;
	external_validation: boolean;
}

function jsonError(
	req: Request,
	status: number,
	error: string,
	extra: Record<string, unknown> = {},
): Response {
	return corsJson(req, status, { ok: false, error, ...extra });
}

/** Bounded, strictly-decoded JSON body. */
async function boundedJson(req: Request): Promise<Record<string, unknown>> {
	const reader = req.body?.getReader();
	if (!reader) throw new Error("invalid_json");
	const chunks: Uint8Array[] = [];
	let size = 0;
	while (true) {
		const { value, done } = await reader.read();
		if (done) break;
		size += value.byteLength;
		if (size > MAX_BODY_BYTES) {
			await reader.cancel();
			throw new Error("request_too_large");
		}
		chunks.push(value);
	}
	const bytes = new Uint8Array(size);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
	} catch {
		throw new Error("invalid_json");
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid_json");
	return parsed as Record<string, unknown>;
}

/**
 * Resolve the tenant from server state only.
 *
 * The caller may name a tenant (so a user who belongs to several teams chooses
 * which one to view), but the named tenant is then *verified*: it must appear
 * in the caller's active memberships. The body's `tenant_id` is never used to
 * skip that check.
 */
async function resolveAuthorizedTenant(
	ctx: Pick<HandlerContext, "db" | "userId" | "token">,
	namedTenant: string | null,
): Promise<{ ok: true; tenantId: string } | { ok: false; status: 401 | 403 | 503; error: string }> {
	// Read the caller's memberships only. `tenant_id` in the body selects among
	// them; it never widens the set, and a name that is not in the set is a 403
	// rather than a lookup against an arbitrary tenant.
	const { data: memberships, error } = await ctx.db
		.from("tenant_members")
		.select("tenant_id,role,expires_at")
		.eq("user_id", ctx.userId);
	if (error) return { ok: false, status: 503, error: "authorization_unavailable" };
	const active = (memberships ?? []).filter(
		(row) => membershipActive(row) && ["owner", "admin"].includes(String(row.role)),
	);
	if (active.length === 0) return { ok: false, status: 403, error: "billing_forbidden" };
	if (namedTenant !== null && namedTenant !== undefined && !isUuid(namedTenant)) {
		return { ok: false, status: 403, error: "billing_forbidden" };
	}
	const candidate = namedTenant ?? (active[0]?.tenant_id as string);
	if (!active.some((row) => row.tenant_id === candidate)) {
		return { ok: false, status: 403, error: "billing_forbidden" };
	}
	const { data: tenant, error: tenantError } = await ctx.db
		.from("tenants")
		.select("status")
		.eq("id", candidate)
		.maybeSingle();
	if (tenantError) return { ok: false, status: 503, error: "authorization_unavailable" };
	if (tenant?.status !== "active") return { ok: false, status: 403, error: "tenant_inactive" };
	const barrier = await checkIdentityBarrier(ctx.db, ctx.token, ctx.userId, candidate);
	if (!barrier.ok) return { ok: false, status: barrier.status, error: barrier.error };
	return { ok: true, tenantId: candidate };
}

function toReceipt(row: LedgerRow): SettlementReceipt {
	const lines: SettlementLine[] = [];
	for (const entry of Array.isArray(row.lines) ? row.lines : []) {
		const parsed = parseSettlementLine(entry);
		if (parsed.ok) lines.push(parsed.value);
	}
	return {
		settlementId: row.settlement_id,
		tenantId: "",
		provider: row.provider === "stripe" ? "stripe" : "provider_fixture",
		providerCustomerId: row.provider_customer_id,
		providerSubscriptionId: row.provider_subscription_id,
		requestId: row.request_id,
		status: row.status as SettlementReceipt["status"],
		currency: row.currency as SettlementReceipt["currency"],
		lines,
		totalAmountMinor: Number(row.total_amount_minor),
		quoteReference: row.quote_reference,
		settledAmountMinor: Number(row.settled_amount_minor),
		refundedAmountMinor: Number(row.refunded_amount_minor),
		occurredAt: row.occurred_at,
		recordedAt: row.recorded_at,
		sequence: Number(row.sequence),
		receiptHash: row.receipt_hash,
		externalValidation: false,
	};
}

async function readLedger(ctx: HandlerContext): Promise<LedgerRow[] | null> {
	const { data, error } = await ctx.db.rpc("list_billing_settlements", {
		p_tenant_id: ctx.tenantId,
		p_actor_user_id: ctx.userId,
	});
	if (error?.code === "42501") return null;
	if (error || !Array.isArray(data)) return null;
	return data as LedgerRow[];
}

async function providerCustomerId(ctx: HandlerContext): Promise<string | null> {
	const { data, error } = await ctx.db
		.from("billing_customers")
		.select("provider_customer_id")
		.eq("tenant_id", ctx.tenantId)
		.maybeSingle();
	if (error) return null;
	const value = (data as { provider_customer_id?: unknown } | null)?.provider_customer_id;
	return typeof value === "string" && value !== "" ? value : null;
}

/**
 * A subscription id is a provider fact that we already recorded. It is never
 * taken from the request body: an unbound or client-named subscription would
 * let a caller redirect a quantity change at another tenant's subscription.
 */
async function linkedSubscriptionId(ctx: HandlerContext): Promise<string | null> {
	const { data, error } = await ctx.db
		.from("subscriptions")
		.select("provider_subscription_id,status")
		.eq("tenant_id", ctx.tenantId)
		.maybeSingle();
	if (error) return null;
	const record = data as { provider_subscription_id?: unknown; status?: unknown } | null;
	const value = record?.provider_subscription_id;
	if (typeof value !== "string" || value === "") return null;
	const status = typeof record?.status === "string" ? record.status.toLowerCase() : "";
	if (status !== "" && !["active", "trialing", "past_due"].includes(status)) return null;
	return value;
}

/**
 * Validate + hash + persist one settlement transition, then return the stored
 * receipt. Every field that decides ownership comes from `ctx`, never from
 * `body`.
 */
async function applySettlement(
	req: Request,
	ctx: HandlerContext,
	body: Record<string, unknown>,
): Promise<Response> {
	const raw = body.receipt;
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
		return jsonError(req, 400, "invalid_receipt");
	}
	const candidate = raw as Record<string, unknown>;
	if (candidate.tenantId !== undefined || candidate.tenant_id !== undefined) {
		return jsonError(req, 400, "tenant_id_must_not_be_supplied");
	}
	if (candidate.providerCustomerId !== undefined || candidate.customer_id !== undefined) {
		return jsonError(req, 400, "customer_id_must_not_be_supplied");
	}

	// The provider customer id is a server fact. Resolve it and reject the whole
	// request when it cannot be established, instead of writing an unbound row.
	if (!ctx.provider) return jsonError(req, 503, "provider_not_configured");
	let customerId: string;
	try {
		customerId = await ctx.provider.ensureCustomer({
			tenantId: ctx.tenantId,
			existingCustomerId: await providerCustomerId(ctx),
		});
	} catch (error) {
		if (error instanceof ProviderNotConfiguredError) return jsonError(req, 503, error.code);
		if (error instanceof ProviderUnavailableError) return jsonError(req, 503, "provider_unavailable");
		return jsonError(req, 503, "provider_unavailable");
	}

	const lines: SettlementLine[] = [];
	for (const entry of Array.isArray(candidate.lines) ? candidate.lines : []) {
		const line = parseSettlementLine(entry);
		if (!line.ok) return jsonError(req, 400, line.error);
		lines.push(line.value);
	}
	if (lines.length === 0) return jsonError(req, 400, "invalid_lines");

	// The subscription is a recorded provider fact, not a client claim. A
	// settlement that claims one is a 409: accepting it would let a caller bind
	// an entitlement (or a later cancellation) to another tenant's subscription.
	const clientSubscription =
		typeof candidate.providerSubscriptionId === "string" ? candidate.providerSubscriptionId : null;
	if (clientSubscription !== null) return jsonError(req, 409, "subscription_id_must_not_be_supplied");
	const subscriptionId = await linkedSubscriptionId(ctx);

	const status = candidate.status;
	// A browser can describe a pending order, but it cannot attest that money
	// was captured. Only a signed provider webhook/reconciler may create a
	// `settled` row; accepting this client field would grant seats for free.
	if (status === "settled") return jsonError(req, 409, "settlement_requires_provider_confirmation");
	const currency = candidate.currency;
	const quoteReference =
		typeof candidate.quoteReference === "string" ? candidate.quoteReference.trim() : null;
	const settledAmountMinor = candidate.settledAmountMinor;
	const refundedAmountMinor = candidate.refundedAmountMinor ?? 0;
	const occurredAt = candidate.occurredAt;
	const sequence = candidate.sequence ?? 0;
	const requestId = typeof candidate.requestId === "string" ? candidate.requestId : "";

	const bound = {
		settlementId: candidate.settlementId,
		tenantId: ctx.tenantId,
		provider: ctx.provider.id,
		providerCustomerId: customerId,
		providerSubscriptionId: subscriptionId,
		requestId,
		status,
		currency,
		lines,
		totalAmountMinor: sumLineAmounts(lines),
		quoteReference: quoteReference === "" ? null : quoteReference,
		settledAmountMinor,
		refundedAmountMinor,
		occurredAt,
		sequence,
		externalValidation: false as const,
	} as unknown as Omit<SettlementReceipt, "receiptHash" | "recordedAt">;

	let hashInput: string;
	let receiptHash: string;
	try {
		hashInput = settlementHashInput(bound);
		receiptHash = await ctx.hash(hashInput);
	} catch {
		return jsonError(req, 503, "receipt_hash_unavailable");
	}

	// Re-parse the fully bound receipt so the exact object that reaches the
	// database is one this module has already validated end to end.
	const validated = parseSettlementReceipt({
		...bound,
		receiptHash,
		recordedAt: new Date(0).toISOString(),
	});
	if (!validated.ok) return jsonError(req, 400, validated.error);

	const { data, error } = await ctx.db.rpc("apply_billing_settlement", {
		p_tenant_id: ctx.tenantId,
		p_actor_user_id: ctx.userId,
		p_settlement_id: bound.settlementId,
		p_request_id: bound.requestId,
		p_provider: bound.provider,
		p_provider_customer_id: bound.providerCustomerId,
		p_provider_subscription_id: bound.providerSubscriptionId,
		p_status: bound.status,
		p_currency: bound.currency,
		p_lines: bound.lines,
		p_total_amount_minor: bound.totalAmountMinor,
		p_quote_reference: bound.quoteReference,
		p_settled_amount_minor: bound.settledAmountMinor,
		p_refunded_amount_minor: bound.refundedAmountMinor,
		p_occurred_at: bound.occurredAt,
		p_sequence: bound.sequence,
		p_hash_input: hashInput,
		p_receipt_hash: receiptHash,
	});
	if (error) {
		if (error.code === "23505") return jsonError(req, 409, "billing_request_conflict");
		if (error.code === "42501") return jsonError(req, 403, "billing_forbidden");
		if (error.code === "22023") return jsonError(req, 400, "invalid_billing_settlement");
		return jsonError(req, 503, "billing_settlement_unavailable");
	}
	if (!data || typeof data !== "object") return jsonError(req, 503, "invalid_billing_settlement_state");

	const stored = toReceipt(data as LedgerRow);
	// The stored record must hash to the same digest we submitted; a mismatch
	// means something rewrote the row between write and read.
	const recomputed = await ctx.hash(stored.hash_input ?? "").catch(() => null);
	const storedHashInput = (data as LedgerRow & { hash_input?: string }).hash_input;
	const integrity =
		typeof storedHashInput === "string" && recomputed !== null && recomputed === stored.receiptHash
			? "verified"
			: "unavailable";
	return corsJson(req, 200, {
		ok: true,
		settlement: stored,
		integrity,
		external_validation: false,
	});
}

async function requestSeats(
	req: Request,
	ctx: HandlerContext,
	body: Record<string, unknown>,
): Promise<Response> {
	if (!ctx.provider) return jsonError(req, 503, "provider_not_configured");
	const requestId = body.request_id;
	if (typeof requestId !== "string" || !/^[A-Za-z0-9_-]{16,80}$/.test(requestId)) {
		return jsonError(req, 400, "invalid_request_id");
	}
	const sku = typeof body.sku === "string" ? body.sku : "aidr.agent.seat";
	if (!SEAT_SKU.test(sku)) return jsonError(req, 400, "invalid_sku");
	const requestedSeats = body.seats;

	const ledger = await readLedger(ctx);
	if (ledger === null) return jsonError(req, 503, "billing_ledger_unavailable");
	const projection = projectEntitlement({
		tenantId: ctx.tenantId,
		receipts: ledger.map((row) => ({ ...toReceipt(row), tenantId: ctx.tenantId })),
	});
	const currentSeats = projection.seats.find((entry) => entry.sku === sku)?.seats ?? 0;
	const decision = evaluateSeatChange(currentSeats, requestedSeats as number);
	if (decision.action === "deny") return jsonError(req, 400, decision.code);

	const subscriptionId = await linkedSubscriptionId(ctx);
	if (!subscriptionId) return jsonError(req, 409, "subscription_not_linked");
	let updated: Awaited<ReturnType<BillingProvider["updateQuantity"]>>;
	try {
		updated = await ctx.provider.updateQuantity(subscriptionId, requestedSeats as number);
	} catch (error) {
		return jsonError(
			req,
			503,
			error instanceof ProviderUnavailableError ? error.code : "provider_unavailable",
		);
	}
	if (!updated || updated.quantity === null) return jsonError(req, 503, "provider_quantity_unavailable");

	const reconciliation = reconcileSeat(projection, sku, updated.quantity);
	const { data, error } = await ctx.db.rpc("recompute_billing_projection", {
		p_tenant_id: ctx.tenantId,
		p_actor_user_id: ctx.userId,
	});
	if (error) return jsonError(req, 503, "billing_projection_unavailable");
	return corsJson(req, 200, {
		ok: true,
		request_id: requestId,
		sku,
		provider_quantity: updated.quantity,
		reconciliation,
		projection: Array.isArray(data) ? data : [],
		external_validation: false,
	});
}

async function cancelOrRefund(
	req: Request,
	ctx: HandlerContext,
	body: Record<string, unknown>,
	action: "cancel" | "refund",
): Promise<Response> {
	const requestId = body.request_id;
	if (typeof requestId !== "string" || !/^[A-Za-z0-9_-]{16,80}$/.test(requestId)) {
		return jsonError(req, 400, "invalid_request_id");
	}
	const settlementId = body.settlement_id;
	if (!isUuid(settlementId)) return jsonError(req, 400, "invalid_settlement_id");
	const ledger = await readLedger(ctx);
	if (ledger === null) return jsonError(req, 503, "billing_ledger_unavailable");
	const rows = ledger
		.filter((row) => row.settlement_id === settlementId)
		.sort((a, b) => b.sequence - a.sequence);
	const latest = rows[0];
	if (!latest) return jsonError(req, 404, "settlement_not_found");
	const receipt = { ...toReceipt(latest), tenantId: ctx.tenantId };

	if (action === "refund") {
		const decision = evaluateRefund(receipt, body.amount_minor as number);
		if (decision.action === "deny") return jsonError(req, 400, decision.code);
		if (!ctx.provider) return jsonError(req, 503, "provider_not_configured");
		let refund: Awaited<ReturnType<BillingProvider["refund"]>>;
		try {
			refund = await ctx.provider.refund({
				providerCustomerId: receipt.providerCustomerId,
				providerSubscriptionId: receipt.providerSubscriptionId,
				amountMinor: decision.refundAmountMinor,
				currency: receipt.currency,
				// Stable across browser retries and concurrent requests: request_id
				// must not permit two provider refunds for one amount.
				idempotencyKey: await ctx.hash(`${ctx.tenantId}:${settlementId}:${decision.refundAmountMinor}:${receipt.currency}`),
			});
		} catch (error) {
			return jsonError(
				req,
				503,
				error instanceof ProviderUnavailableError ? error.code : "provider_unavailable",
			);
		}
		// Provider adapters must return a real provider object id. Never turn an
		// `ok: true`/null response into a locally successful refund.
		if (!refund.ok || typeof refund.refundId !== "string" || refund.refundId.trim() === "") {
			return jsonError(req, 502, refund.reason || "provider_refund_unconfirmed");
		}
		// The ledger only advances after the provider confirms. The refunded
		// receipt is a *new* row, so the original settlement record stays intact.
		const nextReceipt = {
			...receipt,
			requestId,
			status: "refunded" as const,
			refundedAmountMinor: receipt.refundedAmountMinor + decision.refundAmountMinor,
			sequence: latest.sequence + 1,
			occurredAt: new Date().toISOString(),
		};
		const bound = {
			settlementId: nextReceipt.settlementId,
			tenantId: ctx.tenantId,
			provider: ctx.provider.id,
			providerCustomerId: receipt.providerCustomerId,
			providerSubscriptionId: receipt.providerSubscriptionId,
			requestId,
			status: "refunded",
			currency: receipt.currency,
			lines: receipt.lines,
			totalAmountMinor: receipt.totalAmountMinor,
			quoteReference: receipt.quoteReference,
			settledAmountMinor: receipt.settledAmountMinor,
			refundedAmountMinor: nextReceipt.refundedAmountMinor,
			occurredAt: nextReceipt.occurredAt,
			sequence: nextReceipt.sequence,
			externalValidation: false as const,
		} as unknown as Omit<SettlementReceipt, "receiptHash" | "recordedAt">;
		const hashInput = settlementHashInput(bound);
		const receiptHash = await ctx.hash(hashInput);
		const { error } = await ctx.db.rpc("apply_billing_settlement", {
			p_tenant_id: ctx.tenantId,
			p_actor_user_id: ctx.userId,
			p_settlement_id: bound.settlementId,
			p_request_id: bound.requestId,
			p_provider: bound.provider,
			p_provider_customer_id: bound.providerCustomerId,
			p_provider_subscription_id: bound.providerSubscriptionId,
			p_status: bound.status,
			p_currency: bound.currency,
			p_lines: bound.lines,
			p_total_amount_minor: bound.totalAmountMinor,
			p_quote_reference: bound.quoteReference,
			p_settled_amount_minor: bound.settledAmountMinor,
			p_refunded_amount_minor: bound.refundedAmountMinor,
			p_occurred_at: bound.occurredAt,
			p_sequence: bound.sequence,
			p_hash_input: hashInput,
			p_receipt_hash: receiptHash,
		});
		if (error) {
			if (error.code === "23505") return jsonError(req, 409, "billing_request_conflict");
			if (error.code === "42501") return jsonError(req, 403, "billing_forbidden");
			if (error.code === "22023") return jsonError(req, 400, "invalid_billing_transition");
			return jsonError(req, 503, "billing_settlement_unavailable");
		}
		return corsJson(req, 200, {
			ok: true,
			refund_id: refund.refundId,
			refunded_amount_minor: bound.refundedAmountMinor,
			external_validation: false,
		});
	}

	if (latest.status === "refunded") return jsonError(req, 409, "settlement_terminal");
	if (!ctx.provider) return jsonError(req, 503, "provider_not_configured");
	if (receipt.providerSubscriptionId) {
		try {
			await ctx.provider.cancelSubscription(receipt.providerSubscriptionId);
		} catch (error) {
			return jsonError(
				req,
				503,
				error instanceof ProviderUnavailableError ? error.code : "provider_unavailable",
			);
		}
	}
	const occurredAt = new Date().toISOString();
	const bound = {
		settlementId: receipt.settlementId,
		tenantId: ctx.tenantId,
		provider: ctx.provider.id,
		providerCustomerId: receipt.providerCustomerId,
		providerSubscriptionId: receipt.providerSubscriptionId,
		requestId,
		status: "cancelled",
		currency: receipt.currency,
		lines: receipt.lines,
		totalAmountMinor: receipt.totalAmountMinor,
		quoteReference: receipt.quoteReference,
		settledAmountMinor: receipt.settledAmountMinor,
		refundedAmountMinor: receipt.refundedAmountMinor,
		occurredAt,
		sequence: latest.sequence + 1,
		externalValidation: false as const,
	} as unknown as Omit<SettlementReceipt, "receiptHash" | "recordedAt">;
	const hashInput = settlementHashInput(bound);
	const receiptHash = await ctx.hash(hashInput);
	const { error } = await ctx.db.rpc("apply_billing_settlement", {
		p_tenant_id: ctx.tenantId,
		p_actor_user_id: ctx.userId,
		p_settlement_id: bound.settlementId,
		p_request_id: bound.requestId,
		p_provider: bound.provider,
		p_provider_customer_id: bound.providerCustomerId,
		p_provider_subscription_id: bound.providerSubscriptionId,
		p_status: bound.status,
		p_currency: bound.currency,
		p_lines: bound.lines,
		p_total_amount_minor: bound.totalAmountMinor,
		p_quote_reference: bound.quoteReference,
		p_settled_amount_minor: bound.settledAmountMinor,
		p_refunded_amount_minor: bound.refundedAmountMinor,
		p_occurred_at: bound.occurredAt,
		p_sequence: bound.sequence,
		p_hash_input: hashInput,
		p_receipt_hash: receiptHash,
	});
	if (error) {
		if (error.code === "23505") return jsonError(req, 409, "billing_request_conflict");
		if (error.code === "42501") return jsonError(req, 403, "billing_forbidden");
		if (error.code === "22023") return jsonError(req, 400, "invalid_billing_transition");
		return jsonError(req, 503, "billing_settlement_unavailable");
	}
	return corsJson(req, 200, { ok: true, status: "cancelled", external_validation: false });
}

/** Build the request handler. Exported so the contract suite can drive it. */
export function createBillingPortalHandler(deps: BillingPortalDeps = {}) {
	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "GET" && req.method !== "POST") {
			return jsonError(req, 405, "method_not_allowed");
		}
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) {
			return configFailure("billing-portal", config.error, (status, body) =>
				corsJson(req, status, body),
			);
		}

		let provider: BillingProvider | null = null;
		if (deps.provider !== undefined) {
			provider = deps.provider;
		} else {
			try {
				provider = createBillingProvider(runtimeEnv);
			} catch (error) {
				const code = error instanceof ProviderNotConfiguredError ? error.code : "provider_unavailable";
				return jsonError(req, 503, code);
			}
		}

		const allowedReturn = resolveReturnUrl(
			`${config.values.AIDR_DASHBOARD_URL.replace(/\/+$/, "")}/settings`,
			config.values.AIDR_DASHBOARD_URL,
		);
		if (!allowedReturn.ok) return jsonError(req, 500, allowedReturn.error);

		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return jsonError(req, 401, "missing_access_token");

		try {
			const db =
				deps.db ??
				createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, {
					auth: { persistSession: false },
				});
			const { data: auth, error: authError } = await db.auth.getUser(token);
			if (authError || !auth.user?.id) return jsonError(req, 401, "invalid_access_token");

			let body: Record<string, unknown> = {};
			if (req.method === "POST") {
				try {
					body = await boundedJson(req);
				} catch (error) {
					const code = error instanceof Error ? error.message : "invalid_json";
					return jsonError(req, code === "request_too_large" ? 413 : 400, code);
				}
			}

			const context: HandlerContext = {
				db,
				token,
				userId: auth.user.id,
				tenantId: "",
				dashboardUrl: config.values.AIDR_DASHBOARD_URL,
				provider,
				hash: deps.hash ?? sha256,
			};

			// A client may *name* a tenant, but never assert one.
			const namedTenant =
				typeof body.tenant_id === "string"
					? body.tenant_id
					: req.headers.get("X-AIDR-Tenant-ID");
			const resolved = await resolveAuthorizedTenant(context, namedTenant);
			if (!resolved.ok) return jsonError(req, resolved.status, resolved.error);
			context.tenantId = resolved.tenantId;

			if (req.method === "GET") {
				const ledger = await readLedger(context);
				if (ledger === null) return jsonError(req, 503, "billing_ledger_unavailable");
				const { data: projection, error: projectionError } = await db.rpc(
					"recompute_billing_projection",
					{ p_tenant_id: context.tenantId, p_actor_user_id: context.userId },
				);
				if (projectionError) return jsonError(req, 503, "billing_projection_unavailable");
				const receipts = ledger.map((row) => ({
					...toReceipt(row),
					tenantId: context.tenantId,
				}));
				return corsJson(req, 200, {
					ok: true,
					tenant_id: context.tenantId,
					settlements: receipts,
					projection: Array.isArray(projection) ? projection : [],
					self_service: provider !== null,
					external_validation: false,
				});
			}

			const action = body.action;
			if (action === "apply_settlement") return applySettlement(req, context, body);
			if (action === "request_seats") return requestSeats(req, context, body);
			if (action === "cancel") return cancelOrRefund(req, context, body, "cancel");
			if (action === "refund") return cancelOrRefund(req, context, body, "refund");
			return jsonError(req, 400, "unsupported_action");
		} catch {
			return jsonError(req, 503, "billing_portal_unavailable");
		}
	};
}

Deno.serve(createBillingPortalHandler());
