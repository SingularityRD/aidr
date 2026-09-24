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

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
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
type SupabaseClient = ReturnType<typeof createClient<any>>;

export interface BillingPortalDeps {
	/** Overrides the provider selection; used by the contract suite. */
	provider?: BillingProvider | null;
	/** Overrides `crypto.subtle` hashing; used by the contract suite. */
	hash?: (value: string) => Promise<string>;
	/** Overrides the service-role client; used by the contract suite. */
	db?: SupabaseClient;
}

interface HandlerContext {
	db: SupabaseClient;
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

interface ProviderPaymentEvidence {
	provider: "stripe";
	provider_payment_kind: "payment_intent" | "charge";
	provider_payment_id: string;
	provider_customer_id: string;
	provider_subscription_id: string;
	amount_minor: number;
	refunded_amount_minor: number;
	currency: string;
}

class BillingOperationError extends Error {
	constructor(
		readonly status: 400 | 403 | 409 | 503,
		readonly code: string,
		readonly detail: Record<string, unknown> = {},
	) {
		super(code);
	}
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
	const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
	if (!parsed.ok) throw new Error(parsed.error);
	if (!parsed.value || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
		throw new Error("invalid_json");
	}
	return parsed.value as Record<string, unknown>;
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

async function readProviderPayment(
	ctx: HandlerContext,
	settlementId: string,
	providerPaymentId: string | null,
): Promise<{ ok: true; payment: ProviderPaymentEvidence | null } | { ok: false; selectionRequired?: boolean }> {
	const { data, error } = await ctx.db.rpc("get_billing_provider_payment", {
		p_tenant_id: ctx.tenantId,
		p_actor_user_id: ctx.userId,
		p_settlement_id: settlementId,
		p_provider_payment_id: providerPaymentId,
	});
	if (error) return { ok: false };
	if (data === null) return { ok: true, payment: null };
	if (!data || typeof data !== "object" || Array.isArray(data)) return { ok: false };
	const value = data as Record<string, unknown>;
	if (value.selection_required === true) return { ok: false, selectionRequired: true };
	if (
		value.provider !== "stripe" ||
		(value.provider_payment_kind !== "payment_intent" && value.provider_payment_kind !== "charge") ||
		typeof value.provider_payment_id !== "string" ||
		typeof value.provider_customer_id !== "string" ||
		typeof value.provider_subscription_id !== "string" ||
		!Number.isSafeInteger(value.amount_minor) ||
		!Number.isSafeInteger(value.refunded_amount_minor) ||
		typeof value.currency !== "string"
	) return { ok: false };
	return { ok: true, payment: value as unknown as ProviderPaymentEvidence };
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

async function claimBillingOperation(
	ctx: HandlerContext,
	input: { requestId: string; action: "request_seats" | "cancel" | "refund"; resourceId: string; requestHash: string; requestPayload: Record<string, unknown> },
): Promise<
	| { state: "completed"; result: Record<string, unknown>; requestId: string }
	| { state: "new" | "retry"; result: null; requestId: string }
> {
	const { data, error } = await ctx.db.rpc("claim_billing_portal_operation", {
		p_tenant_id: ctx.tenantId,
		p_actor_user_id: ctx.userId,
		p_request_id: input.requestId,
		p_action: input.action,
		p_resource_id: input.resourceId,
		p_request_hash: input.requestHash,
		p_request_payload: input.requestPayload,
	});
	if (error?.code === "23505" || error?.code === "55P03") {
		throw new BillingOperationError(409, error.code === "55P03" ? "billing_operation_in_progress" : "billing_request_conflict");
	}
	if (error?.code === "42501") throw new BillingOperationError(403, "billing_forbidden");
	if (error?.code === "22023") throw new BillingOperationError(400, "invalid_billing_operation");
	if (error || !data || typeof data !== "object" || Array.isArray(data)) {
		throw new BillingOperationError(503, "billing_operation_unavailable");
	}
	const state = (data as Record<string, unknown>).state;
	if (state === "recovery_required") {
		throw new BillingOperationError(409, "billing_recovery_required", {
			recovery_request_id: (data as Record<string, unknown>).effective_request_id,
			recovery_action: (data as Record<string, unknown>).recovery_action,
			recovery_request_hash: (data as Record<string, unknown>).recovery_request_hash,
			recovery_payload: (data as Record<string, unknown>).recovery_payload,
		});
	}
	if (state !== "new" && state !== "retry" && state !== "completed") {
		throw new BillingOperationError(503, "invalid_billing_operation_state");
	}
	const result = (data as Record<string, unknown>).result;
	const effectiveRequestId = (data as Record<string, unknown>).effective_request_id;
	if (typeof effectiveRequestId !== "string" || !/^[A-Za-z0-9_-]{16,80}$/.test(effectiveRequestId)) {
		throw new BillingOperationError(503, "invalid_billing_operation_state");
	}
	if (state === "completed") {
		if (!result || typeof result !== "object" || Array.isArray(result) || (result as Record<string, unknown>).ok !== true) {
			throw new BillingOperationError(503, "invalid_billing_operation_state");
		}
		return { state, result: result as Record<string, unknown>, requestId: effectiveRequestId };
	}
	return { state, result: null, requestId: effectiveRequestId };
}

async function claimBillingOperationRecovering(
	ctx: HandlerContext,
	input: Parameters<typeof claimBillingOperation>[1],
): ReturnType<typeof claimBillingOperation> {
	try {
		return await claimBillingOperation(ctx, input);
	} catch (error) {
		if (!(error instanceof BillingOperationError) || error.code !== "billing_recovery_required") throw error;
		let reconciled = false;
		try {
			reconciled = await reconcileBillingRecovery(ctx, error.detail, input);
		} catch {
			// A provider/database read failure leaves the original operation pending.
		}
		if (!reconciled) {
			if (error.detail.recovery_action === "cancel") {
				throw new BillingOperationError(409, "billing_reconciliation_pending", {
					recovery_request_id: error.detail.recovery_request_id,
					recovery_action: "cancel",
				});
			}
			throw error;
		}
		return claimBillingOperation(ctx, input);
	}
}

async function reconcileBillingRecovery(
	ctx: HandlerContext,
	detail: Record<string, unknown>,
	retryInput: Parameters<typeof claimBillingOperation>[1],
): Promise<boolean> {
	if (!ctx.provider) return false;
	const requestId = detail.recovery_request_id;
	const requestHash = detail.recovery_request_hash;
	const action = detail.recovery_action;
	const payload = detail.recovery_payload;
	if (
		typeof requestId !== "string" || !/^[A-Za-z0-9_-]{16,80}$/.test(requestId) ||
		typeof requestHash !== "string" || !/^[0-9a-f]{64}$/.test(requestHash) ||
		!payload || typeof payload !== "object" || Array.isArray(payload)
	) return false;
	const operation = payload as Record<string, unknown>;
	if (operation.provider !== ctx.provider.id) return false;
	const subscriptionId = operation.subscription_id;
	if (typeof subscriptionId !== "string" || !/^sub_[A-Za-z0-9_]{1,252}$/.test(subscriptionId)) return false;
	let subscription: Awaited<ReturnType<BillingProvider["readSubscription"]>>;
	try {
		subscription = await ctx.provider.readSubscription(subscriptionId);
	} catch {
		return false;
	}
	if (!subscription || subscription.subscriptionId !== subscriptionId) return false;
	let result: Record<string, unknown> | null = null;
	if (
		action === "request_seats" &&
		Number.isSafeInteger(operation.seats) &&
		subscription.quantity === operation.seats
	) {
		const { data, error } = await ctx.db.rpc("recompute_billing_projection", {
			p_tenant_id: ctx.tenantId,
			p_actor_user_id: ctx.userId,
		});
		if (error) return false;
		result = {
			ok: true,
			request_id: requestId,
			provider_quantity: subscription.quantity,
			reconciliation: { action: "noop", delta: 0, reason: "provider_state_recovered" },
			projection: Array.isArray(data) ? data : [],
			external_validation: false,
			recovered: true,
		};
	} else if (action === "cancel" && ["canceled", "cancelled"].includes(subscription.status.toLowerCase())) {
		const settlementId = operation.settlement_id;
		if (!isUuid(settlementId)) return false;
		const ledger = await readLedger(ctx);
		if (ledger === null) return false;
		const rows = ledger
			.filter((row) => row.settlement_id === settlementId)
			.sort((a, b) => b.sequence - a.sequence);
		const latest = rows[0];
		if (!latest) return false;
		const receipt = toReceipt(latest);
		if (receipt.provider !== operation.provider || receipt.providerSubscriptionId !== subscriptionId) return false;

		if (latest.status !== "cancelled") {
			if (!Number.isSafeInteger(latest.sequence) || latest.sequence < 0 ||
				!["quote_issued", "order_placed", "settlement_pending", "settled"].includes(latest.status)) {
				return false;
			}
			const bound = {
				...receipt,
				tenantId: ctx.tenantId,
				requestId,
				status: "cancelled" as const,
				occurredAt: new Date().toISOString(),
				sequence: latest.sequence + 1,
				externalValidation: false as const,
			};
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
			if (error) return false;
		}

		const { data, error } = await ctx.db.rpc("recompute_billing_projection", {
			p_tenant_id: ctx.tenantId,
			p_actor_user_id: ctx.userId,
		});
		if (error) return false;
			result = {
				ok: true,
				request_id: requestId,
			status: "cancelled",
			projection: Array.isArray(data) ? data : [],
			external_validation: false,
				recovered: true,
			};
	} else if (action === "cancel" && ["active", "trialing", "past_due"].includes(subscription.status.toLowerCase())) {
		// The provider confirms the cancellation did not take effect. Release the
		// stale operation only for an exact retry of that same cancellation; a
		// different billing action must remain blocked behind the unresolved intent.
		const sameCancellation = retryInput.action === "cancel" &&
			retryInput.requestId === requestId &&
			retryInput.requestHash === requestHash &&
			retryInput.requestPayload.provider === operation.provider &&
			retryInput.requestPayload.settlement_id === operation.settlement_id &&
			retryInput.requestPayload.subscription_id === subscriptionId;
		if (!sameCancellation) return false;
		await failBillingOperation(ctx, requestId, requestHash);
		return true;
	}
	if (!result) return false;
	try {
		await completeBillingOperation(ctx, requestId, requestHash, result);
		return true;
	} catch {
		return false;
	}
}

async function completeBillingOperation(
	ctx: HandlerContext,
	requestId: string,
	requestHash: string,
	result: Record<string, unknown>,
): Promise<void> {
	const { data, error } = await ctx.db.rpc("complete_billing_portal_operation", {
		p_tenant_id: ctx.tenantId,
		p_actor_user_id: ctx.userId,
		p_request_id: requestId,
		p_request_hash: requestHash,
		p_result: result,
	});
	if (error || data !== true) throw new BillingOperationError(503, "billing_operation_completion_unavailable");
}

async function failBillingOperation(
	ctx: HandlerContext,
	requestId: string,
	requestHash: string,
): Promise<void> {
	const { data, error } = await ctx.db.rpc("fail_billing_portal_operation", {
		p_tenant_id: ctx.tenantId,
		p_actor_user_id: ctx.userId,
		p_request_id: requestId,
		p_request_hash: requestHash,
	});
	if (error || data !== true) throw new BillingOperationError(503, "billing_operation_failure_unavailable");
}

async function releaseBillingOperation(
	req: Request,
	ctx: HandlerContext,
	requestId: string,
	requestHash: string,
	status: 400 | 403 | 409 | 502 | 503,
	code: string,
): Promise<Response> {
	try {
		await failBillingOperation(ctx, requestId, requestHash);
	} catch {
		return jsonError(req, 503, "billing_operation_failure_unavailable");
	}
	return jsonError(req, status, code);
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
	const clientSubscription =
		typeof candidate.providerSubscriptionId === "string" ? candidate.providerSubscriptionId : null;
	if (clientSubscription !== null) return jsonError(req, 409, "subscription_id_must_not_be_supplied");
	const status = candidate.status;
	if (status === "settled") return jsonError(req, 409, "settlement_requires_provider_confirmation");
	if (status === "cancelled" || status === "refunded") {
		return jsonError(req, 409, "settlement_transition_requires_provider_confirmation");
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
	const subscriptionId = await linkedSubscriptionId(ctx);

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
	const storedHashInput = (data as LedgerRow & { hash_input?: string }).hash_input;
	const recomputed = typeof storedHashInput === "string"
		? await ctx.hash(storedHashInput).catch(() => null)
		: null;
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
	if (sku !== "aidr.agent.seat") return jsonError(req, 400, "unsupported_sku");
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
	let requestHash: string;
	let operationRequestId = requestId;
	try {
		requestHash = await ctx.hash(`${ctx.tenantId}\nrequest_seats\n${subscriptionId}\n${sku}\n${requestedSeats}`);
		const claim = await claimBillingOperationRecovering(ctx, {
			requestId,
			action: "request_seats",
			resourceId: `tenant:${ctx.tenantId}`,
			requestHash,
			requestPayload: {
				provider: ctx.provider.id,
				subscription_id: subscriptionId,
				seats: requestedSeats,
				sku,
			},
		});
		operationRequestId = claim.requestId;
		if (claim.state === "completed") {
			return corsJson(req, 200, claim.result);
		}
	} catch (error) {
		if (error instanceof BillingOperationError) return jsonError(req, error.status, error.code, error.detail);
		return jsonError(req, 503, "billing_operation_unavailable");
	}
	let updated: Awaited<ReturnType<BillingProvider["updateQuantity"]>>;
	try {
		updated = await ctx.provider.updateQuantity(
			subscriptionId,
			requestedSeats as number,
			requestHash,
		);
	} catch (error) {
		return releaseBillingOperation(
			req, ctx, operationRequestId, requestHash, 503,
			error instanceof ProviderUnavailableError ? error.code : "provider_unavailable",
		);
	}
	if (!updated || updated.quantity === null) {
		return releaseBillingOperation(req, ctx, operationRequestId, requestHash, 503, "provider_quantity_unavailable");
	}

	const reconciliation = reconcileSeat(projection, sku, updated.quantity);
	const { data, error } = await ctx.db.rpc("recompute_billing_projection", {
		p_tenant_id: ctx.tenantId,
		p_actor_user_id: ctx.userId,
	});
	if (error) {
		return releaseBillingOperation(req, ctx, operationRequestId, requestHash, 503, "billing_projection_unavailable");
	}
	const result = {
		ok: true,
		request_id: operationRequestId,
		sku,
		provider_quantity: updated.quantity,
		reconciliation,
		projection: Array.isArray(data) ? data : [],
		external_validation: false,
	};
	try {
		await completeBillingOperation(ctx, operationRequestId, requestHash, result);
	} catch (error) {
		return jsonError(req, 503, error instanceof BillingOperationError ? error.code : "billing_operation_unavailable");
	}
	return corsJson(req, 200, result);
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
	const requestedPaymentId = body.provider_payment_id;
	if (
		requestedPaymentId !== undefined &&
		(typeof requestedPaymentId !== "string" || !/^(pi|ch)_[A-Za-z0-9_]{1,252}$/.test(requestedPaymentId))
	) return jsonError(req, 400, "invalid_provider_payment_id");
	const paymentResult = action === "refund"
		? await readProviderPayment(ctx, settlementId, typeof requestedPaymentId === "string" ? requestedPaymentId : null)
		: { ok: true as const, payment: null };
	if (!paymentResult.ok) return jsonError(
		req,
		paymentResult.selectionRequired ? 409 : 503,
		paymentResult.selectionRequired ? "provider_payment_selection_required" : "provider_payment_evidence_unavailable",
	);
	const payment = paymentResult.payment;
	const ledger = await readLedger(ctx);
	if (ledger === null) return jsonError(req, 503, "billing_ledger_unavailable");
	const rows = ledger
		.filter((row) => row.settlement_id === settlementId)
		.sort((a, b) => b.sequence - a.sequence);
	const latest = rows[0];
	if (!latest && !payment) return jsonError(req, 404, "settlement_not_found");
	const receipt = latest ? { ...toReceipt(latest), tenantId: ctx.tenantId } : null;

	if (action === "refund") {
		if (payment && receipt && (
			receipt.provider !== payment.provider ||
			receipt.providerCustomerId !== payment.provider_customer_id ||
			receipt.providerSubscriptionId !== payment.provider_subscription_id
		)) return jsonError(req, 409, "provider_payment_binding_conflict");
		const requestedAmount = body.amount_minor;
		if (!Number.isSafeInteger(requestedAmount) || (requestedAmount as number) < 1) {
			return jsonError(req, 400, "refund_amount_invalid");
		}
		if (!ctx.provider) return jsonError(req, 503, "provider_not_configured");
		let requestHash: string;
		let operationRequestId = requestId;
		try {
			requestHash = await ctx.hash(
				`${ctx.tenantId}\nrefund\n${requestId}\n${settlementId}\n${payment?.provider_payment_id ?? "legacy"}\n${requestedAmount}\n${payment?.currency ?? receipt?.currency}`,
			);
			const claim = await claimBillingOperationRecovering(ctx, {
				requestId,
				action: "refund",
				resourceId: `tenant:${ctx.tenantId}`,
				requestHash,
				requestPayload: {
					provider: ctx.provider.id,
					settlement_id: settlementId,
					provider_payment_id: payment?.provider_payment_id ?? null,
					amount_minor: requestedAmount,
				},
			});
			operationRequestId = claim.requestId;
			if (claim.state === "completed") {
				return corsJson(req, 200, claim.result);
			}
		} catch (error) {
			if (error instanceof BillingOperationError) return jsonError(req, error.status, error.code, error.detail);
			return jsonError(req, 503, "billing_operation_unavailable");
		}
		const decision = evaluateRefund(payment ? {
			status: "settled",
			settledAmountMinor: payment.amount_minor,
			refundedAmountMinor: payment.refunded_amount_minor,
		} : receipt as SettlementReceipt, requestedAmount as number);
		if (decision.action === "deny") {
			try {
				await failBillingOperation(ctx, operationRequestId, requestHash);
			} catch {
				return jsonError(req, 503, "billing_operation_failure_unavailable");
			}
			return jsonError(req, 400, decision.code);
		}
		let refund: Awaited<ReturnType<BillingProvider["refund"]>>;
		try {
			refund = await ctx.provider.refund({
				providerCustomerId: payment?.provider_customer_id ?? receipt?.providerCustomerId ?? "",
				providerSubscriptionId: payment?.provider_subscription_id ?? receipt?.providerSubscriptionId ?? null,
				providerPaymentKind: payment?.provider_payment_kind ?? null,
				providerPaymentId: payment?.provider_payment_id ?? null,
				amountMinor: decision.refundAmountMinor,
				currency: payment?.currency ?? receipt?.currency ?? "",
				idempotencyKey: requestHash,
			});
		} catch (error) {
			return releaseBillingOperation(
				req, ctx, operationRequestId, requestHash, 503,
				error instanceof ProviderUnavailableError ? error.code : "provider_unavailable",
			);
		}
		// Provider adapters must return a real provider object id. Never turn an
		// `ok: true`/null response into a locally successful refund.
		if (!refund.ok || typeof refund.refundId !== "string" || refund.refundId.trim() === "") {
			try {
				await failBillingOperation(ctx, operationRequestId, requestHash);
			} catch {
				return jsonError(req, 503, "billing_operation_failure_unavailable");
			}
			return jsonError(req, 502, refund.reason || "provider_refund_unconfirmed");
		}
		if (payment) {
			const { data, error } = await ctx.db.rpc("record_billing_provider_refund", {
				p_tenant_id: ctx.tenantId,
				p_actor_user_id: ctx.userId,
				p_settlement_id: settlementId,
				p_provider_payment_id: payment.provider_payment_id,
				p_request_id: operationRequestId,
				p_request_hash: requestHash,
				p_provider_refund_id: refund.refundId,
				p_amount_minor: decision.refundAmountMinor,
			});
			if (error || !data || typeof data !== "object" || Array.isArray(data)) {
				// The provider may already have accepted the refund. Releasing the
				// claim lets the exact same request retry with the same provider
				// idempotency key and persist that provider result safely.
				return releaseBillingOperation(req, ctx, operationRequestId, requestHash, 503, "billing_refund_record_unavailable");
			}
			try {
				await completeBillingOperation(ctx, operationRequestId, requestHash, {
					ok: true,
					refund_id: refund.refundId,
					refunded_amount_minor: (data as Record<string, unknown>).refunded_amount_minor,
					external_validation: true,
				});
			} catch (error) {
				return jsonError(req, 503, error instanceof BillingOperationError ? error.code : "billing_operation_unavailable");
			}
			return corsJson(req, 200, {
				ok: true,
				refund_id: refund.refundId,
				refunded_amount_minor: (data as Record<string, unknown>).refunded_amount_minor,
				external_validation: true,
			});
		}
		if (!receipt || !latest) return jsonError(req, 404, "settlement_not_found");
		// The ledger only advances after the provider confirms. The refunded
		// receipt is a *new* row, so the original settlement record stays intact.
		const nextReceipt = {
			...receipt,
			requestId: operationRequestId,
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
		let receiptHash: string;
		try {
			receiptHash = await ctx.hash(hashInput);
		} catch {
			return releaseBillingOperation(req, ctx, operationRequestId, requestHash, 503, "billing_refund_record_unavailable");
		}
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
			if (error.code === "23505") return releaseBillingOperation(req, ctx, operationRequestId, requestHash, 409, "billing_request_conflict");
			if (error.code === "42501") return releaseBillingOperation(req, ctx, operationRequestId, requestHash, 403, "billing_forbidden");
			if (error.code === "22023") return releaseBillingOperation(req, ctx, operationRequestId, requestHash, 400, "invalid_billing_transition");
			return releaseBillingOperation(req, ctx, operationRequestId, requestHash, 503, "billing_settlement_unavailable");
		}
		try {
			await completeBillingOperation(ctx, operationRequestId, requestHash, {
				ok: true,
				refund_id: refund.refundId,
				refunded_amount_minor: bound.refundedAmountMinor,
				external_validation: false,
			});
		} catch (error) {
			return jsonError(req, 503, error instanceof BillingOperationError ? error.code : "billing_operation_unavailable");
		}
		return corsJson(req, 200, {
			ok: true,
			refund_id: refund.refundId,
			refunded_amount_minor: bound.refundedAmountMinor,
			external_validation: false,
		});
	}

	if (!receipt || !latest) return jsonError(req, 404, "settlement_not_found");
	if (latest.status === "refunded") return jsonError(req, 409, "settlement_terminal");
	if (!ctx.provider) return jsonError(req, 503, "provider_not_configured");
	let requestHash: string;
	let operationRequestId = requestId;
	let cancellationLatest = latest;
	let cancellationReceipt = receipt;
	try {
		requestHash = await ctx.hash(`${ctx.tenantId}\ncancel\n${settlementId}\n${receipt.providerSubscriptionId ?? "-"}`);
		const claim = await claimBillingOperationRecovering(ctx, {
			requestId,
			action: "cancel",
			resourceId: `tenant:${ctx.tenantId}`,
			requestHash,
			requestPayload: {
				provider: ctx.provider.id,
				settlement_id: settlementId,
				subscription_id: receipt.providerSubscriptionId,
			},
		});
		operationRequestId = claim.requestId;
		if (claim.state === "completed") {
			return corsJson(req, 200, claim.result);
		}
	} catch (error) {
		if (error instanceof BillingOperationError) return jsonError(req, error.status, error.code, error.detail);
		return jsonError(req, 503, "billing_operation_unavailable");
	}
	const currentLedger = await readLedger(ctx);
	if (currentLedger === null) {
		try {
			await failBillingOperation(ctx, operationRequestId, requestHash);
		} catch {
			return jsonError(req, 503, "billing_operation_failure_unavailable");
		}
		return jsonError(req, 503, "billing_ledger_unavailable");
	}
	const currentRows = currentLedger
		.filter((row) => row.settlement_id === settlementId)
		.sort((a, b) => b.sequence - a.sequence);
	const currentLatest = currentRows[0];
	if (!currentLatest) {
		try {
			await failBillingOperation(ctx, operationRequestId, requestHash);
		} catch {
			return jsonError(req, 503, "billing_operation_failure_unavailable");
		}
		return jsonError(req, 404, "settlement_not_found");
	}
	cancellationLatest = currentLatest;
	cancellationReceipt = { ...toReceipt(currentLatest), tenantId: ctx.tenantId };
	if (
		cancellationReceipt.provider !== ctx.provider.id ||
		cancellationReceipt.provider !== receipt.provider ||
		cancellationReceipt.providerSubscriptionId !== receipt.providerSubscriptionId
	) {
		try {
			await failBillingOperation(ctx, operationRequestId, requestHash);
		} catch {
			return jsonError(req, 503, "billing_operation_failure_unavailable");
		}
		return jsonError(req, 409, "provider_binding_conflict");
	}
	if (cancellationLatest.status === "cancelled") {
		const result = { ok: true, status: "cancelled", external_validation: false, recovered: true };
		try {
			await completeBillingOperation(ctx, operationRequestId, requestHash, result);
		} catch (error) {
			return jsonError(req, 503, error instanceof BillingOperationError ? error.code : "billing_operation_unavailable");
		}
		return corsJson(req, 200, result);
	}
	if (cancellationLatest.status === "refunded") {
		try {
			await failBillingOperation(ctx, operationRequestId, requestHash);
		} catch {
			return jsonError(req, 503, "billing_operation_failure_unavailable");
		}
		return jsonError(req, 409, "settlement_terminal");
	}
	if (cancellationReceipt.providerSubscriptionId) {
		let cancellationConfirmed = false;
		try {
			cancellationConfirmed = await ctx.provider.cancelSubscription(
				cancellationReceipt.providerSubscriptionId,
				requestHash,
			);
		} catch (error) {
			let observed: Awaited<ReturnType<BillingProvider["readSubscription"]>> = null;
			try {
				observed = await ctx.provider.readSubscription(cancellationReceipt.providerSubscriptionId);
			} catch {
				// Preserve the processing claim when provider state is still unknown.
			}
			if (observed?.subscriptionId === cancellationReceipt.providerSubscriptionId) {
				const status = observed.status.toLowerCase();
				if (["canceled", "cancelled"].includes(status)) {
					cancellationConfirmed = true;
				} else if (["active", "trialing", "past_due"].includes(status)) {
					try {
						await failBillingOperation(ctx, operationRequestId, requestHash);
					} catch {
						return jsonError(req, 503, "billing_operation_failure_unavailable");
					}
				}
			}
			if (!cancellationConfirmed) {
				return jsonError(
					req,
					503,
					error instanceof ProviderUnavailableError ? error.code : "provider_unavailable",
				);
			}
			// The DELETE may have succeeded while its response was lost; persist
			// the local transition from the provider's terminal state.
		}
		if (!cancellationConfirmed) {
			try {
				await failBillingOperation(ctx, operationRequestId, requestHash);
			} catch {
				return jsonError(req, 503, "billing_operation_failure_unavailable");
			}
			return jsonError(req, 502, "provider_cancellation_unconfirmed");
		}
	}
	const occurredAt = new Date().toISOString();
	const bound = {
		settlementId: cancellationReceipt.settlementId,
		tenantId: ctx.tenantId,
		provider: ctx.provider.id,
		providerCustomerId: cancellationReceipt.providerCustomerId,
		providerSubscriptionId: cancellationReceipt.providerSubscriptionId,
		requestId: operationRequestId,
		status: "cancelled",
		currency: cancellationReceipt.currency,
		lines: cancellationReceipt.lines,
		totalAmountMinor: cancellationReceipt.totalAmountMinor,
		quoteReference: cancellationReceipt.quoteReference,
		settledAmountMinor: cancellationReceipt.settledAmountMinor,
		refundedAmountMinor: cancellationReceipt.refundedAmountMinor,
		occurredAt,
		sequence: cancellationLatest.sequence + 1,
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
	try {
		await completeBillingOperation(ctx, operationRequestId, requestHash, {
			ok: true,
			status: "cancelled",
			external_validation: false,
		});
	} catch (error) {
		return jsonError(req, 503, error instanceof BillingOperationError ? error.code : "billing_operation_unavailable");
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
		const selfServiceEnabled = (runtimeEnv("AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING") ?? "")
			.trim().toLowerCase() === "true";

		let provider: BillingProvider | null = null;
		if (deps.provider !== undefined) {
			provider = deps.provider;
		} else if (selfServiceEnabled) {
			if ((runtimeEnv("AIDR_BILLING_PROVIDER") ?? "").trim().toLowerCase() !== "stripe") {
				return jsonError(req, 503, "provider_not_configured");
			}
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
				if (!selfServiceEnabled) return jsonError(req, 410, "disabled_for_direct_ga");
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
					self_service: selfServiceEnabled && provider !== null,
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
