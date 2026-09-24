import { isUuid, type StripeEventEvaluation } from "./events.ts";

export interface StripeCustomerLinkage {
	userId: string;
	tenantId: string;
}

export function selectStripeCustomerLinkage(
	rows: unknown,
	hints: { userId?: string | null; tenantId?: string | null } = {},
): { linkage: StripeCustomerLinkage | null; conflict: boolean; ambiguous: boolean } {
	if (!Array.isArray(rows)) return { linkage: null, conflict: false, ambiguous: false };
	const candidates = rows.filter((value): value is Record<string, unknown> =>
		!!value && typeof value === "object" && !Array.isArray(value) &&
		isUuid((value as Record<string, unknown>).user_id) &&
		isUuid((value as Record<string, unknown>).tenant_id)
	);
	const matches = candidates.filter((row) =>
		(!hints.userId || row.user_id === hints.userId) &&
		(!hints.tenantId || row.tenant_id === hints.tenantId)
	);
	if (matches.length === 1) {
		return {
			linkage: { userId: matches[0].user_id as string, tenantId: matches[0].tenant_id as string },
			conflict: false,
			ambiguous: false,
		};
	}
	return {
		linkage: null,
		// A customer reused by another tenant is allowed. Only a different
		// user binding inside the event's claimed tenant is a conflict.
		conflict: !!hints.tenantId &&
			candidates.some((row) => row.tenant_id === hints.tenantId) &&
			matches.length === 0,
		ambiguous: matches.length > 1,
	};
}

/** An offboarded buyer may still revoke seats on their already-bound subscription. */
export function isBoundZeroSeatTransition(evaluation: StripeEventEvaluation, row: unknown, userId: string, tenantId: string): boolean {
	if (evaluation.action !== "reconcile" || !evaluation.writeEntitlement || evaluation.extraAgents !== 0 ||
		!evaluation.subscriptionId || !isUuid(userId) || !isUuid(tenantId) ||
		!row || typeof row !== "object" || Array.isArray(row)) return false;
	const bound = row as Record<string, unknown>;
	return bound.provider === "stripe" && bound.provider_subscription_id === evaluation.subscriptionId &&
		bound.user_id === userId && bound.tenant_id === tenantId;
}
