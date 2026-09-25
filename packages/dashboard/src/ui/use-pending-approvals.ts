import { useEffect, useState } from "react";
import { countPendingApprovals } from "../lib/approvals";

const PENDING_APPROVALS_REFRESH_MS = 30_000;

/**
 * Pending approval count for the navigation badge. `tenantId` null disables
 * the query (no tenant, role unresolved, or a role that cannot decide). Any
 * failure hides the badge; it never shows a fabricated zero.
 */
export function usePendingApprovalCount(tenantId: string | null): number | null {
	const [count, setCount] = useState<number | null>(null);
	useEffect(() => {
		setCount(null);
		if (!tenantId) return;
		let cancelled = false;
		const refresh = () => {
			void countPendingApprovals(tenantId).then((value) => {
				if (!cancelled) setCount(value);
			});
		};
		refresh();
		const timer = setInterval(refresh, PENDING_APPROVALS_REFRESH_MS);
		return () => {
			cancelled = true;
			clearInterval(timer);
		};
	}, [tenantId]);
	return count;
}
