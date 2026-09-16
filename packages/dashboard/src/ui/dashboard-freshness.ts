/**
 * Browser-side freshness for the live-agent view.
 *
 * This is intentionally separate from central discovery freshness: the dashboard
 * can only classify the `agents.last_seen` value it received. Invalid or future
 * timestamps never become a connected/healthy state.
 */

export const DASHBOARD_CONNECTED_WINDOW_MS = 10 * 60 * 1000;
export type DashboardAgentFreshness = "fresh" | "stale" | "unknown";

export function dashboardAgentFreshness(
	lastSeen: string | null | undefined,
	nowMs = Date.now(),
	windowMs = DASHBOARD_CONNECTED_WINDOW_MS,
): DashboardAgentFreshness {
	if (
		typeof lastSeen !== "string" ||
		!Number.isFinite(nowMs) ||
		!Number.isFinite(windowMs) ||
		windowMs < 0
	) {
		return "unknown";
	}
	const seenMs = Date.parse(lastSeen);
	if (!Number.isFinite(seenMs)) return "unknown";
	return seenMs <= nowMs && nowMs - seenMs <= windowMs ? "fresh" : "stale";
}
