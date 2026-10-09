/**
 * Plugin-scan event helpers shared by the overview, events and incidents feeds.
 *
 * A `plugin_scan` payload whose `findings_count` is missing or malformed must
 * not read as "0 finding(s)": that looks like a clean scan when the dashboard
 * actually does not know the result.
 */

/** The reported finding count, or `null` when it is missing or not a valid count. */
export function pluginScanFindingsCount(
	payload: Record<string, unknown> | null | undefined,
): number | null {
	const raw = payload?.findings_count;
	return typeof raw === "number" && Number.isSafeInteger(raw) && raw >= 0 ? raw : null;
}

/** One-line summary: `<plugin>: N finding(s)` or `<plugin>: finding count unavailable`. */
export function pluginScanSummary(payload: Record<string, unknown> | null | undefined): string {
	const key = typeof payload?.plugin_key === "string" ? payload.plugin_key : "plugin";
	const count = pluginScanFindingsCount(payload);
	return count === null ? `${key}: finding count unavailable` : `${key}: ${count} finding(s)`;
}
