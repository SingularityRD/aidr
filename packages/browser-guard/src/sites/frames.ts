/**
 * Hosts where Browser Guard also runs inside subframes (`all_frames: true`), not only in
 * the top frame.
 *
 * Why: the Microsoft 365 Copilot pane inside the Office web apps (Word, Excel, PowerPoint
 * and Outlook on the web, served from hosts such as `*.officeapps.live.com`,
 * `*.office.com` and `*.cloud.microsoft`) is rendered in a cross-origin iframe. A content
 * script declared for the top frame only never sees text typed there, so the guard is also
 * declared for subframes of the Microsoft 365 Copilot hosts below. The Office host pages
 * themselves get no content script and no host permission: only the Copilot frame is
 * guarded, exactly like the top-level Copilot page (site id `copilot`).
 *
 * UNVERIFIED against a live tenant (readiness item BG-LIVE): Microsoft does not document
 * which origin serves the in-app Copilot pane, and it could not be checked offline. The
 * list is deliberately limited to the Microsoft 365 Copilot hosts the `copilot` adapter
 * already protects at top level (./copilot.ts); if a tenant's pane is served from another
 * origin it is not covered, and adding that host here (and to the adapter) is the fix.
 * Every other site stays top-frame only, so frames of unrelated sites are never touched.
 *
 * Pure data: imported by the site adapters, the build (manifest) and the background
 * worker (which accepts content-script messages from a subframe only on these hosts).
 */
export const M365_COPILOT_HOSTS: readonly string[] = Object.freeze([
	"m365.cloud.microsoft",
	"copilot.cloud.microsoft",
]);

/** Exact HTTPS hosts whose content scripts run in every frame (top frame and subframes). */
export const FRAME_GUARD_HOSTS: readonly string[] = M365_COPILOT_HOSTS;

/** True when `url` is an https URL (no port, no credentials) on a {@link FRAME_GUARD_HOSTS} host. */
export function isFrameGuardUrl(url: unknown): boolean {
	if (typeof url !== "string" || url.length > 8192) return false;
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return false;
	}
	if (parsed.protocol !== "https:" || parsed.port || parsed.username || parsed.password)
		return false;
	return FRAME_GUARD_HOSTS.includes(parsed.hostname);
}

/**
 * Whether the content script may start in a frame: always in the top frame, in a subframe
 * only on a frame-guarded host. The manifest already limits `all_frames` to those hosts;
 * this keeps a future injection path (or a manifest mistake) from guarding frames of
 * unrelated sites.
 */
export function guardRunsInFrame(topFrame: boolean, url: unknown): boolean {
	return topFrame || isFrameGuardUrl(url);
}
