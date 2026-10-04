/** Resolve either an AIDR gateway base or a hosted/self-hosted Supabase Functions base. */
export function controlPlaneUrl(endpoint: string, operation: string): string {
	const base = endpoint.trim().replace(/\/+$/, "");
	const path = operation.replace(/^\/+/, "");
	if (!/^[a-z][a-z0-9-]*$/.test(path)) throw new Error("Invalid control plane operation");
	return /\/v1$/.test(base) ? `${base}/${path}` : `${base}/v1/${path}`;
}

export function assertSecureControlPlaneEndpoint(
	endpoint: string,
	allowInsecureLoopback = false,
): void {
	if (!endpoint) return;
	try {
		const parsed = new URL(endpoint);
		const loopback =
			parsed.hostname === "localhost" ||
			parsed.hostname === "[::1]" ||
			/^127(?:\.\d{1,3}){3}$/.test(parsed.hostname);
		if (
			parsed.protocol === "https:" ||
			(parsed.protocol === "http:" && loopback && allowInsecureLoopback)
		) {
			return;
		}
	} catch {
		// Use the same actionable error for malformed and insecure endpoints.
	}
	throw new Error(
		"Control plane endpoint must use HTTPS (loopback HTTP requires allow_insecure_loopback)",
	);
}

/**
 * Control plane used by `mode: "managed"` installs that do not set
 * `control_plane.endpoint`.
 *
 * This is the origin that serves the connector API (`/v1/device-start`,
 * `/v1/device-poll`, `/v1/enroll`, `/v1/ingest`, `/v1/policy`, `/v1/revocations`):
 * the AIDR web application (Next.js `src/app/v1/*` in the aidr-landing repo).
 * The previous default, `aidr-control.svc.singularityrd.com`, never had DNS
 * (AIDR-016). Local mode (the default) never contacts it.
 */
export const DEFAULT_CONTROL_PLANE_ENDPOINT = "https://aidr.singularityrd.com";
