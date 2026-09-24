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
