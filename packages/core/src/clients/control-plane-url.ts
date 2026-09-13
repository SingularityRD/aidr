/** Resolve either an AIDR gateway base or a hosted/self-hosted Supabase Functions base. */
export function controlPlaneUrl(endpoint: string, operation: string): string {
	const base = endpoint.trim().replace(/\/+$/, "");
	const path = operation.replace(/^\/+/, "");
	if (!/^[a-z][a-z0-9-]*$/.test(path)) throw new Error("Invalid control plane operation");
	return /\/v1$/.test(base) ? `${base}/${path}` : `${base}/v1/${path}`;
}
