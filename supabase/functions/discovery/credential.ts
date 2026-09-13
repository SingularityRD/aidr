const COLLECTOR_CREDENTIAL = /^aidr_dc_[A-Za-z0-9_-]{43}$/;

export function hasCollectorCredentialPrefix(token: string): boolean {
	return token.startsWith("aidr_dc_");
}

export function validCollectorCredential(token: string): boolean {
	return COLLECTOR_CREDENTIAL.test(token);
}

/** A 256-bit secret is returned once; only its digest is persisted. */
export function createCollectorCredential(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(32));
	const base64 = btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
	return `aidr_dc_${base64}`;
}

export async function collectorCredentialHash(token: string): Promise<string> {
	if (!validCollectorCredential(token)) throw new Error("invalid_collector_credential");
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
