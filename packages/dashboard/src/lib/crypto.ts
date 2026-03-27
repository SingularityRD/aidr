function base64UrlEncode(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	const b64 = btoa(bin);
	return b64.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function generateApiKey(): string {
	const bytes = new Uint8Array(24);
	crypto.getRandomValues(bytes);
	return `aidr_live_${base64UrlEncode(bytes)}`;
}

export async function sha256Hex(input: string): Promise<string> {
	const data = new TextEncoder().encode(input);
	const digest = await crypto.subtle.digest("SHA-256", data);
	const bytes = new Uint8Array(digest);
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

