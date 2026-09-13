export function getBearerToken(header: string | null): string | null {
	const value = header ?? "";
	const m = value.match(/^Bearer\s+(.+)$/i);
	return m?.[1]?.trim() ? m[1].trim() : null;
}

/** Browser SDKs add their session JWT to Authorization; an explicit device code wins. */
export async function readDeviceCode(req: Request): Promise<string | null> {
	try {
		const body: unknown = await req.json();
		if (body && typeof body === "object" && "device_code" in body) {
			const code = (body as { device_code: unknown }).device_code;
			return typeof code === "string" && code.trim().length <= 1024 ? code.trim() || null : null;
		}
	} catch {
		// Native hooks use a bearer device code with no JSON body.
	}
	return getBearerToken(req.headers.get("Authorization"));
}
