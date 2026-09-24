import { readBoundedJson } from "./request-limits.ts";

export function getBearerToken(header: string | null): string | null {
	const value = header ?? "";
	const m = value.match(/^Bearer\s+(.+)$/i);
	return m?.[1]?.trim() ? m[1].trim() : null;
}

/** Browser SDKs add their session JWT to Authorization; an explicit device code wins. */
export async function readDeviceCode(req: Request): Promise<string | null> {
	const parsed = await readBoundedJson(req, 2_048);
	if (parsed.ok) {
		const body = parsed.value;
		if (body && typeof body === "object" && "device_code" in body) {
			const code = (body as { device_code: unknown }).device_code;
			return typeof code === "string" && code.trim().length <= 1024 ? code.trim() || null : null;
		}
	}
	if (!parsed.ok && parsed.error === "request_too_large") return null;
	// Native hooks use a bearer device code with no JSON body.
	const bearer = getBearerToken(req.headers.get("Authorization"));
	return bearer && bearer.length <= 1024 ? bearer : null;
}
