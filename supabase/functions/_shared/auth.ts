export function getBearerToken(header: string | null): string | null {
	const value = header ?? "";
	const m = value.match(/^Bearer\s+(.+)$/i);
	return m?.[1]?.trim() ? m[1].trim() : null;
}
