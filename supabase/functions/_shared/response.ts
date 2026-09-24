/** Common response boundary for Edge Functions.
 *
 * Every public response gets a caller-safe request id. The id is accepted
 * only when it matches the constrained token format; otherwise a fresh UUID
 * is generated so clients cannot inject log delimiters or PII.
 */
export function getRequestId(req: Request): string {
	const supplied = (req.headers.get("x-request-id") ?? "").trim();
	return /^[A-Za-z0-9._:-]{1,128}$/.test(supplied) ? supplied : crypto.randomUUID();
}
