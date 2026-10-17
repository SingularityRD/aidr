export interface AuditCursor {
  tenant: string;
  user: string;
  format: "json" | "csv";
  /** Which trail the cursor pages through; absent means the tenant audit_logs trail. */
  source?: "admin";
  /**
   * Optional half-open export range [from, to) as canonical ISO timestamps.
   * Signed with the cursor, so a later page can never widen or drop it.
   */
  from?: string;
  to?: string;
  snapshot: string;
  expires: number;
  after: { created_at: string; id: string };
}
const encoder = new TextEncoder();
const timestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
// admin_audit_logs ids are a bigint identity.
const bigintId = /^[1-9][0-9]{0,18}$/;
function encode(bytes: Uint8Array): string { return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function decode(text: string): Uint8Array {
  const bytes = Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  // atob accepts nonzero unused bits in the final sextet. Require a single
  // canonical representation so modified cursor strings are always rejected.
  if (encode(bytes) !== text) throw new Error("noncanonical_base64url");
  return bytes;
}
// Range bounds are optional, but when present they are canonical ISO strings.
function rangeValid(cursor: Pick<AuditCursor, "from" | "to">): boolean {
  for (const bound of [cursor.from, cursor.to]) {
    if (bound !== undefined && (typeof bound !== "string" || !timestamp.test(bound) || !Number.isFinite(Date.parse(bound)))) return false;
  }
  return cursor.from === undefined || cursor.to === undefined || Date.parse(cursor.from) < Date.parse(cursor.to);
}
async function key(secret: string) { return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]); }
export async function signAuditCursor(cursor: AuditCursor, secret: string): Promise<string> {
  const payload = encode(encoder.encode(JSON.stringify(cursor)));
  const mac = await crypto.subtle.sign("HMAC", await key(secret), encoder.encode(`aidr-audit-export-v1:${payload}`));
  return `${payload}.${encode(new Uint8Array(mac))}`;
}
export async function readAuditCursor(value: unknown, secret: string, binding: Pick<AuditCursor, "tenant" | "user" | "format" | "source" | "from" | "to">, now = Date.now()): Promise<AuditCursor> {
  try {
    if (typeof value !== "string" || value.length > 2048 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) throw new Error();
    const [payload, mac] = value.split(".");
    if (!await crypto.subtle.verify("HMAC", await key(secret), new Uint8Array(decode(mac)), encoder.encode(`aidr-audit-export-v1:${payload}`))) throw new Error();
    const cursor = JSON.parse(new TextDecoder().decode(decode(payload))) as AuditCursor;
    if (cursor.tenant !== binding.tenant || cursor.user !== binding.user || cursor.format !== binding.format || cursor.source !== binding.source || cursor.from !== binding.from || cursor.to !== binding.to || !rangeValid(cursor) || typeof cursor.after?.id !== "string" || !Number.isSafeInteger(cursor.expires) || cursor.expires <= now || cursor.expires > now + 900000 || !timestamp.test(cursor.snapshot) || !timestamp.test(cursor.after?.created_at) || !(binding.source === "admin" ? bigintId : uuid).test(cursor.after.id) || !Number.isFinite(Date.parse(cursor.snapshot)) || !Number.isFinite(Date.parse(cursor.after.created_at)) || Date.parse(cursor.after.created_at) > Date.parse(cursor.snapshot)) throw new Error();
    return cursor;
  } catch { throw new Error("invalid_or_expired_export_cursor"); }
}

// An ISO 8601 date-time with an explicit zone, at most millisecond precision
// (so normalising to `toISOString()` never moves a bound).
const rangeInput = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:\d{2})$/;
const EARLIEST_RANGE_BOUND = Date.parse("2000-01-01T00:00:00Z");

// Date.parse rolls 2026-02-31 over to March; refuse it instead.
function calendarValid(value: string): boolean {
  const [y, mo, d, h, mi, s = 0] = (value.match(/\d+/g) ?? []).slice(0, 6).map(Number);
  const probe = new Date(Date.UTC(y, mo - 1, d));
  return probe.getUTCFullYear() === y && probe.getUTCMonth() === mo - 1 && probe.getUTCDate() === d && h < 24 && mi < 60 && s < 60;
}

export type AuditExportRange = { ok: true; from?: string; to?: string } | { ok: false };

/**
 * Validate the optional `from` / `to` bounds of an audit export. Each is an
 * ISO timestamp with a zone; the range is half-open [from, to). The result
 * is canonical (UTC, milliseconds) so it can be compared with a signed cursor.
 */
export function parseAuditExportRange(from: unknown, to: unknown, now = Date.now()): AuditExportRange {
  // `from` may not lie in the future (an export that can only ever be empty);
  // `to` may, e.g. the end of the current day.
  const bound = (value: unknown, latest: number): string | undefined | null => {
    if (value === undefined) return undefined;
    if (typeof value !== "string" || value.length > 40 || !rangeInput.test(value) || !calendarValid(value)) return null;
    const ms = Date.parse(value);
    if (!Number.isFinite(ms) || ms < EARLIEST_RANGE_BOUND || ms > latest) return null;
    return new Date(ms).toISOString();
  };
  const start = bound(from, now + 300_000);
  const end = bound(to, Date.parse("9999-12-31T23:59:59.999Z"));
  if (start === null || end === null) return { ok: false };
  if (start !== undefined && end !== undefined && Date.parse(start) >= Date.parse(end)) return { ok: false };
  return { ok: true, ...(start !== undefined ? { from: start } : {}), ...(end !== undefined ? { to: end } : {}) };
}
