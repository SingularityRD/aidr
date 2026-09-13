export interface AuditCursor {
  tenant: string;
  user: string;
  format: "json" | "csv";
  snapshot: string;
  expires: number;
  after: { created_at: string; id: string };
}
const encoder = new TextEncoder();
const timestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
function encode(bytes: Uint8Array): string { return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function decode(text: string): Uint8Array {
  const bytes = Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  // atob accepts nonzero unused bits in the final sextet. Require a single
  // canonical representation so modified cursor strings are always rejected.
  if (encode(bytes) !== text) throw new Error("noncanonical_base64url");
  return bytes;
}
async function key(secret: string) { return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]); }
export async function signAuditCursor(cursor: AuditCursor, secret: string): Promise<string> {
  const payload = encode(encoder.encode(JSON.stringify(cursor)));
  const mac = await crypto.subtle.sign("HMAC", await key(secret), encoder.encode(`aidr-audit-export-v1:${payload}`));
  return `${payload}.${encode(new Uint8Array(mac))}`;
}
export async function readAuditCursor(value: unknown, secret: string, binding: Pick<AuditCursor, "tenant" | "user" | "format">, now = Date.now()): Promise<AuditCursor> {
  try {
    if (typeof value !== "string" || value.length > 2048 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) throw new Error();
    const [payload, mac] = value.split(".");
    if (!await crypto.subtle.verify("HMAC", await key(secret), decode(mac), encoder.encode(`aidr-audit-export-v1:${payload}`))) throw new Error();
    const cursor = JSON.parse(new TextDecoder().decode(decode(payload))) as AuditCursor;
    if (cursor.tenant !== binding.tenant || cursor.user !== binding.user || cursor.format !== binding.format || !Number.isSafeInteger(cursor.expires) || cursor.expires <= now || cursor.expires > now + 900000 || !timestamp.test(cursor.snapshot) || !timestamp.test(cursor.after?.created_at) || !uuid.test(cursor.after?.id) || !Number.isFinite(Date.parse(cursor.snapshot)) || !Number.isFinite(Date.parse(cursor.after.created_at)) || Date.parse(cursor.after.created_at) > Date.parse(cursor.snapshot)) throw new Error();
    return cursor;
  } catch { throw new Error("invalid_or_expired_export_cursor"); }
}
