import { describe, expect, it } from "vitest";
import { readAuditCursor, signAuditCursor } from "../_shared/export-cursor.ts";
const now = Date.now();
const binding = { tenant: crypto.randomUUID(), user: crypto.randomUUID(), format: "json" as const };
const cursor = { ...binding, snapshot: new Date(now).toISOString(), expires: now + 600000, after: { created_at: new Date(now - 1000).toISOString(), id: crypto.randomUUID() } };
describe("audit export cursor authorization", () => {
  it("preserves a bounded snapshot and exact cursor", async () => {
    const token = await signAuditCursor(cursor, "secret");
    expect(await readAuditCursor(token, "secret", binding, now)).toEqual(cursor);
  });
  it("rejects tampering, another tenant/user/format, wrong key and expiry", async () => {
    const token = await signAuditCursor(cursor, "secret");
    for (const [value, secret, scope, time] of [
      [token.replace(/.$/, c => c === "A" ? "B" : "A"), "secret", binding, now],
      [token, "wrong", binding, now], [token, "secret", { ...binding, tenant: crypto.randomUUID() }, now],
      [token, "secret", { ...binding, user: crypto.randomUUID() }, now],
      [token, "secret", { ...binding, format: "csv" as const }, now], [token, "secret", binding, now + 600000],
    ] as const) await expect(readAuditCursor(value, secret, scope, time)).rejects.toThrow("invalid_or_expired");
  });
  it("rejects query syntax and cursor positions beyond the snapshot even with a valid MAC", async () => {
    for (const after of [{ ...cursor.after, id: "id),tenant_id.neq.x" }, { ...cursor.after, created_at: new Date(now + 1000).toISOString() }]) {
      const token = await signAuditCursor({ ...cursor, after }, "secret");
      await expect(readAuditCursor(token, "secret", binding, now)).rejects.toThrow();
    }
  });
  it("rejects all noncanonical encodings of the same HMAC bytes", async () => {
    const token = await signAuditCursor(cursor, "secret");
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = alphabet.indexOf(token.at(-1)!);
    expect(last % 4).toBe(0);
    for (const unusedBits of [1, 2, 3]) {
      const modified = token.slice(0, -1) + alphabet[last + unusedBits];
      // The MAC bytes are identical: reject the encoding, not a fake bad MAC.
      const bytes = (value: string) => atob(value.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"));
      expect(bytes(modified)).toEqual(bytes(token));
      await expect(readAuditCursor(modified, "secret", binding, now)).rejects.toThrow("invalid_or_expired");
    }
  });
});
