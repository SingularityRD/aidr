import { describe, expect, it } from "vitest";
import { parseAuditExportRange, readAuditCursor, signAuditCursor } from "../_shared/export-cursor.ts";
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
  it("binds the administrative trail: a cursor cannot cross between audit and admin trails", async () => {
    const adminBinding = { ...binding, source: "admin" as const };
    const adminCursor = { ...adminBinding, snapshot: cursor.snapshot, expires: cursor.expires, after: { created_at: cursor.after.created_at, id: "42" } };
    const adminToken = await signAuditCursor(adminCursor, "secret");
    expect(await readAuditCursor(adminToken, "secret", adminBinding, now)).toEqual(adminCursor);
    await expect(readAuditCursor(adminToken, "secret", binding, now)).rejects.toThrow("invalid_or_expired");
    const auditToken = await signAuditCursor(cursor, "secret");
    await expect(readAuditCursor(auditToken, "secret", adminBinding, now)).rejects.toThrow("invalid_or_expired");
    for (const id of ["0", "4.2", "42),id.gt.0", "1".repeat(20)]) {
      const token = await signAuditCursor({ ...adminCursor, after: { ...adminCursor.after, id } }, "secret");
      await expect(readAuditCursor(token, "secret", adminBinding, now)).rejects.toThrow("invalid_or_expired");
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
  it("binds the export range: a cursor cannot be replayed with another or no range", async () => {
    const from = "2026-01-01T00:00:00.000Z";
    const to = new Date(now + 60000).toISOString();
    const ranged = { ...binding, from, to };
    const token = await signAuditCursor({ ...cursor, from, to }, "secret");
    expect(await readAuditCursor(token, "secret", ranged, now)).toMatchObject({ from, to });
    for (const scope of [binding, { ...binding, from }, { ...binding, to }, { ...ranged, from: "2025-01-01T00:00:00.000Z" }, { ...ranged, to: undefined }]) {
      await expect(readAuditCursor(token, "secret", scope, now)).rejects.toThrow("invalid_or_expired");
    }
    // An unranged cursor cannot gain a range either.
    const plain = await signAuditCursor(cursor, "secret");
    await expect(readAuditCursor(plain, "secret", ranged, now)).rejects.toThrow("invalid_or_expired");
    // A signed but inverted or noncanonical range is still refused.
    for (const bad of [{ from: to, to: from }, { from: "2026-01-01", to }]) {
      const forged = await signAuditCursor({ ...cursor, ...bad }, "secret");
      await expect(readAuditCursor(forged, "secret", { ...binding, ...bad }, now)).rejects.toThrow("invalid_or_expired");
    }
  });
  it("parses optional ISO range bounds into canonical UTC", () => {
    expect(parseAuditExportRange(undefined, undefined, now)).toEqual({ ok: true });
    expect(parseAuditExportRange("2026-09-01T03:00:00+03:00", "2026-10-01T00:00Z", now)).toEqual({
      ok: true, from: "2026-09-01T00:00:00.000Z", to: "2026-10-01T00:00:00.000Z",
    });
    expect(parseAuditExportRange(undefined, "2999-01-01T00:00:00Z", now)).toEqual({ ok: true, to: "2999-01-01T00:00:00.000Z" });
    for (const [from, to] of [
      ["2026-09-01", undefined], [undefined, "2026-09-01T00:00:00"], ["2026-02-30T00:00:00Z", undefined],
      ["2026-09-01T24:00:00Z", undefined], ["2026-09-02T00:00:00Z", "2026-09-01T00:00:00Z"],
      ["2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z"], [new Date(now + 3_600_000).toISOString(), undefined],
      ["1999-01-01T00:00:00Z", undefined], [null, undefined], [undefined, 0], ["x".repeat(41), undefined],
    ]) expect(parseAuditExportRange(from, to, now)).toEqual({ ok: false });
  });
});
