import { afterEach, describe, expect, it, vi } from "vitest";
import { collectAuditExport } from "../enterprise/audit-export";
afterEach(() => vi.unstubAllGlobals());
const page = (next: string | null, rows = 1) => ({ ok: true, url: "https://storage.example.test/export", rows, snapshot: "2026-09-11T00:00:00Z", next_cursor: next, complete: next === null });
describe("paginated audit download", () => {
  it("combines JSON pages without omitting or duplicating rows", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response('[{"id":"a"}]')).mockResolvedValueOnce(new Response('[{"id":"b"}]')));
    const get = vi.fn().mockResolvedValueOnce(page("cursor-2")).mockResolvedValueOnce(page(null));
    expect(JSON.parse(await (await collectAuditExport("json", get)).text())).toEqual([{ id: "a" }, { id: "b" }]);
    expect(get).toHaveBeenNthCalledWith(2, "cursor-2");
  });
  it("preserves quoted multiline CSV while removing only repeated headers", async () => {
    const header = "id,created_at,user_id,action,verdict";
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response(`${header}\r\n"a","","","line\r\nbreak",""`)).mockResolvedValueOnce(new Response(`${header}\r\n"b","","","'=formula",""`)));
    const get = vi.fn().mockResolvedValueOnce(page("cursor-2")).mockResolvedValueOnce(page(null));
    const text = await (await collectAuditExport("csv", get)).text();
    expect(text.split(header)).toHaveLength(2); expect(text).toContain('"line\r\nbreak"'); expect(text).toContain("'=formula");
  });
  it("rejects partial downloads, row mismatch, snapshot changes and repeated cursors", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(() => Promise.resolve(new Response('[{"id":"a"}]'))));
    await expect(collectAuditExport("json", vi.fn().mockResolvedValue(page(null, 2)))).rejects.toThrow("row count");
    await expect(collectAuditExport("json", vi.fn().mockResolvedValue(page("same")))).rejects.toThrow("did not advance");
    const changed = vi.fn().mockResolvedValueOnce(page("next")).mockResolvedValueOnce({ ...page(null), snapshot: "different" });
    await expect(collectAuditExport("json", changed)).rejects.toThrow("incomplete");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("unavailable", { status: 503 })));
    await expect(collectAuditExport("json", vi.fn().mockResolvedValue(page(null)))).rejects.toThrow("download failed");
  });
});
