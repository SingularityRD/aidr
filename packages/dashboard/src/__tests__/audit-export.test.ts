import { afterEach, describe, expect, it, vi } from "vitest";
import { collectAuditExport } from "../enterprise/audit-export";

afterEach(() => vi.unstubAllGlobals());
const page = async (content: string, next: string | null, rows = 1) => {
	const bytes = new TextEncoder().encode(content);
	const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
	return {
		ok: true,
		url: "https://storage.example.test/export",
		rows,
		bytes: bytes.byteLength,
		sha256: Array.from(digest, (value) => value.toString(16).padStart(2, "0")).join(""),
		snapshot: "2026-09-11T00:00:00Z",
		next_cursor: next,
		complete: next === null,
	};
};
describe("paginated audit download", () => {
	it("combines JSON pages without omitting or duplicating rows", async () => {
		const first = '[{"id":"a"}]';
		const second = '[{"id":"b"}]';
		vi.stubGlobal(
			"fetch",
			vi
				.fn()
				.mockResolvedValueOnce(new Response(first))
				.mockResolvedValueOnce(new Response(second)),
		);
		const get = vi
			.fn()
			.mockResolvedValueOnce(await page(first, "cursor-2"))
			.mockResolvedValueOnce(await page(second, null));
		expect(JSON.parse(await (await collectAuditExport("json", get)).text())).toEqual([
			{ id: "a" },
			{ id: "b" },
		]);
		expect(get).toHaveBeenNthCalledWith(2, "cursor-2");
	});
	it("preserves quoted multiline CSV while removing only repeated headers", async () => {
		const header = "id,created_at,user_id,action,verdict";
		const first = `${header}\r\n"a","","","line\r\nbreak",""`;
		const second = `${header}\r\n"b","","","'=formula",""`;
		vi.stubGlobal(
			"fetch",
			vi
				.fn()
				.mockResolvedValueOnce(new Response(first))
				.mockResolvedValueOnce(new Response(second)),
		);
		const get = vi
			.fn()
			.mockResolvedValueOnce(await page(first, "cursor-2"))
			.mockResolvedValueOnce(await page(second, null));
		const text = await (await collectAuditExport("csv", get)).text();
		expect(text.split(header)).toHaveLength(2);
		expect(text).toContain('"line\r\nbreak"');
		expect(text).toContain("'=formula");
	});
	it("rejects partial downloads, row mismatch, snapshot changes and repeated cursors", async () => {
		const content = '[{"id":"a"}]';
		vi.stubGlobal(
			"fetch",
			vi.fn().mockImplementation(() => Promise.resolve(new Response('[{"id":"a"}]'))),
		);
		await expect(
			collectAuditExport("json", vi.fn().mockResolvedValue(await page(content, null, 2))),
		).rejects.toThrow("row count");
		await expect(
			collectAuditExport("json", vi.fn().mockResolvedValue(await page(content, "same"))),
		).rejects.toThrow("did not advance");
		const changed = vi
			.fn()
			.mockResolvedValueOnce(await page(content, "next"))
			.mockResolvedValueOnce({ ...(await page(content, null)), snapshot: "different" });
		await expect(collectAuditExport("json", changed)).rejects.toThrow("incomplete");
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("unavailable", { status: 503 })));
		await expect(
			collectAuditExport("json", vi.fn().mockResolvedValue(await page(content, null))),
		).rejects.toThrow("download failed");
	});
	it("rejects truncated and same-length tampered CSV pages before producing a file", async () => {
		const complete =
			'id,created_at,user_id,action,verdict\r\n"a","","","allowed",""\r\n"b","","","blocked",""';
		const truncated = 'id,created_at,user_id,action,verdict\r\n"a","","","allowed",""';
		const altered = complete.replace("allowed", "denied!");
		for (const downloaded of [truncated, altered]) {
			vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(downloaded)));
			await expect(
				collectAuditExport("csv", vi.fn().mockResolvedValue(await page(complete, null, 2))),
			).rejects.toThrow("integrity check");
		}
	});
	it("fetches signed pages without referrer, cache reuse, or ambient credentials", async () => {
		const content = '[{"id":"a"}]';
		const fetch = vi.fn().mockResolvedValue(new Response(content));
		vi.stubGlobal("fetch", fetch);
		await collectAuditExport("json", vi.fn().mockResolvedValue(await page(content, null)));
		expect(fetch).toHaveBeenCalledWith(
			new URL("https://storage.example.test/export"),
			expect.objectContaining({
				cache: "no-store",
				credentials: "omit",
				referrerPolicy: "no-referrer",
			}),
		);
	});
	it("refuses non-HTTPS signed links before fetching", async () => {
		const fetch = vi.fn();
		vi.stubGlobal("fetch", fetch);
		const content = '[{"id":"a"}]';
		await expect(
			collectAuditExport("json", async () => ({
				...(await page(content, null)),
				url: "http://storage.example.test/export",
			})),
		).rejects.toThrow("incomplete");
		expect(fetch).not.toHaveBeenCalled();
	});
	it("keeps local Supabase development usable over loopback HTTP", async () => {
		const content = '[{"id":"a"}]';
		const fetch = vi.fn().mockResolvedValue(new Response(content));
		vi.stubGlobal("fetch", fetch);
		await collectAuditExport("json", async () => ({
			...(await page(content, null)),
			url: "http://127.0.0.1:54321/storage/v1/object/sign/test",
		}));
		expect(fetch).toHaveBeenCalledWith(
			new URL("http://127.0.0.1:54321/storage/v1/object/sign/test"),
			expect.any(Object),
		);
	});
});
