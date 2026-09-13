type ExportPage = { ok: boolean; url: string; rows: number; snapshot: string; next_cursor: string | null; complete: boolean };
export async function collectAuditExport(format: "json" | "csv", getPage: (cursor?: string) => Promise<ExportPage>): Promise<Blob> {
  const parts: string[] = [];
  const seen = new Set<string>();
  let cursor: string | undefined, snapshot: string | undefined, bytes = 0, rows = 0;
  for (let number = 0; number < 200; number++) {
    const page = await getPage(cursor);
    if (page?.ok !== true || typeof page.url !== "string" || !Number.isSafeInteger(page.rows) || page.rows < 0 || page.rows > 500 || typeof page.snapshot !== "string" || (snapshot && snapshot !== page.snapshot) || (page.complete !== (page.next_cursor === null))) throw new Error("Export response was incomplete. No file was produced.");
    snapshot = page.snapshot;
    const response = await fetch(page.url, { signal: AbortSignal.timeout(30000), credentials: "omit" });
    if (!response.ok || !response.body) throw new Error("Export download failed. Retry the export.");
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let content = "", pageBytes = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read(); if (done) break;
        pageBytes += value.byteLength; bytes += value.byteLength;
        if (pageBytes > 8 * 1024 * 1024 || bytes > 64 * 1024 * 1024) throw new Error("This export exceeds the browser limit. Use the paginated export API.");
        content += decoder.decode(value, { stream: true });
      }
      content += decoder.decode();
    } finally { await reader.cancel(); reader.releaseLock(); }
    if (format === "json") {
      const data = JSON.parse(content); if (!Array.isArray(data) || data.length !== page.rows) throw new Error("Export row count mismatch. No file was produced.");
      if (data.length) parts.push(JSON.stringify(data).slice(1, -1));
    } else {
      const header = "id,created_at,user_id,action,verdict";
      if (!content.startsWith(header) || (content.length > header.length && !content.startsWith(`${header}\r\n`))) throw new Error("Export column mismatch. No file was produced.");
      if (number === 0) parts.push(header);
      if (content.length > header.length) parts.push(content.slice(header.length + 2));
    }
    rows += page.rows;
    if (page.complete) return new Blob([format === "json" ? `[${parts.join(",")}]` : parts.join("\r\n")], { type: format === "json" ? "application/json" : "text/csv;charset=utf-8" });
    if (!page.rows || typeof page.next_cursor !== "string" || !page.next_cursor || seen.has(page.next_cursor)) throw new Error("Export pagination did not advance. No file was produced.");
    seen.add(page.next_cursor); cursor = page.next_cursor;
  }
  throw new Error(`The browser limit of ${rows} records was reached. Use the paginated export API. No partial file was produced.`);
}
