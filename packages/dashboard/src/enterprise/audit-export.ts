type ExportPage = {
	ok: boolean;
	url: string;
	rows: number;
	bytes: number;
	sha256: string;
	snapshot: string;
	next_cursor: string | null;
	complete: boolean;
};

function toHex(bytes: ArrayBuffer): string {
	return Array.from(new Uint8Array(bytes), (value) => value.toString(16).padStart(2, "0")).join("");
}

/** CSV header of each export trail; must match the server's column list exactly. */
const AUDIT_EXPORT_HEADERS = {
	audit: "id,created_at,user_id,action,verdict",
	admin: "id,created_at,actor_user_id,target_user_id,action,detail",
} as const;
export type AuditExportSource = keyof typeof AUDIT_EXPORT_HEADERS;

export async function collectAuditExport(
	format: "json" | "csv",
	getPage: (cursor?: string) => Promise<ExportPage>,
	source: AuditExportSource = "audit",
): Promise<Blob> {
	const parts: string[] = [];
	const seen = new Set<string>();
	let cursor: string | undefined,
		snapshot: string | undefined,
		bytes = 0,
		rows = 0;
	for (let number = 0; number < 200; number++) {
		const page = await getPage(cursor);
		if (
			page?.ok !== true ||
			typeof page.url !== "string" ||
			!Number.isSafeInteger(page.rows) ||
			page.rows < 0 ||
			page.rows > 500 ||
			!Number.isSafeInteger(page.bytes) ||
			page.bytes < 1 ||
			page.bytes > 8 * 1024 * 1024 ||
			typeof page.sha256 !== "string" ||
			!/^[a-f0-9]{64}$/.test(page.sha256) ||
			typeof page.snapshot !== "string" ||
			(snapshot && snapshot !== page.snapshot) ||
			page.complete !== (page.next_cursor === null)
		)
			throw new Error("Export response was incomplete. No file was produced.");
		snapshot = page.snapshot;
		let downloadUrl: URL;
		try {
			downloadUrl = new URL(page.url);
		} catch {
			throw new Error("Export response was incomplete. No file was produced.");
		}
		const localDevelopmentHost = ["localhost", "127.0.0.1", "[::1]"].includes(downloadUrl.hostname);
		if (
			(downloadUrl.protocol !== "https:" &&
				!(downloadUrl.protocol === "http:" && localDevelopmentHost)) ||
			downloadUrl.username ||
			downloadUrl.password
		)
			throw new Error("Export response was incomplete. No file was produced.");
		const response = await fetch(downloadUrl, {
			signal: AbortSignal.timeout(30000),
			credentials: "omit",
			cache: "no-store",
			referrerPolicy: "no-referrer",
		});
		if (!response.ok || !response.body)
			throw new Error("Export download failed. Retry the export.");
		const reader = response.body.getReader();
		const chunks: Uint8Array[] = [];
		let pageBytes = 0;
		try {
			for (;;) {
				const { done, value } = await reader.read();
				if (done) break;
				pageBytes += value.byteLength;
				bytes += value.byteLength;
				if (pageBytes > 8 * 1024 * 1024 || bytes > 64 * 1024 * 1024)
					throw new Error("This export exceeds the browser limit. Use the paginated export API.");
				chunks.push(value);
			}
		} finally {
			await reader.cancel();
			reader.releaseLock();
		}
		if (pageBytes !== page.bytes)
			throw new Error("Export integrity check failed. No file was produced.");
		const payload = new Uint8Array(pageBytes);
		let offset = 0;
		for (const chunk of chunks) {
			payload.set(chunk, offset);
			offset += chunk.byteLength;
		}
		if (toHex(await crypto.subtle.digest("SHA-256", payload)) !== page.sha256)
			throw new Error("Export integrity check failed. No file was produced.");
		const content = new TextDecoder("utf-8", { fatal: true }).decode(payload);
		if (format === "json") {
			const data = JSON.parse(content);
			if (!Array.isArray(data) || data.length !== page.rows)
				throw new Error("Export row count mismatch. No file was produced.");
			if (data.length) parts.push(JSON.stringify(data).slice(1, -1));
		} else {
			const header = AUDIT_EXPORT_HEADERS[source];
			if (
				!content.startsWith(header) ||
				(content.length > header.length && !content.startsWith(`${header}\r\n`))
			)
				throw new Error("Export column mismatch. No file was produced.");
			if (number === 0) parts.push(header);
			if (content.length > header.length) parts.push(content.slice(header.length + 2));
		}
		rows += page.rows;
		if (page.complete)
			return new Blob([format === "json" ? `[${parts.join(",")}]` : parts.join("\r\n")], {
				type: format === "json" ? "application/json" : "text/csv;charset=utf-8",
			});
		if (
			!page.rows ||
			typeof page.next_cursor !== "string" ||
			!page.next_cursor ||
			seen.has(page.next_cursor)
		)
			throw new Error("Export pagination did not advance. No file was produced.");
		seen.add(page.next_cursor);
		cursor = page.next_cursor;
	}
	throw new Error(
		`The browser limit of ${rows} records was reached. Use the paginated export API. No partial file was produced.`,
	);
}
