export function serializeAuditExport(rows: Record<string, unknown>[], format: "csv" | "json"): string {
	if (format === "json") return JSON.stringify(rows, null, 2);
	const columns = ["id", "created_at", "user_id", "action", "verdict"];
	const cell = (value: unknown) => {
		let text = value == null ? "" : typeof value === "object" ? JSON.stringify(value) : String(value);
		if (/^[\s]*[=+@-]/.test(text)) text = `'${text}`;
		return `"${text.replace(/"/g, '""')}"`;
	};
	return [columns.join(","), ...rows.map((row) => columns.map((column) => cell(row[column])).join(","))].join("\r\n");
}
