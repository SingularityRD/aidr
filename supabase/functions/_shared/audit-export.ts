export const AUDIT_EXPORT_COLUMNS = ["id", "created_at", "user_id", "action", "verdict"] as const;
/** Administrative trail (admin_audit_logs): who changed tenant configuration. */
export const ADMIN_AUDIT_EXPORT_COLUMNS = ["id", "created_at", "actor_user_id", "target_user_id", "action", "detail"] as const;

export function serializeAuditExport(
	rows: Record<string, unknown>[],
	format: "csv" | "json",
	columns: readonly string[] = AUDIT_EXPORT_COLUMNS,
): string {
	if (format === "json") return JSON.stringify(rows, null, 2);
	const cell = (value: unknown) => {
		let text = value == null ? "" : typeof value === "object" ? JSON.stringify(value) : String(value);
		if (/^[\s]*[=+@-]/.test(text)) text = `'${text}`;
		return `"${text.replace(/"/g, '""')}"`;
	};
	return [columns.join(","), ...rows.map((row) => columns.map((column) => cell(row[column])).join(","))].join("\r\n");
}
