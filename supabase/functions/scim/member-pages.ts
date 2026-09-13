/** Collect every page before using a group member list for a read-modify-write PATCH. */
export async function collectMemberPages<T>(
	fetchPage: (offset: number, limit: number) => Promise<T[]>,
	pageSize = 200,
): Promise<T[]> {
	const rows: T[] = [];
	while (true) {
		const page = await fetchPage(rows.length, pageSize);
		if (page.length > pageSize) throw new Error("SCIM member page exceeded the requested size");
		if (page.length === 0) return rows;
		rows.push(...page);
	}
}
