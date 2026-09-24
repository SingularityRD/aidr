export const SCIM_MEMBER_PAGE_SIZE = 200;
export const MAX_SCIM_GROUP_MEMBERS = 1_000;

export class ScimMemberLimitError extends Error {
	constructor(limit = MAX_SCIM_GROUP_MEMBERS) {
		super(`group membership exceeds the limit of ${limit}`);
		this.name = "ScimMemberLimitError";
	}
}

/** Collect every page before using a bounded group member list. */
export async function collectMemberPages<T>(
	fetchPage: (offset: number, limit: number) => Promise<T[]>,
	pageSize = SCIM_MEMBER_PAGE_SIZE,
	maxRows = MAX_SCIM_GROUP_MEMBERS,
): Promise<T[]> {
	if (!Number.isSafeInteger(pageSize) || pageSize < 1 || !Number.isSafeInteger(maxRows) || maxRows < 0) {
		throw new RangeError("SCIM member pagination limits are invalid");
	}
	const rows: T[] = [];
	while (true) {
		const requested = Math.min(pageSize, maxRows - rows.length + 1);
		const page = await fetchPage(rows.length, requested);
		if (page.length > requested) throw new Error("SCIM member page exceeded the requested size");
		if (page.length === 0) return rows;
		rows.push(...page);
		if (rows.length > maxRows) throw new ScimMemberLimitError(maxRows);
	}
}
