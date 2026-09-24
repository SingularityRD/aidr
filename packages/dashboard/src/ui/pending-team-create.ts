export interface PendingTeamCreate {
	requestId: string;
	name: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function storageKey(userId: string): string {
	return `aidr:onboarding-team-create:v1:${userId}`;
}

export function readPendingTeamCreate(userId: string, storage: Storage): PendingTeamCreate | null {
	const raw = storage.getItem(storageKey(userId));
	if (raw === null) return null;
	let value: unknown;
	try {
		value = JSON.parse(raw);
	} catch {
		throw new Error(
			"Saved workspace request is unreadable. Creation is paused to avoid a duplicate.",
		);
	}
	if (
		!value ||
		typeof value !== "object" ||
		!("requestId" in value) ||
		!("name" in value) ||
		typeof value.requestId !== "string" ||
		!UUID.test(value.requestId) ||
		typeof value.name !== "string" ||
		value.name.trim().length === 0 ||
		value.name.trim().length > 200
	) {
		throw new Error("Saved workspace request is invalid. Creation is paused to avoid a duplicate.");
	}
	return { requestId: value.requestId, name: value.name };
}

export function savePendingTeamCreate(
	userId: string,
	attempt: PendingTeamCreate,
	storage: Storage,
): void {
	storage.setItem(storageKey(userId), JSON.stringify(attempt));
}

export function clearPendingTeamCreate(userId: string, requestId: string, storage: Storage): void {
	const current = readPendingTeamCreate(userId, storage);
	if (current?.requestId === requestId) storage.removeItem(storageKey(userId));
}
