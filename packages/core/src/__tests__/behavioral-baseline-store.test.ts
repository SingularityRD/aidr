import { mkdtemp, readdir, readFile, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	type BehavioralBaselineObservation,
	type BehavioralBaselineSessionState,
	FileBehavioralBaselineStore,
} from "../behavioral-baseline-store.js";

const NOW = Date.parse("2026-09-12T12:00:00.000Z");
const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;

const tempDirs: string[] = [];

async function temporaryStoreDir(): Promise<string> {
	const dir = await mkdtemp(join(tmpdir(), "aidr-behavioral-store-"));
	tempDirs.push(dir);
	return dir;
}

afterEach(async () => {
	for (const dir of tempDirs.splice(0)) {
		await rm(dir, { recursive: true, force: true });
	}
});

function observation(
	index: number,
	overrides: Partial<BehavioralBaselineObservation> = {},
): BehavioralBaselineObservation {
	return {
		toolName: "Read",
		timestamp: NOW - index,
		riskScore: 10,
		commandToken: `command:sha256:${String(index).padStart(64, "0")}`,
		...overrides,
	};
}

function sessionState(
	observations: BehavioralBaselineObservation[],
	overrides: Partial<BehavioralBaselineSessionState> = {},
): BehavioralBaselineSessionState {
	return {
		baselineSamples: observations.length,
		observations,
		fingerprintCounts:
			observations.length > 0 ? { "event:sha256:fixture": observations.length } : {},
		...overrides,
	};
}

/** Record paths, without depending on the store's internal file naming. */
async function storedRecords(dir: string): Promise<string[]> {
	const entries = await readdir(dir, { recursive: true });
	return entries.filter((entry) => entry.endsWith(".json")).map((entry) => join(dir, entry));
}

async function recordMatching(
	dir: string,
	match: (parsed: Record<string, unknown>) => boolean,
): Promise<string> {
	for (const path of await storedRecords(dir)) {
		const parsed = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
		if (match(parsed)) return path;
	}
	throw new Error("No stored record matched");
}

function recordForSession(dir: string, sessionId: string): Promise<string> {
	return recordMatching(dir, (parsed) => parsed.session_id === sessionId);
}

function tenantDirFor(dir: string, tenantId: string): Promise<string> {
	return recordMatching(dir, (parsed) => parsed.tenant_id === tenantId).then((path) =>
		dirname(path),
	);
}

async function setModifiedAt(path: string, timestamp: number): Promise<void> {
	const when = new Date(timestamp);
	await utimes(path, when, when);
}

describe("FileBehavioralBaselineStore", () => {
	it("round-trips observations and bounds the events it keeps per session", async () => {
		const dir = await temporaryStoreDir();
		const store = new FileBehavioralBaselineStore({
			storeDir: dir,
			now: () => NOW,
			maxEventsPerSession: 3,
		});

		await store.save(
			"tenant-a",
			"session-a",
			sessionState(
				[observation(0), observation(1), observation(2), observation(3), observation(4)],
				{ baselineSamples: 5 },
			),
		);

		const loaded = await store.load("tenant-a", "session-a");
		// The accepted-sample count is preserved, while only the newest three
		// observations are retained, so the record stays bounded.
		expect(loaded?.baselineSamples).toBe(5);
		expect(loaded?.observations.map((entry) => entry.timestamp)).toEqual([
			NOW - 2,
			NOW - 3,
			NOW - 4,
		]);
		expect(loaded?.fingerprintCounts).toEqual({ "event:sha256:fixture": 5 });

		// A scope that was never written is empty, not a neighbouring scope.
		expect(await store.load("tenant-b", "session-a")).toBeNull();
		expect(await store.load("tenant-a", "session-b")).toBeNull();
	});

	it("rejects a record that is not bound to the requested tenant and session", async () => {
		const dir = await temporaryStoreDir();
		const store = new FileBehavioralBaselineStore({ storeDir: dir, now: () => NOW });
		await store.save("tenant-a", "session-a", sessionState([observation(0)]));

		const record = await recordForSession(dir, "session-a");
		const parsed = JSON.parse(await readFile(record, "utf8")) as Record<string, unknown>;

		await writeFile(record, JSON.stringify({ ...parsed, tenant_id: "tenant-b" }));
		expect(await store.load("tenant-a", "session-a")).toBeNull();

		await writeFile(record, JSON.stringify({ ...parsed, session_id: "session-b" }));
		expect(await store.load("tenant-a", "session-a")).toBeNull();

		await writeFile(record, JSON.stringify({ ...parsed, baseline_samples: 1, observations: [] }));
		expect(await store.load("tenant-a", "session-a")).toBeNull();

		await writeFile(record, "{ not json");
		expect(await store.load("tenant-a", "session-a")).toBeNull();

		// The unmodified record still loads, so the rejections above do not pass
		// merely because every load fails.
		await writeFile(record, JSON.stringify(parsed));
		expect((await store.load("tenant-a", "session-a"))?.baselineSamples).toBe(1);
	});

	it("expires a baseline outside the retention window and keeps the newest sessions", async () => {
		const dir = await temporaryStoreDir();
		const store = new FileBehavioralBaselineStore({
			storeDir: dir,
			now: () => NOW,
			maxSessionsPerTenant: 2,
		});

		await store.save("tenant-a", "s1", sessionState([observation(0)]));
		// Backdate before the next write: pruning only runs on save, and an
		// explicit write time makes the retention decision deterministic.
		await setModifiedAt(await recordForSession(dir, "s1"), NOW - 40 * DAY);
		await store.save("tenant-a", "s2", sessionState([observation(1)]));

		// s1 was outside the event window, so it was dropped rather than trusted.
		// Only two sessions exist at this point, so retention — not the quota — is
		// what removed it.
		expect(await store.load("tenant-a", "s1")).toBeNull();
		expect(await store.load("tenant-a", "s2")).not.toBeNull();

		await store.save("tenant-a", "s3", sessionState([observation(2)]));
		await setModifiedAt(await recordForSession(dir, "s2"), NOW - 2 * HOUR);
		await setModifiedAt(await recordForSession(dir, "s3"), NOW - 1 * HOUR);

		// Three live sessions now exceed the per-tenant quota, so the oldest goes.
		await store.save("tenant-a", "s4", sessionState([observation(3)]));

		expect(await store.load("tenant-a", "s2")).toBeNull();
		expect(await store.load("tenant-a", "s3")).not.toBeNull();
		expect(await store.load("tenant-a", "s4")).not.toBeNull();
		expect(await storedRecords(dir)).toHaveLength(2);
	});

	it("bounds the number of tenants kept on disk", async () => {
		const dir = await temporaryStoreDir();
		const store = new FileBehavioralBaselineStore({
			storeDir: dir,
			now: () => NOW,
			maxTenants: 2,
		});

		await store.save("tenant-a", "session-a", sessionState([observation(0)]));
		await setModifiedAt(await tenantDirFor(dir, "tenant-a"), NOW - 3 * HOUR);
		await store.save("tenant-b", "session-a", sessionState([observation(1)]));
		await setModifiedAt(await tenantDirFor(dir, "tenant-b"), NOW - 2 * HOUR);

		// The third tenant exceeds the store bound, so the oldest one goes.
		await store.save("tenant-c", "session-a", sessionState([observation(2)]));
		expect(await store.load("tenant-a", "session-a")).toBeNull();
		expect(await store.load("tenant-b", "session-a")).not.toBeNull();
		await setModifiedAt(await tenantDirFor(dir, "tenant-c"), NOW - 1 * HOUR);

		await store.save("tenant-d", "session-a", sessionState([observation(3)]));

		expect(await store.load("tenant-b", "session-a")).toBeNull();
		expect(await store.load("tenant-c", "session-a")).not.toBeNull();
		expect(await store.load("tenant-d", "session-a")).not.toBeNull();
		expect(await readdir(dir)).toHaveLength(2);
	});
});
