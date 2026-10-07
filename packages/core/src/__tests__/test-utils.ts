import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { vi } from "vitest";
import { cacheEntryMac, loadOrCreateCacheKey } from "../cache.js";
import type { CachedEntry } from "../types.js";

/**
 * Windows refuses symlink creation without Developer Mode or elevation
 * (`EPERM`). A test that needs a real symlink skips on such a host instead of
 * failing; it still runs wherever symlinks can be created (Linux CI).
 */
export function isSymlinkPermissionError(error: unknown): boolean {
	return process.platform === "win32" && (error as NodeJS.ErrnoException)?.code === "EPERM";
}

const CLEANUP_MAX_RETRIES = 30;
const CLEANUP_INITIAL_DELAY_MS = 100;
const CLEANUP_MAX_DELAY_MS = 1_000;

const realDateNow = Date.now.bind(Date);
let clockOffsetMs = 0;

/**
 * Move `Date.now()` forward by `ms` without waiting. For retry/backoff logic that
 * is gated on the wall clock (e.g. "retry after 1 s"): a real `delay()` makes the
 * test slow and, when the machine is loaded, still races the deadline. Undone by
 * `vi.restoreAllMocks()`; only `Date.now` moves, timers and file mtimes do not.
 */
export function advanceWallClock(ms: number): void {
	if (!vi.isMockFunction(Date.now)) clockOffsetMs = 0;
	clockOffsetMs += ms;
	vi.spyOn(Date, "now").mockImplementation(() => realDateNow() + clockOffsetMs);
}

/**
 * Write a verdict-cache fixture the way the cache itself would: every entry
 * carries a MAC under the installation's cache key (created next to the file).
 * A fixture written as plain JSON is, correctly, ignored by the cache.
 */
export async function writeSignedCacheFixture(
	cachePath: string,
	store: Partial<Record<"urls" | "commands" | "packages", Record<string, CachedEntry> | unknown>>,
): Promise<void> {
	await mkdir(dirname(cachePath), { recursive: true });
	const key = await loadOrCreateCacheKey(dirname(cachePath));
	const signed: Record<string, unknown> = {};
	for (const kind of ["urls", "commands", "packages"] as const) {
		const section = store[kind] ?? {};
		// Malformed sections and entries are kept as they are (tests of rejection).
		if (typeof section !== "object" || section === null) {
			signed[kind] = section;
			continue;
		}
		signed[kind] = Object.fromEntries(
			Object.entries(section as Record<string, unknown>).map(([id, entry]) => [
				id,
				entry && typeof entry === "object"
					? { ...entry, mac: cacheEntryMac(key, kind, id, entry as CachedEntry) }
					: entry,
			]),
		);
	}
	await writeFile(cachePath, JSON.stringify(signed), "utf8");
}

export async function makeTmpDir(): Promise<string> {
	const dir = join(tmpdir(), `aidr-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
	await mkdir(dir, { recursive: true });
	return dir;
}

/**
 * Remove a test directory, allowing Windows antivirus/indexer handles time to
 * release files before retrying the recursive delete. The final error is
 * intentionally propagated so cleanup failures remain fatal.
 */
export async function removeTmpDir(dir: string): Promise<void> {
	let retryDelayMs = CLEANUP_INITIAL_DELAY_MS;
	for (let attempt = 0; ; attempt += 1) {
		try {
			await rm(dir, { recursive: true, force: true });
			return;
		} catch (error) {
			if (attempt >= CLEANUP_MAX_RETRIES) throw error;
			await delay(retryDelayMs);
			retryDelayMs = Math.min(retryDelayMs * 2, CLEANUP_MAX_DELAY_MS);
		}
	}
}
