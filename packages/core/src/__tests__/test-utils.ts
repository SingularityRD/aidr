import { mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { vi } from "vitest";

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
