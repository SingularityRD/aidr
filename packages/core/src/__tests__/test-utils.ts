import { mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const CLEANUP_MAX_RETRIES = 30;
const CLEANUP_INITIAL_DELAY_MS = 100;
const CLEANUP_MAX_DELAY_MS = 1_000;

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
