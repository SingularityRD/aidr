import { mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export async function makeTmpDir(): Promise<string> {
	const dir = join(tmpdir(), `aidr-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
	await mkdir(dir, { recursive: true });
	return dir;
}

/**
 * Remove a test directory, allowing Windows antivirus/indexer handles time to
 * release files before retrying the recursive delete.
 */
export async function removeTmpDir(dir: string): Promise<void> {
	await rm(dir, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
}
