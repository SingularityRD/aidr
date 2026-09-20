import { existsSync, rmSync } from "node:fs";

const DEFAULT_ATTEMPTS = 5;
const DEFAULT_RETRY_DELAY_MS = 100;
const RETRYABLE_WINDOWS_CODES = new Set(["EPERM", "EBUSY", "ENOTEMPTY"]);

/**
 * Remove a temporary release staging directory without hiding Windows handle
 * races. Every attempt is bounded and the directory is verified absent before
 * returning; callers therefore cannot accidentally proceed with stale files.
 */
export function cleanupDirectory(
	directory,
	{
		platform = process.platform,
		attempts = DEFAULT_ATTEMPTS,
		retryDelayMs = DEFAULT_RETRY_DELAY_MS,
		remove = rmSync,
		exists = existsSync,
		sleep = (milliseconds) => {
			Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
		},
		warn = (message) => console.warn(message),
	} = {},
) {
	const maxAttempts = Math.max(1, Math.floor(attempts));
	let lastError;

	for (let attempt = 1; attempt <= maxAttempts; attempt++) {
		try {
			remove(directory, { recursive: true, force: true, maxRetries: 0 });
		} catch (error) {
			lastError = error;
			const code = error?.code;
			const retryable = platform === "win32" && RETRYABLE_WINDOWS_CODES.has(code);
			if (!retryable || attempt === maxAttempts) break;
			warn(`WARN: temporary release staging cleanup failed (${code}) for ${directory}; retry ${attempt + 1}/${maxAttempts}`);
			sleep(retryDelayMs);
			continue;
		}

		if (!exists(directory)) return;
		lastError = new Error("staging directory still exists after cleanup");
		if (platform !== "win32" || attempt === maxAttempts) break;
		warn(`WARN: temporary release staging directory remains after cleanup for ${directory}; retry ${attempt + 1}/${maxAttempts}`);
		sleep(retryDelayMs);
	}

	const code = lastError?.code ? ` (${lastError.code})` : "";
	throw new Error(
		`Unable to remove temporary release staging directory after ${maxAttempts} attempt(s): ${directory}${code}. `
		+ "Close processes holding files in this directory and remove it manually before retrying; no release candidate was considered clean.",
		{ cause: lastError },
	);
}
