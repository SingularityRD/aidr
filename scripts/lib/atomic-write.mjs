import { renameSync } from "node:fs";

const sleepSync = (milliseconds) => {
	if (milliseconds <= 0) return;
	Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
};

/**
 * Rename an already-written temporary file into place, tolerating the short
 * sharing-violation window Windows can produce while another process releases
 * the destination. The source is left in place when all attempts fail so the
 * caller can remove it without risking a partial destination write.
 */
export function renameWithRetry(source, destination, options = {}) {
	const attempts = options.attempts ?? 8;
	const delayMs = options.delayMs ?? 25;
	const rename = options.rename ?? renameSync;
	const sleep = options.sleep ?? sleepSync;
	let lastError;
	for (let attempt = 0; attempt < attempts; attempt++) {
		try {
			rename(source, destination);
			return;
		} catch (error) {
			lastError = error;
			if (!['EPERM', 'EACCES', 'EBUSY'].includes(error?.code) || attempt === attempts - 1) throw error;
			sleep(delayMs);
		}
	}
	throw lastError;
}
