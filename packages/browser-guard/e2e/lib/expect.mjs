// Assertion and polling helpers. No fixed sleeps: every wait polls a condition
// with a deadline, and "must not happen" checks poll for a bounded window.

export class AssertionError extends Error {
	constructor(message, details) {
		super(message);
		this.name = "AssertionError";
		this.details = details;
	}
}

const POLL_MS = 50;

function delay(ms) {
	return new Promise((resolve) => setTimeout(resolve, Math.min(ms, 500)));
}

/**
 * Polls `probe` until it returns a truthy value, then returns that value.
 * Errors thrown by the probe are retried until the deadline (DOM not ready yet, etc.).
 */
export async function waitFor(
	probe,
	{ timeout = 8000, message = "condition", interval = POLL_MS } = {},
) {
	const deadline = Date.now() + timeout;
	let lastError;
	let lastValue;
	for (;;) {
		try {
			lastValue = await probe();
			if (lastValue) return lastValue;
		} catch (error) {
			lastError = error;
		}
		if (Date.now() >= deadline) {
			const why = lastError ? ` (last error: ${lastError.message ?? lastError})` : "";
			throw new AssertionError(`timed out after ${timeout}ms waiting for ${message}${why}`, {
				lastValue: summarise(lastValue),
			});
		}
		await delay(interval);
	}
}

/** Asserts `probe` stays falsy for the whole window (e.g. "no request was sent"). */
export async function staysFalse(
	probe,
	{ window = 1200, message = "condition", interval = POLL_MS } = {},
) {
	const deadline = Date.now() + window;
	while (Date.now() < deadline) {
		const value = await probe();
		if (value) {
			throw new AssertionError(`expected ${message} not to happen within ${window}ms`, {
				value: summarise(value),
			});
		}
		await delay(interval);
	}
}

function summarise(value) {
	if (value === undefined || value === null) return value;
	const text = typeof value === "string" ? value : JSON.stringify(value);
	return text && text.length > 400 ? `${text.slice(0, 400)}...` : text;
}

/**
 * Collects named checks for one scenario. `check` records and continues so a
 * scenario reports every failed expectation, `must` records and throws.
 */
export class Checks {
	constructor() {
		this.results = [];
	}

	check(name, ok, details) {
		this.results.push({ name, ok: Boolean(ok), ...(ok ? {} : { details: summarise(details) }) });
		return Boolean(ok);
	}

	must(name, ok, details) {
		if (!this.check(name, ok, details)) throw new AssertionError(`${name}`, details);
	}

	contains(name, haystack, needle) {
		const ok =
			typeof haystack === "string" &&
			(needle instanceof RegExp ? needle.test(haystack) : haystack.includes(needle));
		return this.check(name, ok, { expected: String(needle), actual: haystack });
	}

	excludes(name, haystack, needle) {
		const ok =
			typeof haystack === "string" &&
			!(needle instanceof RegExp ? needle.test(haystack) : haystack.includes(needle));
		return this.check(name, ok, { forbidden: String(needle), actual: haystack });
	}

	equal(name, actual, expected) {
		return this.check(name, actual === expected, { expected, actual });
	}

	get failed() {
		return this.results.filter((r) => !r.ok);
	}
}
