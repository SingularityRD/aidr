import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll } from "vitest";

/**
 * Per-test-file home directory (Vitest `setupFiles`).
 *
 * The core evaluator keeps state under `~/.singularity-aidr`: the audit log,
 * the verdict cache, toxic-flow session records and runaway-guard session
 * records. A suite that calls `evaluateToolCall` without its own HOME would read
 * and write the developer's real directory, and session-level state (loop
 * counters, chain history, 24 h TTL) would then leak between test files and
 * between runs, turning later runs into false `ask` verdicts. Every test file
 * therefore starts with a fresh, empty HOME. Suites that stub HOME themselves
 * (`vi.stubEnv`, a spawned hook's `env`) still override it.
 *
 * `os.homedir()` reads HOME on POSIX and USERPROFILE on Windows; both are set.
 */
const previous = {
	HOME: process.env.HOME,
	USERPROFILE: process.env.USERPROFILE,
};
const home = mkdtempSync(join(tmpdir(), "aidr-vitest-home-"));
process.env.HOME = home;
process.env.USERPROFILE = home;

// A file whose tests are all skipped runs no hooks and leaves this (empty)
// directory behind in the OS temp directory.
afterAll(() => {
	for (const [name, value] of Object.entries(previous)) {
		if (value === undefined) delete process.env[name];
		else process.env[name] = value;
	}
	rmSync(home, { recursive: true, force: true, maxRetries: 3 });
});
