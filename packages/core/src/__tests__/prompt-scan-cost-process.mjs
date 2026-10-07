/**
 * Times scanPrompt on one large adversarial prompt in a Node process of its own.
 *
 * The parent test transpiles the current prompt-protection source into a
 * scratch directory and passes that module here, so the measurement is of the
 * code under test (never a stale dist/ tree) and carries none of the parent's
 * instrumentation: under `vitest --coverage` the test process counts every
 * executed block for V8 coverage, which is a cost of the test harness, not of
 * the scan.
 *
 * argv: <module path> <JSON case>, where the case is
 *   { head?: string, unit: string, count?: number, tail?: string, targetChars: number }
 * and the prompt is head + unit × count (`{i}` in unit replaced by the repetition
 * index; count defaults to enough repetitions to reach targetChars) + tail.
 * Prints {"length", "full", "default"}: the prompt length and the best of three
 * wall-clock times, in milliseconds, for a full warn-mode scan and a default scan.
 */
import { pathToFileURL } from "node:url";

const [modulePath, caseJson] = process.argv.slice(2);
if (!modulePath || !caseJson) throw new Error("Expected a module path and a JSON case");
const { scanPrompt } = await import(pathToFileURL(modulePath).href);

const { head = "", unit, count, tail = "", targetChars } = JSON.parse(caseJson);
const repetitions = count ?? Math.ceil(targetChars / unit.length);
const body = unit.includes("{i}")
	? Array.from({ length: repetitions }, (_, i) => unit.replaceAll("{i}", String(i))).join("")
	: unit.repeat(repetitions);
const prompt = head + body + tail;

function bestOfThree(run) {
	let best = Number.POSITIVE_INFINITY;
	for (let attempt = 0; attempt < 3; attempt++) {
		const started = performance.now();
		run();
		best = Math.min(best, performance.now() - started);
	}
	return best;
}

const full = bestOfThree(() => scanPrompt(prompt, { secrets: "warn", pii: "warn" }));
const defaults = bestOfThree(() => scanPrompt(prompt));
process.stdout.write(JSON.stringify({ length: prompt.length, full, default: defaults }));
