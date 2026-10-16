/**
 * Native-host acceptance observation tests.
 *
 * Two properties matter and both are easy to get wrong:
 *
 *   1. Outside a gate run the module must be completely inert. Every real user
 *      session runs with none of the gate's variables set, so any file write
 *      here would be a production side effect that no test previously covered.
 *   2. Inside a gate run it must never write the side-effect sentinel. The
 *      sentinel is the evidence that the protected action did not happen; a
 *      connector that created it would forge the result the gate exists to
 *      measure, and the gate would then report a leak that never occurred.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	createHostObservation,
	HOST_OBSERVATION_ENV,
	HOST_OBSERVATION_MARKER,
	recordHostObservation,
} from "../host-observation.js";

const workspaces: string[] = [];

function workspace(): string {
	const dir = mkdtempSync(join(tmpdir(), "aidr-host-observation-"));
	workspaces.push(dir);
	return dir;
}

afterEach(() => {
	for (const dir of workspaces.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("host observation contract", () => {
	it("is inert when the gate's contract is absent", () => {
		expect(createHostObservation({})).toBeNull();
		// An ordinary user session has unrelated environment variables set.
		expect(createHostObservation({ HOME: "/home/dev", PATH: "/usr/bin" })).toBeNull();
	});

	it("treats a partial contract as absent instead of guessing", () => {
		const dir = workspace();
		// A receipt with no nonce cannot be correlated with a case, so writing one
		// would produce a receipt the gate must reject anyway.
		expect(
			createHostObservation({ [HOST_OBSERVATION_ENV.receipt]: join(dir, "receipt") }),
		).toBeNull();
		expect(
			createHostObservation({
				[HOST_OBSERVATION_ENV.receipt]: join(dir, "receipt"),
				[HOST_OBSERVATION_ENV.nonce]: "abc",
			}),
		).toBeNull();
		// A blank value is not a value.
		expect(
			createHostObservation({
				[HOST_OBSERVATION_ENV.receipt]: "   ",
				[HOST_OBSERVATION_ENV.nonce]: "abc",
				[HOST_OBSERVATION_ENV.workspace]: dir,
			}),
		).toBeNull();
	});

	it("refuses receipt paths outside the disposable gate workspace", () => {
		const dir = workspace();
		expect(
			createHostObservation({
				[HOST_OBSERVATION_ENV.receipt]: join(dir, "..", "outside.receipt"),
				[HOST_OBSERVATION_ENV.nonce]: "nonce",
				[HOST_OBSERVATION_ENV.workspace]: dir,
			}),
		).toBeNull();
		expect(
			createHostObservation({
				[HOST_OBSERVATION_ENV.receipt]: "relative.receipt",
				[HOST_OBSERVATION_ENV.nonce]: "nonce",
				[HOST_OBSERVATION_ENV.workspace]: dir,
			}),
		).toBeNull();
	});

	it("records nothing when there is no observation", () => {
		expect(recordHostObservation(null, { connector: "claude-code", event: "PreToolUse" })).toBe(
			false,
		);
	});

	it("writes a nonce-stamped receipt the gate can correlate", () => {
		const dir = workspace();
		const receipt = join(dir, "hook.receipt");
		const observation = createHostObservation({
			[HOST_OBSERVATION_ENV.receipt]: receipt,
			[HOST_OBSERVATION_ENV.nonce]: "case-nonce-123",
			[HOST_OBSERVATION_ENV.workspace]: dir,
		});

		expect(
			recordHostObservation(observation, {
				connector: "claude-code",
				event: "PreToolUse",
				toolName: "Bash",
				decision: "deny",
			}),
		).toBe(true);

		const lines = readFileSync(receipt, "utf8").trim().split("\n");
		expect(lines).toHaveLength(1);
		const record = JSON.parse(lines[0] as string);
		expect(record.marker).toBe(HOST_OBSERVATION_MARKER);
		expect(record.nonce).toBe("case-nonce-123");
		expect(record.connector).toBe("claude-code");
		expect(record.toolName).toBe("Bash");
		expect(record.decision).toBe("deny");
		// The gate matches the receipt content against the interpolated nonce.
		expect(lines[0]).toContain("case-nonce-123");
	});

	it("appends one line per invocation so repeated calls stay distinguishable", () => {
		const dir = workspace();
		const receipt = join(dir, "hook.receipt");
		const observation = createHostObservation({
			[HOST_OBSERVATION_ENV.receipt]: receipt,
			[HOST_OBSERVATION_ENV.nonce]: "nonce",
			[HOST_OBSERVATION_ENV.workspace]: dir,
		});
		recordHostObservation(observation, { connector: "a", event: "PreToolUse" });
		recordHostObservation(observation, { connector: "b", event: "PostToolUse" });
		expect(readFileSync(receipt, "utf8").trim().split("\n")).toHaveLength(2);
	});

	it("omits fields the connector did not observe rather than inventing them", () => {
		const dir = workspace();
		const receipt = join(dir, "hook.receipt");
		const observation = createHostObservation({
			[HOST_OBSERVATION_ENV.receipt]: receipt,
			[HOST_OBSERVATION_ENV.nonce]: "n",
			[HOST_OBSERVATION_ENV.workspace]: dir,
		});
		recordHostObservation(observation, { connector: "codex", event: "PreToolUse" });
		const record = JSON.parse(readFileSync(receipt, "utf8").trim());
		expect(record).not.toHaveProperty("toolName");
		expect(record).not.toHaveProperty("decision");
	});

	it("reports a write failure instead of throwing, and never touches the sentinel", () => {
		const dir = workspace();
		// A receipt path whose parent does not exist cannot be appended to.
		const observation = createHostObservation({
			[HOST_OBSERVATION_ENV.receipt]: join(dir, "missing-dir", "hook.receipt"),
			[HOST_OBSERVATION_ENV.nonce]: "n",
			[HOST_OBSERVATION_ENV.workspace]: dir,
		});
		expect(() =>
			recordHostObservation(observation, { connector: "c", event: "PreToolUse" }),
		).not.toThrow();
		expect(recordHostObservation(observation, { connector: "c", event: "PreToolUse" })).toBe(false);
	});

	it("never creates the side-effect sentinel", () => {
		const dir = workspace();
		const receipt = join(dir, "hook.receipt");
		const sentinel = join(dir, "side-effect.marker");
		// A hostile-looking environment: the sentinel path is present in the
		// environment the gate injects, but this module must not read or write it.
		const observation = createHostObservation({
			[HOST_OBSERVATION_ENV.receipt]: receipt,
			[HOST_OBSERVATION_ENV.nonce]: "n",
			[HOST_OBSERVATION_ENV.workspace]: dir,
			AIDR_NATIVE_TEST_SENTINEL: sentinel,
		});
		writeFileSync(join(dir, "unrelated.txt"), "x");
		recordHostObservation(observation, { connector: "c", event: "PreToolUse" });

		// The sentinel must still be absent: only the host's own action may create it.
		expect(() => readFileSync(sentinel, "utf8")).toThrow();
		expect(Object.values(HOST_OBSERVATION_ENV)).not.toContain("AIDR_NATIVE_TEST_SENTINEL");
	});
});
