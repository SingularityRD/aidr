/**
 * Regression tests for the managed-mode disarm (AIDR-015 completion).
 *
 * `mode: "managed"` is both the commercial default and a value operators set
 * explicitly. Before this fix, the managed gate's hard `disabled()` returns ran
 * unconditionally, and they can NEVER be satisfied by an installation that has
 * not been enrolled - the installation id file is created *during* enrollment,
 * and a signed entitlement only exists after a successful control-plane sync.
 * The result was that setting `mode: "managed"` disarmed the entire product:
 *
 *   {"mode":"managed"}                          -> `rm -rf /` ALLOWED
 *   {"mode":"managed","auth":{"api_key":""}}    -> `rm -rf /` ALLOWED
 *   {"mode":"managed","auth":{"api_key":"fake"}}-> `rm -rf /` ALLOWED
 *
 * The last case is the worst: an operator who mistypes their api_key loses all
 * protection, because a token was present but the control plane never validated
 * it, so the signed-entitlement gate fired and returned an inert verdict.
 *
 * The rule these tests pin down: only a *validated* credential may disarm local
 * detection. No credentials, or credentials the control plane never accepted,
 * must still enforce locally.
 */

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { evaluateToolCall, extractFromBash } from "../index.js";

let home: string;
let previousHome: string | undefined;
let previousUserProfile: string | undefined;
let threatsDir: string;
let allowlistsDir: string;

const DESTRUCTIVE = "rm -rf /";
const BENIGN = "ls -la";

function request(command: string) {
	return {
		sessionId: "s-managed-disarm",
		toolName: "Bash",
		toolInput: { command },
		artifacts: extractFromBash(command),
	};
}

async function writeConfig(body: unknown) {
	await mkdir(join(home, ".singularity-aidr"), { recursive: true });
	await writeFile(join(home, ".singularity-aidr", "config.json"), JSON.stringify(body), "utf8");
}

function context() {
	return {
		configPath: join(home, ".singularity-aidr", "config.json"),
		threatsDir,
		allowlistsDir,
	};
}

beforeEach(async () => {
	home = await mkdtemp(join(tmpdir(), "aidr-managed-disarm-"));
	previousHome = process.env.HOME;
	previousUserProfile = process.env.USERPROFILE;
	process.env.HOME = home;
	process.env.USERPROFILE = home;

	const res = resolve(
		dirname(fileURLToPath(import.meta.url)),
		"..",
		"..",
		"..",
		"claude-code",
		"resources",
	);
	threatsDir = join(res, "threats");
	allowlistsDir = join(res, "allowlists");
});

afterEach(async () => {
	if (previousHome === undefined) delete process.env.HOME;
	else process.env.HOME = previousHome;
	if (previousUserProfile === undefined) delete process.env.USERPROFILE;
	else process.env.USERPROFILE = previousUserProfile;
	await rm(home, { recursive: true, force: true });
});

describe("managed mode never disarms local detection while un-enrolled", () => {
	// NEVER ENROLLED: no credential of any kind. None of the managed-only hard
	// gates can be satisfied by such an installation, so they must not run and
	// local detection must proceed normally.
	const NEVER_ENROLLED: Array<[string, unknown]> = [
		["managed with no auth block", { mode: "managed" }],
		["managed with an empty api_key", { mode: "managed", auth: { api_key: "" } }],
		[
			"managed with signed entitlements required",
			{ mode: "managed", licensing: { require_signed_entitlements: true } },
		],
		[
			"managed with the control plane disabled",
			{ mode: "managed", control_plane: { enabled: false } },
		],
	];

	for (const [label, config] of NEVER_ENROLLED) {
		it(`still denies a destructive command: ${label}`, async () => {
			await writeConfig(config);
			const verdict = await evaluateToolCall(request(DESTRUCTIVE), context());

			expect(verdict.decision).not.toBe("allow");
			expect(verdict.decision).toBe("deny");
			// A real detection reason, not a licensing/mode reason.
			expect(verdict.reasons.join(" ")).not.toContain("disabled");
			expect(verdict.source).toBe("heuristic");
		});

		it(`still allows a benign command: ${label}`, async () => {
			await writeConfig(config);
			const verdict = await evaluateToolCall(request(BENIGN), context());

			expect(verdict.decision).toBe("allow");
		});
	}

	// CREDENTIAL PRESENT BUT NOT VALIDATED. Validation needs a reachable control
	// plane, so a credential-plus-disabled-control-plane is a misconfigured
	// *enrolled* install: it reaches the licensing gate and fails closed with `ask`
	// before local detection runs. The rule pinned here is only that it must never
	// become a silent `allow` - which is exactly what the old code returned.
	const UNVALIDATED_CREDENTIAL: Array<[string, unknown]> = [
		["managed with a bogus api_key", { mode: "managed", auth: { api_key: "not-a-real-key" } }],
		[
			"managed with a bogus enrollment token",
			{ mode: "managed", auth: { enrollment_token: "bogus" } },
		],
	];

	for (const [label, config] of UNVALIDATED_CREDENTIAL) {
		it(`never silently allows a destructive command: ${label}`, async () => {
			await writeConfig(config);
			const verdict = await evaluateToolCall(request(DESTRUCTIVE), context());

			// Never a clean allow. The exact verdict depends on whether the licensing
			// gate fires (ask, needs a human) or local detection ran (deny); both stop
			// the call, and neither is a silent pass.
			expect(verdict.decision).not.toBe("allow");
		});

		it(`does not report a destructive command as clean: ${label}`, async () => {
			await writeConfig(config);
			const verdict = await evaluateToolCall(request(DESTRUCTIVE), context());

			expect(verdict.category).not.toBe("none");
			expect(verdict.reasons.length).toBeGreaterThan(0);
		});
	}

	it("fails closed with an explanatory ask when an enrolled commercial install cannot reach its control plane", async () => {
		// Documented, deliberate behaviour: the licensing gate is a commercial control,
		// so it is allowed to stop work - but it must say why, and it must not be a
		// silent pass. It is NOT local-only enforcement; the reason below is the
		// evidence, and that distinction is exactly what the old code hid.
		const previous = process.env.AIDR_COMMERCIAL;
		process.env.AIDR_COMMERCIAL = "1";
		try {
			await writeConfig({
				mode: "managed",
				control_plane: { enabled: false },
				auth: { api_key: "fake" },
			});
			const verdict = await evaluateToolCall(request(BENIGN), context());

			expect(verdict.decision).toBe("ask");
			expect(verdict.reasons.join(" ")).toContain("control_plane.enabled=false");
		} finally {
			if (previous === undefined) delete process.env.AIDR_COMMERCIAL;
			else process.env.AIDR_COMMERCIAL = previous;
		}
	});

	it("never returns a clean allow for that configuration in the default build either", async () => {
		// The default (non-commercial) build reports an inert verdict here rather than
		// `ask`, because `disabled()` only escalates to `ask` for commercial builds.
		// That is a real limitation of this configuration and is recorded in
		// READINESS_BACKLOG.json under AIDR-015 rather than hidden: what this test
		// guarantees is that the verdict is never a clean, unexplained `allow`.
		await writeConfig({
			mode: "managed",
			control_plane: { enabled: false },
			auth: { api_key: "fake" },
		});
		const verdict = await evaluateToolCall(request(BENIGN), context());

		if (verdict.decision === "allow") {
			// If it does allow, it must be labelled as a licensing disable, not as a
			// detection result. A `category: "none"` allow would be indistinguishable
			// from a genuine clean inspection.
			expect(verdict.source).toBe("managed_disabled");
			expect(verdict.category).toBe("managed_disabled");
			expect(verdict.reasons.join(" ")).toContain("control_plane.enabled=false");
		}
	});

	it("enforces locally with no config file at all", async () => {
		const verdict = await evaluateToolCall(request(DESTRUCTIVE), context());
		expect(verdict.decision).toBe("deny");
	});

	it("does not report the disarm reason for an un-enrolled managed install", async () => {
		// Sanity: the reason string that used to mask the disarm must not appear
		// for an un-enrolled managed install.
		await writeConfig({ mode: "managed" });
		const verdict = await evaluateToolCall(request(DESTRUCTIVE), context());

		expect(verdict.category).not.toBe("managed_disabled");
		expect(verdict.reasons.join(" ")).not.toContain("AIDR disabled");
	});
});
