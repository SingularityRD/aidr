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

import { generateKeyPairSync } from "node:crypto";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { evaluateToolCall, extractFromBash } from "../index.js";
import { removeTmpDir } from "./test-utils.js";

let home: string;
let previousHome: string | undefined;
let previousUserProfile: string | undefined;
let threatsDir: string;
let allowlistsDir: string;

const DESTRUCTIVE = "rm -rf /";
const BENIGN = "ls -la";
const PUBLIC_KEY_PEM = generateKeyPairSync("ed25519")
	.publicKey.export({
		type: "spki",
		format: "pem",
	})
	.toString();

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
	await removeTmpDir(home);
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
		[
			"managed with a provisioned entitlement trust key but no credentials",
			{
				mode: "managed",
				licensing: {
					require_signed_entitlements: true,
					public_keys_pem: [PUBLIC_KEY_PEM],
					revocations_enabled: false,
				},
			},
		],
		[
			"managed with a provisioned trust key and empty credentials",
			{
				mode: "managed",
				auth: { api_key: "", enrollment_token: "" },
				control_plane: { enabled: false },
				licensing: {
					require_signed_entitlements: true,
					public_keys_pem: [PUBLIC_KEY_PEM],
					revocations_enabled: false,
				},
			},
		],
		[
			"managed with a trust key and enrollment token awaiting exchange",
			{
				mode: "managed",
				auth: { enrollment_token: "not-yet-exchanged" },
				control_plane: { enabled: false },
				licensing: {
					require_signed_entitlements: true,
					public_keys_pem: [PUBLIC_KEY_PEM],
					revocations_enabled: false,
				},
			},
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

	it("enforces locally in a fresh commercial install with provisioned trust keys", async () => {
		const previous = process.env.AIDR_COMMERCIAL;
		process.env.AIDR_COMMERCIAL = "1";
		try {
			await writeConfig({
				mode: "managed",
				licensing: {
					require_signed_entitlements: true,
					public_keys_pem: [PUBLIC_KEY_PEM],
					revocations_enabled: false,
				},
			});
			const destructive = await evaluateToolCall(request(DESTRUCTIVE), context());
			expect(destructive).toMatchObject({ decision: "deny", source: "heuristic" });
			expect(destructive.category).not.toBe("managed_disabled");
			const benign = await evaluateToolCall(request(BENIGN), context());
			expect(benign.decision).toBe("allow");
			expect(benign.category).not.toBe("managed_disabled");
		} finally {
			if (previous === undefined) delete process.env.AIDR_COMMERCIAL;
			else process.env.AIDR_COMMERCIAL = previous;
		}
	});

	it.each(["config", "cache"])(
		"keeps the signed-entitlement refusal when a %s API credential is held",
		async (location) => {
			await writeConfig({
				mode: "managed",
				auth: location === "config" ? { api_key: "held-api-credential" } : {},
				control_plane: { enabled: true },
				licensing: {
					require_signed_entitlements: true,
					public_keys_pem: [PUBLIC_KEY_PEM],
					revocations_enabled: false,
				},
			});
			await writeFile(
				join(home, ".singularity-aidr", "managed.json"),
				JSON.stringify({
					// Isolate the signature gate from prerequisite network/iid checks.
					last_sync_attempt_at: new Date().toISOString(),
					...(location === "cache" ? { api_key: "held-api-credential" } : {}),
				}),
			);
			const verdict = await evaluateToolCall(request(BENIGN), context());
			expect(verdict).toMatchObject({
				category: "managed_disabled",
				source: "managed_disabled",
			});
			expect(verdict.reasons.join(" ")).toContain("missing or invalid server-signed entitlement");
		},
	);

	// CREDENTIAL PRESENT BUT NOT VALIDATED. Validation needs a reachable control
	// plane, so a credential-plus-disabled-control-plane is a misconfigured
	// *enrolled* install: it reaches the licensing gate, which turns the managed
	// features off; local detection still runs and decides. The rule pinned here
	// is that a destructive command must never become a silent `allow`.
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

	it("refuses a plaintext commercial endpoint credential", async () => {
		// A commercial release must not accept an endpoint key from config.json.
		const previous = process.env.AIDR_COMMERCIAL;
		process.env.AIDR_COMMERCIAL = "1";
		try {
			await writeConfig({
				mode: "managed",
				control_plane: { enabled: false },
				auth: { api_key: "fake" },
			});
			const verdict = await evaluateToolCall(request(BENIGN), context());

			expect(verdict.decision).toBe("deny");
			expect(verdict.reasons.length).toBeGreaterThan(0);
		} finally {
			if (previous === undefined) delete process.env.AIDR_COMMERCIAL;
			else process.env.AIDR_COMMERCIAL = previous;
		}
	});

	it("never returns a clean allow for that configuration in the default build either", async () => {
		// A failed licensing gate turns the managed features off and returns the
		// local verdict. For a benign command that is an allow, and this test
		// guarantees it is never a clean, unexplained `allow`.
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
