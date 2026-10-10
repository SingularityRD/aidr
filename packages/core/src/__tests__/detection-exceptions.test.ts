/**
 * Time-limited, operator-only detection exceptions (catalog item 80).
 *
 * Pins: exact scope (rule id, optional exact artifact, subject), automatic lift
 * at expiry, bounded lifetime, self-defense rules never excepted, operator-key
 * integrity and ledger-backed revocation for local records, Ed25519 binding for
 * managed records, and an audit entry for every use.
 */

import { createHash, sign as cryptoSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	addDetectionException,
	applyDetectionExceptions,
	DETECTION_EXCEPTION_MAX_TTL_MS,
	type DetectionException,
	DetectionExceptionError,
	type DetectionExceptionStoreOptions,
	detectionExceptionArtifactDigest,
	findGitRepository,
	isProtectedRule,
	listDetectionExceptions,
	loadUsableLocalExceptions,
	normalizeRepoRemote,
	parseSignedDetectionExceptions,
	removeDetectionException,
} from "../detection-exceptions.js";
import { evaluateToolCall } from "../evaluator.js";
import {
	clearOperatorApprovalKeyCache,
	type OperatorApprovalStoreOptions,
} from "../operator-approvals.js";
import {
	clearRemoteRuntimePolicyCacheForTests,
	signedDetectionExceptions,
	signedDetectionExceptionsOf,
	syncRemoteRuntimePolicy,
} from "../remote-policy.js";
import { ConfigSchema, type HeuristicMatch, type Threat } from "../types.js";

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse("2026-10-07T12:00:00.000Z");

function threat(id: string, category = "tool"): Threat {
	return {
		id,
		category,
		severity: "high",
		confidence: 0.8,
		action: "require_approval",
		pattern: "x",
		compiledPattern: /x/,
		matchOn: new Set(["command"]),
		title: id,
		expiresAt: null,
		revoked: false,
	} as Threat;
}

function match(id: string, artifact = "chmod 777 ./deploy.sh", category?: string): HeuristicMatch {
	return { threat: threat(id, category), artifact, matchValue: "chmod 777" };
}

function exception(overrides: Partial<DetectionException> = {}): DetectionException {
	return {
		id: "exc-00000001",
		ruleId: "CLT-CMD-011",
		artifactSha256: null,
		subject: { kind: "agent", value: "claude-code" },
		createdAt: new Date(NOW - DAY).toISOString(),
		expiresAt: new Date(NOW + DAY).toISOString(),
		createdBy: "op (interactive)",
		reason: "build script needs it",
		source: "local",
		...overrides,
	};
}

const ctx = { user: "alice", agent: "claude-code", repo: { root: process.cwd() } };

describe("applyDetectionExceptions", () => {
	it("lifts only the excepted rule, for the subject, while unexpired", () => {
		const matches = [match("CLT-CMD-011"), match("CLT-CMD-001")];
		const { kept, applied } = applyDetectionExceptions(matches, [exception()], ctx, NOW);
		expect(kept.map((m) => m.threat.id)).toEqual(["CLT-CMD-001"]);
		expect(applied.map((a) => a.ruleId)).toEqual(["CLT-CMD-011"]);
	});

	it("lifts automatically at expiry and ignores records issued in the future", () => {
		const expired = exception({ expiresAt: new Date(NOW - 1).toISOString() });
		expect(applyDetectionExceptions([match("CLT-CMD-011")], [expired], ctx, NOW).kept).toHaveLength(
			1,
		);
		const future = exception({
			createdAt: new Date(NOW + DAY).toISOString(),
			expiresAt: new Date(NOW + 2 * DAY).toISOString(),
		});
		expect(applyDetectionExceptions([match("CLT-CMD-011")], [future], ctx, NOW).kept).toHaveLength(
			1,
		);
		const tooLong = exception({ expiresAt: new Date(NOW + 40 * DAY).toISOString() });
		expect(applyDetectionExceptions([match("CLT-CMD-011")], [tooLong], ctx, NOW).kept).toHaveLength(
			1,
		);
	});

	it("an artifact-scoped exception covers that exact artifact only", () => {
		const scoped = exception({
			artifactSha256: detectionExceptionArtifactDigest("chmod 777 ./deploy.sh"),
		});
		expect(
			applyDetectionExceptions([match("CLT-CMD-011")], [scoped], ctx, NOW).applied,
		).toHaveLength(1);
		expect(
			applyDetectionExceptions([match("CLT-CMD-011", "chmod 777 /etc")], [scoped], ctx, NOW).kept,
		).toHaveLength(1);
	});

	it("matches the subject exactly: other agents, users and repos are not covered", () => {
		const m = [match("CLT-CMD-011")];
		expect(
			applyDetectionExceptions(m, [exception()], { ...ctx, agent: "cursor" }, NOW).kept,
		).toHaveLength(1);
		const user = exception({ subject: { kind: "user", value: "Alice" } });
		expect(applyDetectionExceptions(m, [user], ctx, NOW).applied).toHaveLength(1);
		expect(applyDetectionExceptions(m, [user], { ...ctx, user: "bob" }, NOW).kept).toHaveLength(1);
		const repo = exception({ subject: { kind: "repo", value: process.cwd() } });
		expect(applyDetectionExceptions(m, [repo], ctx, NOW).applied).toHaveLength(1);
		expect(
			applyDetectionExceptions(m, [repo], { ...ctx, repo: { root: tmpdir() } }, NOW).kept,
		).toHaveLength(1);
		const remote = exception({ subject: { kind: "repo", value: "github.com/acme/app" } });
		const trustedRoot = join(tmpdir(), "aidr-trusted-repos");
		expect(
			applyDetectionExceptions(
				m,
				[remote],
				{
					...ctx,
					repo: { root: join(trustedRoot, "app"), remote: "git@github.com:Acme/app.git" },
					trustedRepoRoots: [trustedRoot],
				},
				NOW,
			).applied,
		).toHaveLength(1);
	});

	it("never trusts a repository remote outside an operator-configured root", () => {
		// The origin URL lives in .git/config, which the agent can rewrite: a
		// remote match alone must not carry an exception into another checkout.
		const m = [match("CLT-CMD-011")];
		const remote = exception({ subject: { kind: "repo", value: "github.com/acme/app" } });
		const forged = { root: join(tmpdir(), "elsewhere"), remote: "https://github.com/acme/app" };
		expect(applyDetectionExceptions(m, [remote], { ...ctx, repo: forged }, NOW).kept).toHaveLength(
			1,
		);
		expect(
			applyDetectionExceptions(
				m,
				[remote],
				{ ...ctx, repo: forged, trustedRepoRoots: [join(tmpdir(), "aidr-trusted-repos")] },
				NOW,
			).kept,
		).toHaveLength(1);
		// A sibling whose name only starts with the trusted root is not inside it.
		expect(
			applyDetectionExceptions(
				m,
				[remote],
				{
					...ctx,
					repo: { ...forged, root: join(tmpdir(), "aidr-trusted-repos-evil") },
					trustedRepoRoots: [join(tmpdir(), "aidr-trusted-repos")],
				},
				NOW,
			).kept,
		).toHaveLength(1);
	});

	it("never lifts a self-defense or canary rule, whatever the record says", () => {
		for (const [id, category] of [
			["CLT-SELF-007", "self_defense"],
			["CLT-SELF-008", "tool"],
			["CLT-CANARY-001", "tool"],
			["CUSTOM-1", "self_defense"],
		] as const) {
			const { kept } = applyDetectionExceptions(
				[match(id, "aidr approve x", category)],
				[exception({ ruleId: id })],
				ctx,
				NOW,
			);
			expect(kept).toHaveLength(1);
		}
		expect(isProtectedRule("clt-self-001")).toBe(true);
	});

	it("normalizes repository remotes", () => {
		expect(normalizeRepoRemote("https://github.com/Acme/App.git")).toBe("github.com/acme/app");
		expect(normalizeRepoRemote("git@github.com:acme/app.git")).toBe("github.com/acme/app");
		expect(normalizeRepoRemote("ssh://git@github.com:22/acme/app")).toBe("github.com/acme/app");
	});

	it("keeps a bracketed IPv6 host intact and drops only its port", () => {
		for (const remote of [
			"ssh://git@[2001:DB8::1]/acme/app.git",
			"ssh://git@[2001:db8::1]:22/acme/app",
			"git@[2001:db8::1]:acme/app.git",
			"https://[2001:db8::1]:8443/acme/app/",
		]) {
			expect(normalizeRepoRemote(remote), remote).toBe("[2001:db8::1]/acme/app");
		}
		expect(normalizeRepoRemote("ssh://git@[2001:db8::2]/acme/app")).not.toBe(
			normalizeRepoRemote("ssh://git@[2001:db8::1]/acme/app"),
		);
	});
});

// ── Local store ───────────────────────────────────────────────────────

let dir: string;
let approvals: OperatorApprovalStoreOptions;
let store: DetectionExceptionStoreOptions;
let ledger: string | null;

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "aidr-detection-exceptions-"));
	clearOperatorApprovalKeyCache();
	const key = randomBytes(32);
	ledger = null;
	approvals = {
		path: join(dir, "approvals.json"),
		keyProvider: {
			load: () => ({ key, location: "os-vault", store: "macos-keychain" }),
			anchor: () => ({
				location: "os-vault",
				read: () => ledger,
				write: (value) => {
					ledger = value;
				},
			}),
		},
	};
	store = { path: join(dir, "detection-exceptions.json"), approvals, now: () => NOW };
});

afterEach(() => {
	clearOperatorApprovalKeyCache();
	rmSync(dir, { recursive: true, force: true });
});

const ADD = {
	ruleId: "CLT-CMD-011",
	subject: { kind: "agent" as const, value: "claude-code" },
	ttlMs: 7 * DAY,
	reason: "deploy script",
	createdBy: "op (interactive)",
};

describe("local exception store", () => {
	it("adds a signed exception the evaluator can use, and lists it", async () => {
		const created = await addDetectionException(ADD, store);
		expect(created.expiresAt).toBe(new Date(NOW + 7 * DAY).toISOString());
		const listed = await listDetectionExceptions(store);
		expect(listed).toHaveLength(1);
		expect(listed[0]?.verified).toBe(true);
		const usable = await loadUsableLocalExceptions(new Set(["CLT-CMD-011"]), store);
		expect(usable.map((e) => e.id)).toEqual([created.id]);
	});

	it("stores only a digest of an exact artifact", async () => {
		await addDetectionException({ ...ADD, artifact: "chmod 777 ./secret-name.sh" }, store);
		const raw = readFileSync(store.path as string, "utf8");
		expect(raw).not.toContain("secret-name");
		expect(raw).toContain(detectionExceptionArtifactDigest("chmod 777 ./secret-name.sh"));
	});

	it("requires a bounded expiry (max 30 days) and a reason", async () => {
		await expect(
			addDetectionException({ ...ADD, ttlMs: DETECTION_EXCEPTION_MAX_TTL_MS + 1 }, store),
		).rejects.toMatchObject({ code: "invalid_ttl" });
		await expect(addDetectionException({ ...ADD, ttlMs: 0 }, store)).rejects.toMatchObject({
			code: "invalid_ttl",
		});
		await expect(addDetectionException({ ...ADD, reason: "  " }, store)).rejects.toMatchObject({
			code: "invalid_reason",
		});
	});

	it("refuses self-defense rules", async () => {
		for (const ruleId of ["CLT-SELF-007", "CLT-SELF-001", "CLT-CANARY-001"]) {
			const error = await addDetectionException({ ...ADD, ruleId }, store).catch((e) => e);
			expect(error).toBeInstanceOf(DetectionExceptionError);
			expect((error as DetectionExceptionError).code).toBe("protected_rule");
		}
	});

	it("is disabled (fail closed) without the operator key", async () => {
		const noVault: DetectionExceptionStoreOptions = {
			...store,
			approvals: { ...approvals, keyProvider: { load: () => null } },
		};
		await expect(addDetectionException(ADD, noVault)).rejects.toMatchObject({
			code: "key_unavailable",
		});
	});

	it("ignores a hand-edited or forged record", async () => {
		await addDetectionException(ADD, store);
		const path = store.path as string;
		const doc = JSON.parse(readFileSync(path, "utf8"));
		doc.exceptions[0].expires_at = new Date(NOW + 29 * DAY).toISOString();
		doc.exceptions.push({ ...doc.exceptions[0], id: "forged-0001", rule_id: "CLT-CMD-001" });
		writeFileSync(path, JSON.stringify(doc));
		expect(await loadUsableLocalExceptions(new Set(["CLT-CMD-011", "CLT-CMD-001"]), store)).toEqual(
			[],
		);
		expect((await listDetectionExceptions(store)).every((e) => !e.verified)).toBe(true);
	});

	it("a removed exception stays revoked even if an old copy of the file is restored", async () => {
		const created = await addDetectionException(ADD, store);
		const backup = readFileSync(store.path as string, "utf8");
		await removeDetectionException(created.id, store);
		expect(await listDetectionExceptions(store)).toEqual([]);
		writeFileSync(store.path as string, backup);
		expect(await loadUsableLocalExceptions(new Set(["CLT-CMD-011"]), store)).toEqual([]);
	});

	it("applies nothing when the revocation ledger is unreadable", async () => {
		await addDetectionException(ADD, store);
		ledger = "{not json";
		expect(await loadUsableLocalExceptions(new Set(["CLT-CMD-011"]), store)).toEqual([]);
	});

	it("drops expired records when listing and writing", async () => {
		await addDetectionException({ ...ADD, ttlMs: 10 * 60 * 1000 }, store);
		const later = { ...store, now: () => NOW + 11 * 60 * 1000 };
		expect(await listDetectionExceptions(later)).toEqual([]);
		expect(await listDetectionExceptions(later, { includeExpired: true })).toHaveLength(1);
		expect(await loadUsableLocalExceptions(new Set(["CLT-CMD-011"]), later)).toEqual([]);
	});
});

// ── Managed (signed policy) ─────────────────────────────────────────────

const signer = generateKeyPairSync("ed25519");
const PUBLIC_PEM = signer.publicKey.export({ type: "spki", format: "pem" }).toString();

function canonical(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
	if (value && typeof value === "object") {
		return `{${Object.entries(value as Record<string, unknown>)
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
			.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`)
			.join(",")}}`;
	}
	return JSON.stringify(value);
}
const sha = (v: unknown) => createHash("sha256").update(canonical(v)).digest("hex");

const WIRE = [
	{
		id: "6f1c1e0e-0000-4000-8000-000000000001",
		rule_id: "CLT-CMD-011",
		artifact_sha256: null,
		subject_kind: "agent",
		subject_value: "0b9f0000-0000-4000-8000-0000000000aa",
		created_at: new Date(NOW - DAY).toISOString(),
		expires_at: new Date(NOW + DAY).toISOString(),
		created_by: "0b9f0000-0000-4000-8000-0000000000bb",
		reason: "approved by security",
	},
];

function signedBody(
	opts: { exceptions?: unknown; bind?: boolean; tamperDigest?: boolean } = {},
): Record<string, unknown> {
	const policy = { command_default: "ask" };
	const exceptions = structuredClone(opts.exceptions ?? WIRE);
	const digest = sha(exceptions);
	const envelope: Record<string, unknown> = {
		schema_version: 1,
		key_id: "k1",
		policy_version: "7",
		policy_sha256: sha(policy),
		sequence: 10,
		issued_at: new Date(NOW - 60_000).toISOString(),
		expires_at: new Date(NOW + 3_600_000).toISOString(),
		tenant_id: "t1",
		...(opts.bind === false ? {} : { detection_exceptions_sha256: digest }),
	};
	return {
		policy_version: "7",
		policy_sha256: envelope.policy_sha256,
		runtime_policy: policy,
		detection_exceptions: exceptions,
		detection_exceptions_sha256: opts.tamperDigest ? "0".repeat(64) : digest,
		policy_signed: {
			alg: "ed25519",
			key_id: "k1",
			sig_b64: cryptoSign(null, Buffer.from(canonical(envelope)), signer.privateKey).toString(
				"base64",
			),
			envelope,
		},
	};
}

const trust = { keys: [PUBLIC_PEM], revoked: new Set<string>() };

describe("signed managed exceptions", () => {
	it("accepts exceptions bound into the verified envelope", () => {
		const exceptions = signedDetectionExceptions(signedBody(), trust, NOW);
		expect(exceptions.map((e) => [e.ruleId, e.source])).toEqual([["CLT-CMD-011", "managed"]]);
	});

	it("carries none without signature trust, without the binding, or with a bad digest", () => {
		expect(signedDetectionExceptions(signedBody(), { keys: [], revoked: new Set() }, NOW)).toEqual(
			[],
		);
		expect(signedDetectionExceptions(signedBody({ bind: false }), trust, NOW)).toEqual([]);
		expect(signedDetectionExceptions(signedBody({ tamperDigest: true }), trust, NOW)).toEqual([]);
		const body = signedBody();
		(body.detection_exceptions as Array<Record<string, unknown>>)[0].rule_id = "CLT-CMD-001";
		expect(signedDetectionExceptions(body, trust, NOW)).toEqual([]);
		expect(signedDetectionExceptions(signedBody(), trust, NOW + 2 * 3_600_000)).toEqual([]);
	});

	it("rejects a list naming a self-defense rule or an over-long window", () => {
		expect(parseSignedDetectionExceptions([{ ...WIRE[0], rule_id: "CLT-SELF-009" }])).toBeNull();
		expect(
			parseSignedDetectionExceptions([
				{ ...WIRE[0], expires_at: new Date(NOW + 31 * DAY).toISOString() },
			]),
		).toBeNull();
		expect(
			signedDetectionExceptions(
				signedBody({ exceptions: [{ ...WIRE[0], rule_id: "CLT-SELF-009" }] }),
				trust,
				NOW,
			),
		).toEqual([]);
	});
});

describe("syncRemoteRuntimePolicy carries signed exceptions", () => {
	const originalFetch = globalThis.fetch;
	afterEach(() => {
		globalThis.fetch = originalFetch;
		clearRemoteRuntimePolicyCacheForTests();
	});

	function config(keys: string[]) {
		return ConfigSchema.parse({
			mode: "local",
			control_plane: {
				enabled: true,
				endpoint: "https://policy.example.test",
				remote_policy_cache_path: join(dir, "policy.json"),
				policy_public_keys_pem: keys,
			},
			licensing: { public_keys_pem: [] },
			logging: { enabled: false },
			cache: { enabled: false },
		});
	}
	const serve = (body: unknown) => {
		globalThis.fetch = vi
			.fn()
			.mockResolvedValue({ ok: true, status: 200, json: async () => body } as Response);
	};

	it("attaches verified exceptions to the merged config, and survives the cache", async () => {
		serve(signedBody());
		const merged = await syncRemoteRuntimePolicy(config([PUBLIC_PEM]), "tok", undefined, NOW);
		expect(signedDetectionExceptionsOf(merged).map((e) => e.ruleId)).toEqual(["CLT-CMD-011"]);
		// Served from the in-memory cache on the next call.
		const again = await syncRemoteRuntimePolicy(config([PUBLIC_PEM]), "tok", undefined, NOW);
		expect(signedDetectionExceptionsOf(again)).toHaveLength(1);
		// And from the persisted cache after a restart.
		clearRemoteRuntimePolicyCacheForTests();
		const persisted = await syncRemoteRuntimePolicy(config([PUBLIC_PEM]), "tok", undefined, NOW);
		expect(signedDetectionExceptionsOf(persisted)).toHaveLength(1);
	});

	it("an unsigned policy never carries exceptions", async () => {
		serve(signedBody());
		const merged = await syncRemoteRuntimePolicy(config([]), "tok", undefined, NOW);
		expect(merged.policy.runtime_defaults.command_action).toBe("require_approval");
		expect(signedDetectionExceptionsOf(merged)).toEqual([]);
	});
});

// ── Evaluator integration ─────────────────────────────────────────────

const THREATS_DIR = join(__dirname, "..", "..", "..", "..", "threats");
const ALLOWLISTS_DIR = join(__dirname, "..", "..", "..", "..", "allowlists");
const COMMAND = "chmod 777 ./deploy.sh";

describe("evaluator applies local exceptions", () => {
	let home: string;
	let saved: { HOME?: string; USERPROFILE?: string; key?: string };

	beforeEach(() => {
		home = mkdtempSync(join(tmpdir(), "aidr-exception-eval-"));
		mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
		saved = {
			HOME: process.env.HOME,
			USERPROFILE: process.env.USERPROFILE,
			key: process.env.AIDR_OPERATOR_APPROVAL_KEY_STORAGE,
		};
		process.env.HOME = home;
		process.env.USERPROFILE = home;
		process.env.AIDR_OPERATOR_APPROVAL_KEY_STORAGE = "file";
		clearOperatorApprovalKeyCache();
	});

	afterEach(() => {
		for (const [name, value] of [
			["HOME", saved.HOME],
			["USERPROFILE", saved.USERPROFILE],
			["AIDR_OPERATOR_APPROVAL_KEY_STORAGE", saved.key],
		] as const) {
			if (value === undefined) delete process.env[name];
			else process.env[name] = value;
		}
		clearOperatorApprovalKeyCache();
		rmSync(home, { recursive: true, force: true });
	});

	function configPath(logging: boolean): string {
		const path = join(home, ".singularity-aidr", "config.json");
		writeFileSync(
			path,
			JSON.stringify({
				url_check: { enabled: false },
				package_check: { enabled: false },
				operator_approvals: { key_storage: "file" },
				logging: { enabled: logging },
			}),
		);
		return path;
	}

	async function evaluate(agent: "claude-code" | "cursor", logging = true) {
		return evaluateToolCall(
			{
				sessionId: "s1",
				toolName: "Bash",
				toolInput: { command: COMMAND },
				artifacts: [{ type: "command", value: COMMAND }],
			},
			{
				threatsDir: THREATS_DIR,
				allowlistsDir: ALLOWLISTS_DIR,
				configPath: configPath(logging),
				agentRuntime: agent,
			},
		);
	}

	it("lifts the excepted rule for the subject only and audits every use", async () => {
		const before = await evaluate("claude-code");
		expect(before.matchedThreatId).toBe("CLT-CMD-011");

		await addDetectionException({ ...ADD, ttlMs: DAY }, { approvals: { keyStorage: "file" } });

		const lifted = await evaluate("claude-code");
		expect(lifted.matchedThreatId).not.toBe("CLT-CMD-011");
		const audit = readFileSync(join(home, ".singularity-aidr", "audit.jsonl"), "utf8")
			.trim()
			.split("\n")
			.map((line) => JSON.parse(line) as Record<string, unknown>)
			.filter((entry) => entry.type === "detection_exception");
		expect(audit).toHaveLength(1);
		expect(audit[0]).toMatchObject({ rule_id: "CLT-CMD-011", exception_source: "local" });
		expect(JSON.stringify(audit[0])).not.toContain("deploy.sh");

		// Another agent is not covered.
		expect((await evaluate("cursor")).matchedThreatId).toBe("CLT-CMD-011");
	});

	it("applies nothing when the audit log is disabled", async () => {
		await addDetectionException({ ...ADD, ttlMs: DAY }, { approvals: { keyStorage: "file" } });
		expect((await evaluate("claude-code", false)).matchedThreatId).toBe("CLT-CMD-011");
	});
});

describe("findGitRepository", () => {
	it("reads an origin URL that contains brackets (IPv6 host)", () => {
		const root = mkdtempSync(join(tmpdir(), "aidr-git-ipv6-"));
		try {
			mkdirSync(join(root, ".git"));
			writeFileSync(
				join(root, ".git", "config"),
				[
					"[core]",
					"\tbare = false",
					'[remote "origin"]',
					"\turl = ssh://git@[2001:db8::1]/org/repo.git",
					"\tfetch = +refs/heads/*:refs/remotes/origin/*",
					'[branch "main"]',
					"\tremote = origin",
					"",
				].join("\n"),
			);
			expect(findGitRepository(root)?.remote).toBe("ssh://git@[2001:db8::1]/org/repo.git");
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});
});
