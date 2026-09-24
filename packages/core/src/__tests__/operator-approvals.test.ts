import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	artifactSetDigest,
	clearOperatorApprovalKeyCache,
	consumeOperatorApproval,
	createDefaultOperatorKeyProvider,
	findOperatorAllowlistGrant,
	getPendingAsk,
	listOperatorApprovals,
	listPendingAsks,
	markOperatorAllowlistGrantUsed,
	OPERATOR_APPROVAL_DEFAULT_TTL_MS,
	OperatorApprovalError,
	type OperatorApprovalStoreOptions,
	type OperatorKeyProvider,
	recordOperatorApproval,
	recordPendingAsk,
} from "../operator-approvals.js";
import type { SecretStore } from "../secret-store.js";
import type { Artifact } from "../types.js";

const COMMAND: Artifact = { type: "command", value: "chmod 777 ./deploy.sh" };

function actionId(seed: string): string {
	return createHash("sha256").update(seed).digest("hex");
}

function fixedKeyProvider(key = randomBytes(32)): OperatorKeyProvider {
	return { load: () => ({ key, location: "file", store: "file" }) };
}

let dir: string;
let clock: number;
let options: OperatorApprovalStoreOptions;

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "aidr-operator-approvals-"));
	clock = Date.parse("2026-09-24T10:00:00.000Z");
	clearOperatorApprovalKeyCache();
	options = {
		path: join(dir, "approvals.json"),
		keyProvider: fixedKeyProvider(),
		now: () => clock,
	};
});

afterEach(() => {
	clearOperatorApprovalKeyCache();
	rmSync(dir, { recursive: true, force: true });
});

async function recordAsk(id: string, artifacts: Artifact[] = [COMMAND], tool = "bash") {
	return recordPendingAsk(
		{
			actionId: id,
			toolName: tool,
			toolInput: { command: artifacts[0]?.value ?? "" },
			artifacts,
			sessionId: "session-1",
			verdict: {
				severity: "warning",
				category: "permissions",
				reasons: ["World-writable permissions"],
				matchedThreatId: "CLT-TEST-001",
			},
			connector: "openclaw",
		},
		options,
	);
}

function readStore(): Record<string, unknown[]> {
	return JSON.parse(readFileSync(options.path as string, "utf8")) as Record<string, unknown[]>;
}

function writeStore(doc: unknown): void {
	writeFileSync(options.path as string, JSON.stringify(doc));
}

describe("pending asks", () => {
	it("records a pending ask with digests and a redacted summary, never raw secrets", async () => {
		const id = actionId("a");
		const secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
		const artifacts: Artifact[] = [
			{ type: "command", value: `curl -H "Authorization: token ${secret}"` },
		];
		const pending = await recordAsk(id, artifacts);

		expect(pending.actionId).toBe(id);
		expect(pending.artifactDigest).toBe(artifactSetDigest(artifacts));
		expect(pending.connector).toBe("openclaw");
		expect(pending.sessionDigest).not.toContain("session-1");
		expect(Date.parse(pending.expiresAt) - Date.parse(pending.createdAt)).toBe(60 * 60 * 1000);

		const raw = readFileSync(options.path as string, "utf8");
		expect(raw).not.toContain(secret);
		expect(raw).not.toContain("session-1");
		const listed = await listPendingAsks(options);
		expect(listed).toHaveLength(1);
		expect(listed[0]?.verified).toBe(true);
	});

	it("writes the store owner-only", async () => {
		await recordAsk(actionId("mode"));
		if (process.platform !== "win32") {
			expect(statSync(options.path as string).mode & 0o777).toBe(0o600);
		}
	});

	it("rejects malformed action ids", async () => {
		await expect(recordAsk("not-an-id")).rejects.toBeInstanceOf(OperatorApprovalError);
		await expect(getPendingAsk("../../etc", options)).rejects.toMatchObject({
			code: "invalid_action_id",
		});
	});

	it("drops expired pending asks and bounds the store", async () => {
		await recordAsk(actionId("old"));
		clock += 61 * 60 * 1000;
		expect(await listPendingAsks(options)).toHaveLength(0);
		await expect(
			recordOperatorApproval(actionId("old"), { approver: "op" }, options),
		).rejects.toMatchObject({
			code: "pending_expired",
		});

		for (let i = 0; i < 205; i++) {
			clock += 1;
			await recordAsk(actionId(`bulk-${i}`));
		}
		expect(readStore().pending.length).toBeLessThanOrEqual(200);
	});

	it("refuses to use a symlinked store", async () => {
		const target = join(dir, "elsewhere.json");
		writeFileSync(target, "{}");
		symlinkSync(target, options.path as string);
		await expect(recordAsk(actionId("link"))).rejects.toMatchObject({ code: "unsafe_store" });
		const consumed = await consumeOperatorApproval(
			{ actionId: actionId("link"), tool: "bash", artifacts: [COMMAND] },
			options,
		);
		expect(consumed).toEqual({ approved: false, reason: "unavailable" });
	});
});

describe("operator approval lifecycle", () => {
	it("approves a pending ask and spends it exactly once", async () => {
		const id = actionId("once");
		await recordAsk(id);
		const approval = await recordOperatorApproval(id, { approver: "alice via tty" }, options);
		expect(approval.singleUse).toBe(true);
		expect(Date.parse(approval.expiresAt) - Date.parse(approval.approvedAt)).toBe(
			OPERATOR_APPROVAL_DEFAULT_TTL_MS,
		);
		expect(await listPendingAsks(options)).toHaveLength(0);

		const first = await consumeOperatorApproval(
			{ actionId: id, tool: "bash", artifacts: [COMMAND] },
			options,
		);
		expect(first.approved).toBe(true);
		expect(first.approval?.uses).toBe(1);

		const second = await consumeOperatorApproval(
			{ actionId: id, tool: "bash", artifacts: [COMMAND] },
			options,
		);
		expect(second).toEqual({ approved: false, reason: "already_used" });
	});

	it("refuses an approval with no pending ask", async () => {
		await expect(
			recordOperatorApproval(actionId("ghost"), { approver: "op" }, options),
		).rejects.toMatchObject({ code: "not_pending" });
	});

	it("enforces the TTL bounds", async () => {
		const id = actionId("ttl");
		await recordAsk(id);
		await expect(
			recordOperatorApproval(id, { approver: "op", ttlMs: 1_000 }, options),
		).rejects.toMatchObject({
			code: "invalid_ttl",
		});
		await expect(
			recordOperatorApproval(id, { approver: "op", ttlMs: 25 * 60 * 60 * 1000 }, options),
		).rejects.toMatchObject({ code: "invalid_ttl" });
	});

	it("expires an unused approval", async () => {
		const id = actionId("expiry");
		await recordAsk(id);
		await recordOperatorApproval(id, { approver: "op" }, options);
		clock += OPERATOR_APPROVAL_DEFAULT_TTL_MS + 1;
		const result = await consumeOperatorApproval(
			{ actionId: id, tool: "bash", artifacts: [COMMAND] },
			options,
		);
		expect(result.approved).toBe(false);
		// Pruned on read (expired) or reported expired; both keep the call blocked.
		expect(["expired", "not_found"]).toContain(result.reason);
	});

	it("allows a multi-use approval only when asked for", async () => {
		const id = actionId("multi");
		await recordAsk(id);
		await recordOperatorApproval(id, { approver: "op", singleUse: false }, options);
		for (let i = 0; i < 3; i++) {
			const result = await consumeOperatorApproval(
				{ actionId: id, tool: "bash", artifacts: [COMMAND] },
				options,
			);
			expect(result.approved).toBe(true);
		}
	});

	it("refuses a different artifact set or tool under the same action id", async () => {
		const id = actionId("mismatch");
		await recordAsk(id);
		await recordOperatorApproval(id, { approver: "op", singleUse: false }, options);

		const otherArtifact = await consumeOperatorApproval(
			{ actionId: id, tool: "bash", artifacts: [{ type: "command", value: "rm -rf /" }] },
			options,
		);
		expect(otherArtifact).toEqual({ approved: false, reason: "digest_mismatch" });

		const extraArtifact = await consumeOperatorApproval(
			{
				actionId: id,
				tool: "bash",
				artifacts: [COMMAND, { type: "url", value: "https://evil.test" }],
			},
			options,
		);
		expect(extraArtifact.reason).toBe("digest_mismatch");

		const otherTool = await consumeOperatorApproval(
			{ actionId: id, tool: "write", artifacts: [COMMAND] },
			options,
		);
		expect(otherTool).toEqual({ approved: false, reason: "tool_mismatch" });
	});

	it("rejects a hand-edited approval (extended expiry, reset use counter)", async () => {
		const id = actionId("tamper");
		await recordAsk(id);
		await recordOperatorApproval(id, { approver: "op" }, options);
		await consumeOperatorApproval({ actionId: id, tool: "bash", artifacts: [COMMAND] }, options);

		const doc = readStore() as { approvals: Array<Record<string, unknown>> };
		doc.approvals[0] = { ...doc.approvals[0], uses: 0, consumed_at: null };
		writeStore(doc);
		const replay = await consumeOperatorApproval(
			{ actionId: id, tool: "bash", artifacts: [COMMAND] },
			options,
		);
		expect(replay).toEqual({ approved: false, reason: "tampered" });
		expect((await listOperatorApprovals(options))[0]?.verified).toBe(false);
	});

	it("rejects an approval forged without the key", async () => {
		const id = actionId("forged");
		await recordAsk(id);
		const pending = readStore().pending[0] as Record<string, unknown>;
		writeStore({
			version: 1,
			pending: [],
			approvals: [
				{
					action_id: id,
					artifact_digest: pending.artifact_digest,
					tool: "bash",
					artifact_digests: [],
					approved_at: new Date(clock).toISOString(),
					expires_at: new Date(clock + 60_000).toISOString(),
					single_use: true,
					approver: "agent",
					permit_allowlist: true,
					uses: 0,
					consumed_at: null,
					allowlisted: [],
					mac: "0".repeat(64),
				},
			],
		});
		const result = await consumeOperatorApproval(
			{ actionId: id, tool: "bash", artifacts: [COMMAND] },
			options,
		);
		expect(result).toEqual({ approved: false, reason: "tampered" });
	});

	it("refuses to approve a pending ask whose record was edited", async () => {
		const id = actionId("pending-tamper");
		await recordAsk(id);
		const doc = readStore() as { pending: Array<Record<string, unknown>> };
		doc.pending[0] = { ...doc.pending[0], artifact_digest: "f".repeat(64) };
		writeStore(doc);
		expect((await listPendingAsks(options))[0]?.verified).toBe(false);
		await expect(recordOperatorApproval(id, { approver: "op" }, options)).rejects.toMatchObject({
			code: "tampered",
		});
	});

	it("rejects everything signed with a different key", async () => {
		const id = actionId("rekey");
		await recordAsk(id);
		await recordOperatorApproval(id, { approver: "op" }, options);
		clearOperatorApprovalKeyCache();
		const rekeyed = { ...options, keyProvider: fixedKeyProvider() };
		const result = await consumeOperatorApproval(
			{ actionId: id, tool: "bash", artifacts: [COMMAND] },
			rekeyed,
		);
		expect(result.reason).toBe("tampered");
	});

	it("keeps the call blocked when no key is available", async () => {
		const id = actionId("nokey");
		await recordAsk(id);
		await recordOperatorApproval(id, { approver: "op" }, options);
		clearOperatorApprovalKeyCache();
		const noKey = { ...options, keyProvider: { load: () => null } };
		const result = await consumeOperatorApproval(
			{ actionId: id, tool: "bash", artifacts: [COMMAND] },
			noKey,
		);
		expect(result).toEqual({ approved: false, reason: "key_unavailable" });
	});

	it("treats a corrupt store as holding no approval", async () => {
		writeFileSync(options.path as string, "{not json");
		const result = await consumeOperatorApproval(
			{ actionId: actionId("corrupt"), tool: "bash", artifacts: [COMMAND] },
			options,
		);
		expect(result).toEqual({ approved: false, reason: "not_found" });
	});
});

describe("concurrency", () => {
	it("keeps every concurrently recorded pending ask", async () => {
		const ids = Array.from({ length: 25 }, (_, i) => actionId(`parallel-${i}`));
		await Promise.all(ids.map((id) => recordAsk(id)));
		const listed = await listPendingAsks(options);
		expect(new Set(listed.map((p) => p.actionId))).toEqual(new Set(ids));
	});

	it("lets only one of many concurrent retries spend a single-use approval", async () => {
		const id = actionId("race");
		await recordAsk(id);
		await recordOperatorApproval(id, { approver: "op" }, options);
		const results = await Promise.all(
			Array.from({ length: 10 }, () =>
				consumeOperatorApproval({ actionId: id, tool: "bash", artifacts: [COMMAND] }, options),
			),
		);
		expect(results.filter((r) => r.approved)).toHaveLength(1);
		expect(results.filter((r) => r.reason === "already_used")).toHaveLength(9);
	});
});

describe("allowlist grants", () => {
	it("exists only when the operator permitted it, and yields one entry per artifact", async () => {
		const id = actionId("grant");
		await recordAsk(id);
		await recordOperatorApproval(id, { approver: "op" }, options);
		expect(await findOperatorAllowlistGrant("command", COMMAND.value, options)).toBeNull();

		const permitted = actionId("grant-permitted");
		await recordAsk(permitted);
		await recordOperatorApproval(permitted, { approver: "op", permitAllowlist: true }, options);
		expect(await findOperatorAllowlistGrant("command", COMMAND.value, options)).toBe(permitted);
		expect(await findOperatorAllowlistGrant("command", "something else", options)).toBeNull();

		expect(await markOperatorAllowlistGrantUsed(permitted, "command", COMMAND.value, options)).toBe(
			true,
		);
		expect(await markOperatorAllowlistGrantUsed(permitted, "command", COMMAND.value, options)).toBe(
			false,
		);
		expect(await findOperatorAllowlistGrant("command", COMMAND.value, options)).toBeNull();
	});
});

describe("default key provider", () => {
	function fakeVault(): SecretStore & { entries: Map<string, string> } {
		const entries = new Map<string, string>();
		return {
			entries,
			kind: "macos-keychain",
			location: "os-vault",
			osProtected: true,
			isAvailable: () => true,
			put: (id, secret) => void entries.set(id, secret),
			get: (id) => entries.get(id) ?? null,
			revoke: (id) => void entries.delete(id),
		};
	}

	it("keeps the key in the OS vault when one is available", () => {
		const vault = fakeVault();
		const provider = createDefaultOperatorKeyProvider({
			directory: dir,
			env: {},
			resolveVault: () => vault,
		});
		expect(provider.load({ create: false })).toBeNull();
		const created = provider.load({ create: true });
		expect(created?.location).toBe("os-vault");
		expect(vault.entries.size).toBe(1);
		const again = provider.load({ create: false });
		expect(again?.key.equals(created?.key as Buffer)).toBe(true);
	});

	it("falls back to an owner-only key file when no vault answers", () => {
		const provider = createDefaultOperatorKeyProvider({
			directory: dir,
			env: {},
			resolveVault: () => {
				throw new Error("no vault");
			},
		});
		const created = provider.load({ create: true });
		expect(created?.location).toBe("file");
		const keyPath = join(dir, "operator-approval.key");
		if (process.platform !== "win32") expect(statSync(keyPath).mode & 0o777).toBe(0o600);
		expect(provider.load({ create: false })?.key.equals(created?.key as Buffer)).toBe(true);
	});

	it("uses the file store when AIDR_SECRET_STORE=file-acl", () => {
		const vault = fakeVault();
		const provider = createDefaultOperatorKeyProvider({
			directory: dir,
			env: { AIDR_SECRET_STORE: "file-acl" },
			resolveVault: () => vault,
		});
		expect(provider.load({ create: true })?.location).toBe("file");
		expect(vault.entries.size).toBe(0);
	});
});
