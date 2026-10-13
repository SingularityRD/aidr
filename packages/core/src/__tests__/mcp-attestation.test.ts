import { createHash, createHmac, sign as cryptoSign, generateKeyPairSync } from "node:crypto";
import {
	chmod,
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	stat,
	utimes,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	approveQuarantinedMcpToolset,
	assertPrivateMcpStateDirectory,
	attestMcpToolManifest,
	canonicalMcpToolManifest,
	FileMcpAttestationStore,
	type McpApprovalEntryRejection,
	McpStateDirectoryError,
	type McpToolDefinition,
	type McpToolManifestV1,
	MemoryMcpAttestationStore,
	mcpToolsetHash,
	signMcpToolManifest,
	signMcpToolsetApproval,
	verifyMcpToolsetApproval,
	verifySignedMcpToolManifest,
	writeMcpSignerHealthEvidence,
} from "../mcp-attestation.js";

// Operator approval key: approvals are honoured only when signed by a configured key.
const operatorApproval = generateKeyPairSync("ed25519");
const OPERATOR_APPROVAL_KEY = {
	keyId: "operator-approval-1",
	privateKey: operatorApproval.privateKey,
};
const OPERATOR_APPROVAL_KEYS = {
	"operator-approval-1": operatorApproval.publicKey
		.export({ type: "spki", format: "pem" })
		.toString(),
};

const NOW = new Date("2026-09-12T12:00:00.000Z");
const tempDirs: string[] = [];

afterEach(async () => {
	const { rm } = await import("node:fs/promises");
	await Promise.all(tempDirs.splice(0).map((directory) => rm(directory, { recursive: true })));
});

function keyPair() {
	const pair = generateKeyPairSync("ed25519");
	return {
		privateKey: pair.privateKey,
		publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
	};
}

async function reviewedBindingHash(
	store: MemoryMcpAttestationStore | FileMcpAttestationStore,
	serverId: string,
): Promise<string> {
	const hash = (await store.read(serverId))?.quarantine?.bindingSha256;
	if (!hash) throw new Error("missing reviewed MCP binding");
	return hash;
}

function tool(name = "files.read", description = "Read one workspace file"): McpToolDefinition {
	return {
		name,
		description,
		input_schema: {
			type: "object",
			properties: { path: { type: "string" } },
			required: ["path"],
		},
	};
}

function manifest(sequence: number, tools = [tool()]): McpToolManifestV1 {
	return {
		schema_version: 1,
		server_id: "mcp://customer/filesystem",
		sequence,
		issued_at: "2026-09-12T11:55:00.000Z",
		expires_at: "2026-09-13T11:55:00.000Z",
		tools,
	};
}

function verifier(publicKeyPem: string) {
	return {
		trustedSigners: { "customer-key-1": publicKeyPem },
		expectedServerId: "mcp://customer/filesystem",
		now: NOW,
	};
}

describe("MCP tool-manifest cryptographic verification", () => {
	it("canonicalizes object keys and tool order before signing", () => {
		const one = manifest(1, [tool("z.last"), tool("a.first")]);
		const two = manifest(1, [tool("a.first"), tool("z.last")]);
		expect(canonicalMcpToolManifest(one)).toBe(canonicalMcpToolManifest(two));
		expect(mcpToolsetHash(one.tools)).toBe(mcpToolsetHash(two.tools));
		const specialKeyManifest = manifest(2);
		const firstTool = specialKeyManifest.tools[0];
		if (!firstTool) throw new Error("test manifest tool missing");
		firstTool.input_schema = JSON.parse('{"type":"object","__proto__":{"type":"string"}}');
		expect(canonicalMcpToolManifest(specialKeyManifest)).toContain('"__proto__"');
	});

	it("preserves case-sensitive MCP tool names and accepts underscore identifiers", () => {
		const keys = keyPair();
		const lower = manifest(1, [tool("read_file")]);
		const upper = manifest(1, [tool("READ_FILE")]);
		const both = manifest(1, [tool("read_file"), tool("READ_FILE")]);

		expect(mcpToolsetHash(lower.tools)).not.toBe(mcpToolsetHash(upper.tools));
		expect(
			verifySignedMcpToolManifest(
				signMcpToolManifest({
					manifest: both,
					keyId: "customer-key-1",
					privateKey: keys.privateKey,
				}),
				verifier(keys.publicKeyPem),
			),
		).toMatchObject({ valid: true });
	});

	it("accepts an allowlisted Ed25519 signer", () => {
		const keys = keyPair();
		const signed = signMcpToolManifest({
			manifest: manifest(1),
			keyId: "customer-key-1",
			privateKey: keys.privateKey,
		});
		const result = verifySignedMcpToolManifest(signed, verifier(keys.publicKeyPem));
		expect(result.valid).toBe(true);
	});

	it("binds the signer key id so a revoked alias cannot be substituted", () => {
		const keys = keyPair();
		const signed = signMcpToolManifest({
			manifest: manifest(1),
			keyId: "customer-key-1",
			privateKey: keys.privateKey,
		});
		const config = {
			...verifier(keys.publicKeyPem),
			trustedSigners: {
				"customer-key-1": keys.publicKeyPem,
				"customer-key-2": keys.publicKeyPem,
			},
			revokedKeyIds: new Set(["customer-key-1"]),
		};
		expect(verifySignedMcpToolManifest(signed, config)).toEqual({
			valid: false,
			reason: "revoked_signer",
		});
		expect(verifySignedMcpToolManifest({ ...signed, key_id: "customer-key-2" }, config)).toEqual({
			valid: false,
			reason: "invalid_signature",
		});
	});

	it("rejects legacy V1 signatures; the trusted publisher must re-sign existing manifests", () => {
		const keys = keyPair();
		const oldManifest = manifest(1);
		const legacySignature = cryptoSign(
			null,
			Buffer.from(`AIDR-MCP-TOOL-MANIFEST-V1\n${canonicalMcpToolManifest(oldManifest)}`),
			keys.privateKey,
		).toString("base64");
		expect(
			verifySignedMcpToolManifest(
				{
					key_id: "customer-key-1",
					manifest: oldManifest,
					signature_b64: legacySignature,
				},
				verifier(keys.publicKeyPem),
			),
		).toEqual({ valid: false, reason: "invalid_signature" });
	});

	it("atomically emits the fixed signer readiness evidence contract", async () => {
		const directory = await mkdtemp(join(tmpdir(), "aidr-mcp-signer-health-"));
		tempDirs.push(directory);
		const path = join(directory, "signing.json");
		const evidence = await writeMcpSignerHealthEvidence({
			path,
			lastSuccessAt: new Date("2026-09-12T11:59:00.000Z"),
			activeKeyExpiresAt: new Date("2027-09-12T12:00:00.000Z"),
			now: NOW,
		});
		expect(evidence).toEqual({
			schema_version: 1,
			status: "ok",
			last_success_at: "2026-09-12T11:59:00.000Z",
			active_key_expires_at: "2027-09-12T12:00:00.000Z",
		});
		expect(JSON.parse(await readFile(path, "utf8"))).toEqual(evidence);
		if (process.platform !== "win32") expect((await stat(path)).mode & 0o777).toBe(0o644);
		await expect(
			writeMcpSignerHealthEvidence({
				path,
				lastSuccessAt: NOW,
				activeKeyExpiresAt: new Date("2026-09-12T11:59:59.000Z"),
				now: NOW,
			}),
		).rejects.toThrow("expired");
	});

	it("rejects tampering, unknown signers and revoked signers", () => {
		const keys = keyPair();
		const signed = signMcpToolManifest({
			manifest: manifest(1),
			keyId: "customer-key-1",
			privateKey: keys.privateKey,
		});
		const tampered = structuredClone(signed);
		const firstTool = tampered.manifest.tools[0];
		if (!firstTool) throw new Error("test manifest tool missing");
		firstTool.description = "Read any host file";
		expect(verifySignedMcpToolManifest(tampered, verifier(keys.publicKeyPem))).toEqual({
			valid: false,
			reason: "invalid_signature",
		});
		expect(verifySignedMcpToolManifest(signed, { trustedSigners: {}, now: NOW })).toEqual({
			valid: false,
			reason: "untrusted_signer",
		});
		expect(
			verifySignedMcpToolManifest({ ...signed, unexpected: true }, verifier(keys.publicKeyPem)),
		).toEqual({ valid: false, reason: "invalid_envelope" });
		expect(
			verifySignedMcpToolManifest(signed, {
				...verifier(keys.publicKeyPem),
				revokedKeyIds: new Set(["customer-key-1"]),
			}),
		).toEqual({ valid: false, reason: "revoked_signer" });
	});

	it("rejects expired, future-issued, overlong and cross-server manifests", () => {
		const keys = keyPair();
		const sign = (value: McpToolManifestV1) =>
			signMcpToolManifest({
				manifest: value,
				keyId: "customer-key-1",
				privateKey: keys.privateKey,
			});
		const expired = manifest(1);
		expired.issued_at = "2026-09-10T00:00:00.000Z";
		expired.expires_at = "2026-09-11T00:00:00.000Z";
		expect(verifySignedMcpToolManifest(sign(expired), verifier(keys.publicKeyPem))).toEqual({
			valid: false,
			reason: "expired",
		});

		const future = manifest(1);
		future.issued_at = "2026-09-12T12:06:00.000Z";
		future.expires_at = "2026-09-13T12:06:00.000Z";
		expect(verifySignedMcpToolManifest(sign(future), verifier(keys.publicKeyPem))).toEqual({
			valid: false,
			reason: "not_yet_valid",
		});

		const longLived = manifest(1);
		longLived.expires_at = "2026-10-12T11:55:00.000Z";
		expect(verifySignedMcpToolManifest(sign(longLived), verifier(keys.publicKeyPem))).toEqual({
			valid: false,
			reason: "lifetime_too_long",
		});

		const otherServer = manifest(1);
		otherServer.server_id = "mcp://attacker/server";
		expect(verifySignedMcpToolManifest(sign(otherServer), verifier(keys.publicKeyPem))).toEqual({
			valid: false,
			reason: "unexpected_server",
		});
	});

	it("rejects an invalid verifier clock", () => {
		const keys = keyPair();
		const signed = signMcpToolManifest({
			manifest: manifest(1),
			keyId: "customer-key-1",
			privateKey: keys.privateKey,
		});
		expect(
			verifySignedMcpToolManifest(signed, {
				...verifier(keys.publicKeyPem),
				now: new Date(Number.NaN),
			}),
		).toEqual({ valid: false, reason: "invalid_time_window" });
	});
});

describe("MCP tool drift approval and replay protection", () => {
	it("does not steal an old lock while its recorded process is still alive", async () => {
		const directory = await mkdtemp(join(tmpdir(), "aidr-mcp-live-lock-"));
		tempDirs.push(directory);
		const serverId = "mcp://customer/filesystem";
		const lock = join(
			directory,
			`${createHash("sha256").update(serverId).digest("hex")}.json.lock`,
		);
		await writeFile(lock, JSON.stringify({ pid: process.pid, token: "live-owner" }));
		const stale = new Date(Date.now() - 60_000);
		await utimes(lock, stale, stale);
		const store = new FileMcpAttestationStore(directory, { lockTimeoutMs: 80, staleLockMs: 1 });
		await expect(
			store.transact(serverId, () => ({ state: null, result: "should-not-run" })),
		).rejects.toThrow("timed out acquiring MCP attestation state lock");
		expect(JSON.parse(await readFile(lock, "utf8"))).toMatchObject({
			pid: process.pid,
			token: "live-owner",
		});
	});

	it("quarantines first use, activates only after an out-of-band approval", async () => {
		const keys = keyPair();
		const store = new MemoryMcpAttestationStore();
		const signed = signMcpToolManifest({
			manifest: manifest(1),
			keyId: "customer-key-1",
			privateKey: keys.privateKey,
		});

		const first = await attestMcpToolManifest({
			approvalKeys: OPERATOR_APPROVAL_KEYS,
			candidate: signed,
			verifier: verifier(keys.publicKeyPem),
			store,
		});
		expect(first).toMatchObject({
			status: "quarantined",
			drift: { added: ["files.read"], removed: [], changed: [] },
		});
		if (first.status !== "quarantined") throw new Error("expected quarantine");

		expect(
			await approveQuarantinedMcpToolset({
				approvalKey: OPERATOR_APPROVAL_KEY,
				serverId: signed.manifest.server_id,
				toolsetHash: first.toolsetHash,
				bindingSha256: await reviewedBindingHash(store, signed.manifest.server_id),
				approvedBy: "security@example.com",
				reason: "Change request CR-412",
				store,
				now: NOW,
			}),
		).toEqual({ approved: true, toolsetHash: first.toolsetHash });

		await expect(
			attestMcpToolManifest({
				approvalKeys: OPERATOR_APPROVAL_KEYS,
				candidate: signed,
				verifier: verifier(keys.publicKeyPem),
				store,
			}),
		).resolves.toMatchObject({ status: "accepted" });
	});

	it("requires fresh approval when a different trusted signer presents the same tools", async () => {
		const firstKeys = keyPair();
		const secondKeys = keyPair();
		const store = new MemoryMcpAttestationStore();
		const trust = {
			trustedSigners: {
				"customer-key-1": firstKeys.publicKeyPem,
				"customer-key-2": secondKeys.publicKeyPem,
			},
			expectedServerId: "mcp://customer/filesystem",
			now: NOW,
		};
		const first = await attestMcpToolManifest({
			approvalKeys: OPERATOR_APPROVAL_KEYS,
			candidate: signMcpToolManifest({
				manifest: manifest(1),
				keyId: "customer-key-1",
				privateKey: firstKeys.privateKey,
			}),
			verifier: trust,
			store,
		});
		if (first.status !== "quarantined") throw new Error("expected quarantine");
		await approveQuarantinedMcpToolset({
			approvalKey: OPERATOR_APPROVAL_KEY,
			serverId: "mcp://customer/filesystem",
			toolsetHash: first.toolsetHash,
			bindingSha256: await reviewedBindingHash(store, "mcp://customer/filesystem"),
			approvedBy: "operator",
			reason: "initial signer",
			now: NOW,
			store,
		});
		const replacement = signMcpToolManifest({
			manifest: manifest(2),
			keyId: "customer-key-2",
			privateKey: secondKeys.privateKey,
		});
		await expect(
			attestMcpToolManifest({
				approvalKeys: OPERATOR_APPROVAL_KEYS,
				candidate: replacement,
				verifier: trust,
				store,
			}),
		).resolves.toMatchObject({ status: "quarantined" });
	});

	it("quarantines a changed connection and never accepts an unbound legacy approval", async () => {
		const keys = keyPair();
		const store = new MemoryMcpAttestationStore();
		const signed = signMcpToolManifest({
			manifest: manifest(1),
			keyId: "customer-key-1",
			privateKey: keys.privateKey,
		});
		const first = await attestMcpToolManifest({
			approvalKeys: OPERATOR_APPROVAL_KEYS,
			candidate: signed,
			verifier: verifier(keys.publicKeyPem),
			store,
			connection: ["tenant-a", "https://first.example/mcp"],
		});
		if (first.status !== "quarantined") throw new Error("expected quarantine");
		const reviewedA = await reviewedBindingHash(store, signed.manifest.server_id);
		await approveQuarantinedMcpToolset({
			approvalKey: OPERATOR_APPROVAL_KEY,
			serverId: signed.manifest.server_id,
			toolsetHash: first.toolsetHash,
			bindingSha256: reviewedA,
			approvedBy: "operator",
			reason: "first endpoint",
			now: NOW,
			store,
		});
		await expect(
			attestMcpToolManifest({
				approvalKeys: OPERATOR_APPROVAL_KEYS,
				candidate: signed,
				verifier: verifier(keys.publicKeyPem),
				store,
				connection: ["tenant-a", "https://first.example/mcp"],
			}),
		).resolves.toMatchObject({ status: "accepted" });
		await expect(
			attestMcpToolManifest({
				approvalKeys: OPERATOR_APPROVAL_KEYS,
				candidate: signed,
				verifier: verifier(keys.publicKeyPem),
				store,
				connection: ["tenant-a", "https://other.example/mcp"],
			}),
		).resolves.toMatchObject({ status: "quarantined" });
		await expect(
			approveQuarantinedMcpToolset({
				approvalKey: OPERATOR_APPROVAL_KEY,
				serverId: signed.manifest.server_id,
				toolsetHash: first.toolsetHash,
				bindingSha256: reviewedA,
				approvedBy: "operator",
				reason: "stale review must fail",
				store,
			}),
		).resolves.toEqual({ approved: false, reason: "binding_mismatch" });
		await store.transact(signed.manifest.server_id, (state) => {
			if (!state) throw new Error("missing attestation state");
			state.approvedToolsets = state.approvedToolsets.map(
				({ bindingSha256: _legacy, ...entry }) => entry,
			);
			return { state, result: undefined };
		});
		await expect(
			attestMcpToolManifest({
				approvalKeys: OPERATOR_APPROVAL_KEYS,
				candidate: signed,
				verifier: verifier(keys.publicKeyPem),
				store,
				connection: ["tenant-a", "https://first.example/mcp"],
			}),
		).resolves.toMatchObject({ status: "quarantined" });
	});

	it("accepts a new sequence with unchanged tools and quarantines schema drift", async () => {
		const keys = keyPair();
		const store = new MemoryMcpAttestationStore();
		const firstSigned = signMcpToolManifest({
			manifest: manifest(10),
			keyId: "customer-key-1",
			privateKey: keys.privateKey,
		});
		const first = await attestMcpToolManifest({
			approvalKeys: OPERATOR_APPROVAL_KEYS,
			candidate: firstSigned,
			verifier: verifier(keys.publicKeyPem),
			store,
		});
		if (first.status !== "quarantined") throw new Error("expected quarantine");
		await approveQuarantinedMcpToolset({
			approvalKey: OPERATOR_APPROVAL_KEY,
			serverId: firstSigned.manifest.server_id,
			toolsetHash: first.toolsetHash,
			bindingSha256: await reviewedBindingHash(store, firstSigned.manifest.server_id),
			approvedBy: "operator-1",
			reason: "Initial server enrollment",
			store,
			now: NOW,
		});

		const unchanged = signMcpToolManifest({
			manifest: manifest(11),
			keyId: "customer-key-1",
			privateKey: keys.privateKey,
		});
		await expect(
			attestMcpToolManifest({
				approvalKeys: OPERATOR_APPROVAL_KEYS,
				candidate: unchanged,
				verifier: verifier(keys.publicKeyPem),
				store,
			}),
		).resolves.toMatchObject({
			status: "accepted",
			drift: { added: [], removed: [], changed: [] },
		});

		const changed = signMcpToolManifest({
			manifest: manifest(12, [tool("files.read", "Read every host path")]),
			keyId: "customer-key-1",
			privateKey: keys.privateKey,
		});
		await expect(
			attestMcpToolManifest({
				approvalKeys: OPERATOR_APPROVAL_KEYS,
				candidate: changed,
				verifier: verifier(keys.publicKeyPem),
				store,
			}),
		).resolves.toMatchObject({
			status: "quarantined",
			drift: { added: [], removed: [], changed: ["files.read"] },
		});
	});

	it("rejects lower sequences and same-sequence equivocation", async () => {
		const keys = keyPair();
		const store = new MemoryMcpAttestationStore();
		const signed = (value: McpToolManifestV1) =>
			signMcpToolManifest({
				manifest: value,
				keyId: "customer-key-1",
				privateKey: keys.privateKey,
			});
		await attestMcpToolManifest({
			approvalKeys: OPERATOR_APPROVAL_KEYS,
			candidate: signed(manifest(8)),
			verifier: verifier(keys.publicKeyPem),
			store,
		});
		await expect(
			attestMcpToolManifest({
				approvalKeys: OPERATOR_APPROVAL_KEYS,
				candidate: signed(manifest(7)),
				verifier: verifier(keys.publicKeyPem),
				store,
			}),
		).resolves.toEqual({ status: "rejected", reason: "sequence_replay" });
		await expect(
			attestMcpToolManifest({
				approvalKeys: OPERATOR_APPROVAL_KEYS,
				candidate: signed(manifest(8, [tool("files.write")])),
				verifier: verifier(keys.publicKeyPem),
				store,
			}),
		).resolves.toEqual({ status: "rejected", reason: "sequence_conflict" });
	});

	it("persists approvals and replay state across store instances", async () => {
		const directory = await mkdtemp(join(tmpdir(), "aidr-mcp-attestation-"));
		tempDirs.push(directory);
		const keys = keyPair();
		const signed = signMcpToolManifest({
			manifest: manifest(50),
			keyId: "customer-key-1",
			privateKey: keys.privateKey,
		});
		const firstStore = new FileMcpAttestationStore(directory);
		const first = await attestMcpToolManifest({
			approvalKeys: OPERATOR_APPROVAL_KEYS,
			candidate: signed,
			verifier: verifier(keys.publicKeyPem),
			store: firstStore,
		});
		if (first.status !== "quarantined") throw new Error("expected quarantine");
		await approveQuarantinedMcpToolset({
			approvalKey: OPERATOR_APPROVAL_KEY,
			serverId: signed.manifest.server_id,
			toolsetHash: first.toolsetHash,
			bindingSha256: await reviewedBindingHash(firstStore, signed.manifest.server_id),
			approvedBy: "security-operator",
			reason: "Reviewed tool schemas",
			store: firstStore,
			now: NOW,
		});

		const restartedStore = new FileMcpAttestationStore(directory);
		await expect(
			attestMcpToolManifest({
				approvalKeys: OPERATOR_APPROVAL_KEYS,
				candidate: signed,
				verifier: verifier(keys.publicKeyPem),
				store: restartedStore,
			}),
		).resolves.toMatchObject({ status: "accepted" });

		const replay = signMcpToolManifest({
			manifest: manifest(49),
			keyId: "customer-key-1",
			privateKey: keys.privateKey,
		});
		await expect(
			attestMcpToolManifest({
				approvalKeys: OPERATOR_APPROVAL_KEYS,
				candidate: replay,
				verifier: verifier(keys.publicKeyPem),
				store: restartedStore,
			}),
		).resolves.toEqual({ status: "rejected", reason: "sequence_replay" });
	});

	it("fails closed when persistent state is corrupt", async () => {
		const directory = await mkdtemp(join(tmpdir(), "aidr-mcp-attestation-corrupt-"));
		tempDirs.push(directory);
		const keys = keyPair();
		const signed = signMcpToolManifest({
			manifest: manifest(3),
			keyId: "customer-key-1",
			privateKey: keys.privateKey,
		});
		const stateName = `${(await import("node:crypto"))
			.createHash("sha256")
			.update(signed.manifest.server_id)
			.digest("hex")}.json`;
		await writeFile(join(directory, stateName), "{not-json", "utf8");
		await expect(
			attestMcpToolManifest({
				approvalKeys: OPERATOR_APPROVAL_KEYS,
				candidate: signed,
				verifier: verifier(keys.publicKeyPem),
				store: new FileMcpAttestationStore(directory),
			}),
		).resolves.toEqual({ status: "rejected", reason: "state_unavailable" });
	});
});

describe("operator-signed approvals and sealed attestation state (MSC-1, MSC-14)", () => {
	const SERVER = "mcp://customer/filesystem";

	async function quarantinedFixture(store: MemoryMcpAttestationStore | FileMcpAttestationStore) {
		const keys = keyPair();
		const signed = signMcpToolManifest({
			manifest: manifest(1),
			keyId: "customer-key-1",
			privateKey: keys.privateKey,
		});
		const attest = (
			ignored: McpApprovalEntryRejection[] = [],
			approvalKeys: Record<string, string> = OPERATOR_APPROVAL_KEYS,
		) =>
			attestMcpToolManifest({
				candidate: signed,
				verifier: verifier(keys.publicKeyPem),
				store,
				approvalKeys,
				onApprovalIgnored: (reason) => ignored.push(reason),
			});
		const first = await attest();
		if (first.status !== "quarantined") throw new Error("expected quarantine");
		const quarantine = (await store.read(SERVER))?.quarantine;
		if (!quarantine?.signerKeySha256 || !quarantine.bindingSha256) {
			throw new Error("missing quarantine");
		}
		return {
			attest,
			first,
			quarantine: {
				...quarantine,
				signerKeySha256: quarantine.signerKeySha256,
				bindingSha256: quarantine.bindingSha256,
			},
		};
	}

	/** What a same-user process can do with plain writes: add an approval entry. */
	async function injectApproval(store: MemoryMcpAttestationStore, entry: object): Promise<void> {
		await store.transact(SERVER, (state) => {
			if (!state) throw new Error("missing state");
			state.approvedToolsets.push(entry as (typeof state.approvedToolsets)[number]);
			return { state, result: undefined };
		});
	}

	it("never honours an unsigned approval entry copied from the quarantine record", async () => {
		const store = new MemoryMcpAttestationStore();
		const { attest, quarantine } = await quarantinedFixture(store);
		await injectApproval(store, {
			toolsetHash: quarantine.toolsetHash,
			keyId: quarantine.keyId,
			signerKeySha256: quarantine.signerKeySha256,
			bindingSha256: quarantine.bindingSha256,
			approvedAt: NOW.toISOString(),
			approvedBy: "agent",
			reason: "self",
		});
		const ignored: McpApprovalEntryRejection[] = [];
		await expect(attest(ignored)).resolves.toMatchObject({ status: "quarantined" });
		expect(ignored).toEqual(["unsigned_approval"]);
	});

	it("ignores approvals signed by an unconfigured key, altered after signing, or expired", async () => {
		const store = new MemoryMcpAttestationStore();
		const { attest, quarantine } = await quarantinedFixture(store);
		const base = {
			serverId: SERVER,
			toolsetHash: quarantine.toolsetHash,
			keyId: quarantine.keyId,
			signerKeySha256: quarantine.signerKeySha256,
			bindingSha256: quarantine.bindingSha256,
			approvedBy: "operator",
			reason: "reviewed",
			approvedAt: new Date(NOW.getTime() - 60_000),
			expiresAt: new Date(NOW.getTime() + 60_000),
			approvalKeyId: "operator-approval-1",
		};
		const attacker = generateKeyPairSync("ed25519");
		await injectApproval(
			store,
			signMcpToolsetApproval({ ...base, privateKey: attacker.privateKey }),
		);
		const altered = signMcpToolsetApproval({
			...base,
			privateKey: OPERATOR_APPROVAL_KEY.privateKey,
		});
		await injectApproval(store, { ...altered, reason: "edited after signing" });
		await injectApproval(
			store,
			signMcpToolsetApproval({
				...base,
				approvedAt: new Date(NOW.getTime() - 120_000),
				expiresAt: new Date(NOW.getTime() - 60_000),
				privateKey: OPERATOR_APPROVAL_KEY.privateKey,
			}),
		);
		const ignored: McpApprovalEntryRejection[] = [];
		await expect(attest(ignored)).resolves.toMatchObject({ status: "quarantined" });
		expect(ignored.sort()).toEqual([
			"approval_expired",
			"invalid_approval_signature",
			"invalid_approval_signature",
		]);

		const valid = signMcpToolsetApproval({ ...base, privateKey: OPERATOR_APPROVAL_KEY.privateKey });
		const check = (serverId: string, approvalKeys?: Record<string, string>) =>
			verifyMcpToolsetApproval(valid, { serverId, approvalKeys, now: NOW });
		expect(check(SERVER, OPERATOR_APPROVAL_KEYS)).toBeNull();
		expect(check("mcp://other/server", OPERATOR_APPROVAL_KEYS)).toBe("invalid_approval_signature");
		expect(check(SERVER)).toBe("untrusted_approval_key");
		await injectApproval(store, valid);
		// Honoured only while a configured operator key verifies it.
		await expect(attest([], {})).resolves.toMatchObject({ status: "quarantined" });
		await expect(attest()).resolves.toMatchObject({ status: "accepted" });
	});

	it("refuses to sign with an untrusted key or over a tampered quarantine record", async () => {
		const store = new MemoryMcpAttestationStore();
		const { first, quarantine } = await quarantinedFixture(store);
		const other = generateKeyPairSync("ed25519");
		const request = {
			serverId: SERVER,
			toolsetHash: first.toolsetHash,
			bindingSha256: quarantine.bindingSha256,
			approvedBy: "operator",
			reason: "reviewed",
			store,
			now: NOW,
			approvalKeys: OPERATOR_APPROVAL_KEYS,
		};
		await expect(
			approveQuarantinedMcpToolset({
				...request,
				approvalKey: { keyId: "operator-approval-1", privateKey: other.privateKey },
			}),
		).resolves.toEqual({ approved: false, reason: "approval_key_untrusted" });
		await expect(
			approveQuarantinedMcpToolset({
				...request,
				approvalKey: OPERATOR_APPROVAL_KEY,
				expected: { keyId: "customer-key-2", signerKeySha256: quarantine.signerKeySha256 },
			}),
		).resolves.toEqual({ approved: false, reason: "quarantine_mismatch" });
		// A swapped tool list shown to the reviewer no longer hashes to the toolset.
		await store.transact(SERVER, (state) => {
			if (!state?.quarantine) throw new Error("missing quarantine");
			state.quarantine.tools = [tool("files.read", "Harmless looking description")];
			return { state, result: undefined };
		});
		await expect(
			approveQuarantinedMcpToolset({ ...request, approvalKey: OPERATOR_APPROVAL_KEY }),
		).resolves.toEqual({ approved: false, reason: "quarantine_mismatch" });
	});

	it("seals the state file: an edited, unsealed or re-sealed forged file never approves", async () => {
		const directory = await mkdtemp(join(tmpdir(), "aidr-mcp-attestation-seal-"));
		tempDirs.push(directory);
		const store = new FileMcpAttestationStore(directory);
		const { attest, quarantine } = await quarantinedFixture(store);
		const name = (await readdir(directory)).find((entry) => entry.endsWith(".json"));
		if (!name) throw new Error("missing state file");
		const path = join(directory, name);
		const forged = JSON.parse(await readFile(path, "utf8"));
		forged.approvedToolsets.push({
			toolsetHash: quarantine.toolsetHash,
			keyId: quarantine.keyId,
			signerKeySha256: quarantine.signerKeySha256,
			bindingSha256: quarantine.bindingSha256,
			approvedAt: NOW.toISOString(),
			approvedBy: "agent",
			reason: "self",
		});
		// 1. Plain edit: the seal no longer matches, so the state is refused.
		await writeFile(path, JSON.stringify(forged));
		await expect(attest()).resolves.toEqual({ status: "rejected", reason: "state_unavailable" });
		// 2. Seal stripped: refused as well.
		const { stateMac: _seal, ...unsealed } = forged;
		await writeFile(path, JSON.stringify(unsealed));
		await expect(attest()).resolves.toEqual({ status: "rejected", reason: "state_unavailable" });
		// 3. Re-sealed with the (same-user readable) seal key: the entry is still unsigned.
		const key = await readFile(join(directory, ".state-integrity.key"));
		const canonical = (value: unknown): unknown => {
			if (Array.isArray(value)) return value.map(canonical);
			if (!value || typeof value !== "object") return value;
			const record = value as Record<string, unknown>;
			return Object.fromEntries(
				Object.keys(record)
					.sort()
					.map((entry) => [entry, canonical(record[entry])]),
			);
		};
		const stateMac = createHmac("sha256", key)
			.update("AIDR-MCP-ATTESTATION-STATE-V1\0")
			.update(name)
			.update("\0")
			.update(JSON.stringify(canonical(unsealed)))
			.digest("hex");
		await writeFile(path, JSON.stringify({ ...unsealed, stateMac }));
		const ignored: McpApprovalEntryRejection[] = [];
		await expect(attest(ignored)).resolves.toMatchObject({ status: "quarantined" });
		expect(ignored).toEqual(["unsigned_approval"]);
		expect((await stat(join(directory, ".state-integrity.key"))).mode & 0o077).toBe(0);
	});

	it("requires an absolute, user-owned state directory without group or world write", async () => {
		await expect(assertPrivateMcpStateDirectory("relative/state")).rejects.toMatchObject({
			code: "state_dir_not_absolute",
		});
		await expect(new FileMcpAttestationStore("relative/state").read(SERVER)).rejects.toBeInstanceOf(
			McpStateDirectoryError,
		);
		if (process.platform === "win32") return;
		const parent = await mkdtemp(join(tmpdir(), "aidr-mcp-attestation-perm-"));
		tempDirs.push(parent);
		const directory = join(parent, "state");
		await mkdir(directory, { mode: 0o700 });
		await chmod(directory, 0o777);
		await expect(assertPrivateMcpStateDirectory(directory)).rejects.toMatchObject({
			code: "state_dir_group_or_world_writable",
		});
		const keys = keyPair();
		await expect(
			attestMcpToolManifest({
				candidate: signMcpToolManifest({
					manifest: manifest(1),
					keyId: "customer-key-1",
					privateKey: keys.privateKey,
				}),
				verifier: verifier(keys.publicKeyPem),
				store: new FileMcpAttestationStore(directory),
				approvalKeys: OPERATOR_APPROVAL_KEYS,
			}),
		).resolves.toEqual({ status: "rejected", reason: "state_unavailable" });
		await chmod(directory, 0o750);
		await expect(assertPrivateMcpStateDirectory(directory)).resolves.toBe(true);
		const created = join(parent, "created", "nested");
		await expect(assertPrivateMcpStateDirectory(created, { create: true })).resolves.toBe(true);
		expect((await stat(created)).mode & 0o777).toBe(0o700);
	});
});
