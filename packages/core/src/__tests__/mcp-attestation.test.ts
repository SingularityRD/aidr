import { createHash, sign as cryptoSign, generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, stat, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	approveQuarantinedMcpToolset,
	attestMcpToolManifest,
	canonicalMcpToolManifest,
	FileMcpAttestationStore,
	type McpToolDefinition,
	type McpToolManifestV1,
	MemoryMcpAttestationStore,
	mcpToolsetHash,
	signMcpToolManifest,
	verifySignedMcpToolManifest,
	writeMcpSignerHealthEvidence,
} from "../mcp-attestation.js";

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
			serverId: "mcp://customer/filesystem",
			toolsetHash: first.toolsetHash,
			bindingSha256: await reviewedBindingHash(store, "mcp://customer/filesystem"),
			approvedBy: "operator",
			reason: "initial signer",
			store,
		});
		const replacement = signMcpToolManifest({
			manifest: manifest(2),
			keyId: "customer-key-2",
			privateKey: secondKeys.privateKey,
		});
		await expect(
			attestMcpToolManifest({ candidate: replacement, verifier: trust, store }),
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
			candidate: signed,
			verifier: verifier(keys.publicKeyPem),
			store,
			connection: ["tenant-a", "https://first.example/mcp"],
		});
		if (first.status !== "quarantined") throw new Error("expected quarantine");
		const reviewedA = await reviewedBindingHash(store, signed.manifest.server_id);
		await approveQuarantinedMcpToolset({
			serverId: signed.manifest.server_id,
			toolsetHash: first.toolsetHash,
			bindingSha256: reviewedA,
			approvedBy: "operator",
			reason: "first endpoint",
			store,
		});
		await expect(
			attestMcpToolManifest({
				candidate: signed,
				verifier: verifier(keys.publicKeyPem),
				store,
				connection: ["tenant-a", "https://first.example/mcp"],
			}),
		).resolves.toMatchObject({ status: "accepted" });
		await expect(
			attestMcpToolManifest({
				candidate: signed,
				verifier: verifier(keys.publicKeyPem),
				store,
				connection: ["tenant-a", "https://other.example/mcp"],
			}),
		).resolves.toMatchObject({ status: "quarantined" });
		await expect(
			approveQuarantinedMcpToolset({
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
			candidate: firstSigned,
			verifier: verifier(keys.publicKeyPem),
			store,
		});
		if (first.status !== "quarantined") throw new Error("expected quarantine");
		await approveQuarantinedMcpToolset({
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
			candidate: signed(manifest(8)),
			verifier: verifier(keys.publicKeyPem),
			store,
		});
		await expect(
			attestMcpToolManifest({
				candidate: signed(manifest(7)),
				verifier: verifier(keys.publicKeyPem),
				store,
			}),
		).resolves.toEqual({ status: "rejected", reason: "sequence_replay" });
		await expect(
			attestMcpToolManifest({
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
			candidate: signed,
			verifier: verifier(keys.publicKeyPem),
			store: firstStore,
		});
		if (first.status !== "quarantined") throw new Error("expected quarantine");
		await approveQuarantinedMcpToolset({
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
				candidate: signed,
				verifier: verifier(keys.publicKeyPem),
				store: new FileMcpAttestationStore(directory),
			}),
		).resolves.toEqual({ status: "rejected", reason: "state_unavailable" });
	});
});
