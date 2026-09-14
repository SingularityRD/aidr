import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import {
	approveQuarantinedMcpToolset,
	attestMcpToolManifest,
	MemoryMcpAttestationStore,
	type SignedMcpToolManifestV1,
	signMcpToolManifest,
} from "../mcp-attestation.js";
import { discoverMcpServers } from "../mcp-discovery.js";

function keyPair(): { privateKey: KeyObject; publicKeyPem: string } {
	const pair = generateKeyPairSync("ed25519");
	return {
		privateKey: pair.privateKey,
		publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
	};
}

/** Signed tool manifest bound to the locally configured server name. */
function signedToolManifest(
	privateKey: KeyObject,
	keyId = "publisher-key-1",
): SignedMcpToolManifestV1 {
	return signMcpToolManifest({
		manifest: {
			schema_version: 1,
			server_id: "filesystem",
			sequence: 1,
			issued_at: new Date(Date.now() - 60_000).toISOString(),
			expires_at: new Date(Date.now() + 60 * 60_000).toISOString(),
			tools: [
				{
					name: "files.read",
					description: "Read one workspace file",
					input_schema: { type: "object" },
				},
			],
		},
		keyId,
		privateKey,
	});
}

describe("MCP discovery evidence", () => {
	it("fingerprints configuration changes without exporting credentials", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-discover-"));
		try {
			const path = join(dir, "mcp.json");
			const config = {
				mcp: {
					local: { command: ["bash", "--allow-all", "private-secret"] },
					remote: { url: "https://user:private-secret@mcp.example/tool?key=private-secret" },
				},
			};
			await writeFile(path, JSON.stringify(config));
			const first = await discoverMcpServers([path]);
			expect(first.servers[0]?.risk_hints).toContain("shell_wrapper_command");
			expect(first.servers[0]?.inventory_id).toMatch(/^[0-9a-f]{64}$/);
			expect(JSON.stringify(first)).not.toContain("private-secret");
			expect(first.servers[1]?.endpoint).toBe("https://mcp.example");
			config.mcp.local.command.push("changed");
			await writeFile(path, JSON.stringify(config));
			const changed = await discoverMcpServers([path]);
			expect(changed.servers[0]?.configuration_sha256).not.toBe(
				first.servers[0]?.configuration_sha256,
			);
			expect(changed.servers[0]?.inventory_id).toBe(first.servers[0]?.inventory_id);
			await writeFile(path, "{broken");
			expect((await discoverMcpServers([path])).sources[0]?.status).toBe("invalid");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("binds stable IDs to canonical source and configured alias", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-discover-id-"));
		try {
			const firstPath = join(dir, "first.json");
			const secondPath = join(dir, "second.json");
			await writeFile(
				firstPath,
				JSON.stringify({
					mcpServers: {
						shared: { command: "node", args: ["server.js"] },
						alias: { command: "node", args: ["server.js"] },
					},
				}),
			);
			await writeFile(
				secondPath,
				JSON.stringify({
					mcpServers: {
						shared: { command: "node", args: ["server.js"] },
					},
				}),
			);
			const first = await discoverMcpServers([firstPath, secondPath]);
			expect(first.servers).toHaveLength(3);
			const [shared, alias, otherSource] = first.servers;
			expect(new Set(first.servers.map((server) => server.inventory_id)).size).toBe(3);
			expect(shared?.configuration_sha256).toBe(alias?.configuration_sha256);
			expect(shared?.configuration_sha256).toBe(otherSource?.configuration_sha256);
			expect(shared?.inventory_id).not.toBe(alias?.inventory_id);
			expect(shared?.inventory_id).not.toBe(otherSource?.inventory_id);
			const relativeReport = await discoverMcpServers([relative(process.cwd(), firstPath)]);
			expect(relativeReport.servers[0]?.inventory_id).toBe(shared?.inventory_id);
			await writeFile(
				firstPath,
				JSON.stringify({
					mcpServers: {
						renamed: { command: "node", args: ["server.js"] },
					},
				}),
			);
			const renamed = await discoverMcpServers([firstPath]);
			expect(renamed.servers[0]?.inventory_id).not.toBe(shared?.inventory_id);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("reports a discovered server whose tool manifest is unsigned or unverifiable", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-discover-attest-"));
		try {
			const path = join(dir, "mcp.json");
			await writeFile(
				path,
				JSON.stringify({ mcpServers: { filesystem: { command: "node", args: ["server.js"] } } }),
			);

			// No tenant keyring: the report states the absence instead of implying trust.
			const withoutKeyring = await discoverMcpServers([path]);
			expect(withoutKeyring.servers[0]?.attestation).toEqual({
				status: "unverifiable",
				keyring: "absent",
				approval_state: "unavailable",
				reason: "no_keyring",
			});

			const keys = keyPair();
			const foreignKeys = keyPair();
			const keyring = { "publisher-key-1": keys.publicKeyPem };

			// A keyring alone never manufactures a verified verdict.
			const unsigned = await discoverMcpServers([path], { attestation: { keyring } });
			expect(unsigned.servers[0]?.attestation).toMatchObject({
				status: "unsigned",
				keyring: "configured",
				reason: "no_signed_manifest",
			});

			// A signer outside the tenant keyring stays unverifiable.
			const unknownSigner = await discoverMcpServers([path], {
				attestation: {
					keyring,
					manifests: { filesystem: signedToolManifest(foreignKeys.privateKey, "publisher-key-2") },
				},
			});
			expect(unknownSigner.servers[0]?.attestation).toMatchObject({
				status: "unverifiable",
				keyring: "configured",
				reason: "unknown_signer",
				key_id: "publisher-key-2",
			});

			// A trusted key id re-used with a different private key is not an alias: the
			// key id is bound into the signature and the file is rejected.
			const keyIdSubstitution = await discoverMcpServers([path], {
				attestation: {
					keyring,
					manifests: { filesystem: signedToolManifest(foreignKeys.privateKey) },
				},
			});
			expect(keyIdSubstitution.servers[0]?.attestation).toMatchObject({
				status: "rejected",
				keyring: "configured",
				reason: "invalid_signature",
				key_id: "publisher-key-1",
			});

			// A verified signature is evidence, not an operator approval.
			const unapproved = await discoverMcpServers([path], {
				attestation: { keyring, manifests: { filesystem: signedToolManifest(keys.privateKey) } },
			});
			expect(unapproved.servers[0]?.attestation).toMatchObject({
				status: "unapproved",
				keyring: "configured",
				approval_state: "unavailable",
				reason: "approval_state_unavailable",
				server_id: "filesystem",
			});
			expect(unapproved.servers[0]?.attestation.toolset_hash).toMatch(/^[0-9a-f]{64}$/);
			expect(unapproved.servers[0]?.attestation.status).not.toBe("approved");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("carries the quarantined toolset hash into discovery output", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-discover-quarantine-"));
		try {
			const path = join(dir, "mcp.json");
			await writeFile(
				path,
				JSON.stringify({ mcpServers: { filesystem: { command: "node", args: ["server.js"] } } }),
			);
			const keys = keyPair();
			const keyring = { "publisher-key-1": keys.publicKeyPem };
			const signed = signedToolManifest(keys.privateKey);
			const readOnlyStore = new MemoryMcpAttestationStore();

			// Discovery reads approval state; it must not create or advance it.
			const unapproved = await discoverMcpServers([path], {
				attestation: { keyring, manifests: { filesystem: signed }, store: readOnlyStore },
			});
			expect(unapproved.servers[0]?.attestation).toMatchObject({
				status: "unapproved",
				approval_state: "available",
				reason: "not_approved",
			});
			expect(await readOnlyStore.read("filesystem")).toBeNull();

			const store = new MemoryMcpAttestationStore();
			const decision = await attestMcpToolManifest({
				candidate: signed,
				verifier: { trustedSigners: keyring, expectedServerId: "filesystem" },
				store,
			});
			if (decision.status !== "quarantined") throw new Error("expected quarantine");

			const quarantined = await discoverMcpServers([path], {
				attestation: { keyring, manifests: { filesystem: signed }, store },
			});
			expect(quarantined.servers[0]?.attestation).toMatchObject({
				status: "quarantined",
				approval_state: "available",
				key_id: "publisher-key-1",
				server_id: "filesystem",
				toolset_hash: decision.toolsetHash,
				quarantined_toolset_hash: decision.toolsetHash,
			});

			await approveQuarantinedMcpToolset({
				serverId: "filesystem",
				toolsetHash: decision.toolsetHash,
				approvedBy: "security-operator",
				reason: "approved change request CR-77",
				store,
			});
			const approved = await discoverMcpServers([path], {
				attestation: { keyring, manifests: { filesystem: signed }, store },
			});
			expect(approved.servers[0]?.attestation).toEqual({
				status: "approved",
				keyring: "configured",
				approval_state: "available",
				key_id: "publisher-key-1",
				server_id: "filesystem",
				toolset_hash: decision.toolsetHash,
			});
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});
});
