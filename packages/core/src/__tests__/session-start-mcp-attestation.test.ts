import { generateKeyPairSync } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	approveQuarantinedMcpToolset,
	attestMcpToolManifest,
	MemoryMcpAttestationStore,
	type SignedMcpToolManifestV1,
	signMcpToolManifest,
} from "../mcp-attestation.js";
import { discoverMcpServers } from "../mcp-discovery.js";
import { runSessionStart } from "../session-start.js";
import { ConfigSchema } from "../types.js";

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

const originalFetch = globalThis.fetch;

function signedToolManifest(
	privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"],
	serverId = "filesystem",
): SignedMcpToolManifestV1 {
	return signMcpToolManifest({
		manifest: {
			schema_version: 1,
			server_id: serverId,
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
		keyId: "publisher-key-1",
		privateKey,
	});
}

describe("session start MCP tool-manifest coverage", () => {
	let root: string;
	let prevHome: string | undefined;

	beforeEach(async () => {
		prevHome = process.env.HOME;
		root = join(tmpdir(), `aidr-session-mcp-attest-${Math.random().toString(16).slice(2)}`);
		await mkdir(root, { recursive: true });
		process.env.HOME = root;
	});

	afterEach(async () => {
		globalThis.fetch = originalFetch;
		if (prevHome === undefined) delete process.env.HOME;
		else process.env.HOME = prevHome;
		await rm(root, { recursive: true, force: true });
	});

	it("reports an unapproved server as a coverage finding instead of a neutral inventory row", async () => {
		const aidrDir = join(root, ".singularity-aidr");
		const threatsDir = join(root, "threats");
		const allowlistsDir = join(root, "allowlists");
		const inventoryPath = join(root, "mcp.json");
		const configPath = join(aidrDir, "config.json");
		await mkdir(aidrDir, { recursive: true });
		await mkdir(threatsDir, { recursive: true });
		await mkdir(allowlistsDir, { recursive: true });
		await writeFile(
			inventoryPath,
			JSON.stringify({
				mcpServers: {
					filesystem: { command: "node", args: ["filesystem.js"] },
					unsigned: { url: "https://mcp.example.test/tools" },
					draft: { url: "https://mcp.example.test/draft" },
				},
			}),
			"utf-8",
		);

		const keys = generateKeyPairSync("ed25519");
		const publicKeyPem = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
		const signed = signedToolManifest(keys.privateKey);
		const draftSigned = signedToolManifest(keys.privateKey, "draft");
		const store = new MemoryMcpAttestationStore();
		const filesystem = (await discoverMcpServers([inventoryPath])).servers.find(
			(server) => server.name === "filesystem",
		);
		if (!filesystem) throw new Error("missing filesystem inventory");
		const decision = await attestMcpToolManifest({
			approvalKeys: OPERATOR_APPROVAL_KEYS,
			candidate: signed,
			connection: [
				"discovery-v1",
				"tenant-a",
				filesystem.inventory_id,
				filesystem.configuration_sha256,
			],
			verifier: {
				trustedSigners: { "publisher-key-1": publicKeyPem },
				expectedServerId: "filesystem",
			},
			store,
		});
		if (decision.status !== "quarantined") throw new Error("expected quarantine");
		await approveQuarantinedMcpToolset({
			approvalKey: OPERATOR_APPROVAL_KEY,
			serverId: "filesystem",
			toolsetHash: decision.toolsetHash,
			bindingSha256: (await store.read("filesystem"))?.quarantine?.bindingSha256 ?? "",
			approvedBy: "security-operator",
			reason: "initial server enrollment CR-91",
			store,
		});

		const config = ConfigSchema.parse({
			policy: { enabled: true, mcp: { enabled: true, inventory_paths: [inventoryPath] } },
			control_plane: { enabled: false },
			url_check: { enabled: false },
			file_check: { enabled: false },
			package_check: { enabled: false },
			cache: { enabled: false },
			logging: { enabled: false },
		});
		await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf-8");
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ ok: true, version: "0.6.0" }),
		} as unknown as Response);

		const result = await runSessionStart({
			plugins: [],
			threatsDir,
			allowlistsDir,
			version: "0.6.0",
			agentRuntime: "claude-code",
			configPath,
			aidrDirPath: aidrDir,
			mcpAttestation: {
				tenantId: "tenant-a",
				keyring: { "publisher-key-1": publicKeyPem },
				manifests: { filesystem: signed, draft: draftSigned },
				store,
				approvalKeys: OPERATOR_APPROVAL_KEYS,
			},
		});

		// All three servers remain inventory; the two without verified approval are findings.
		expect(result.posture).toMatchObject({ mcpServers: 3, unverifiedMcpServers: 2 });
		expect(
			result.coverageFindings
				?.map((finding) => ({
					server: finding.server,
					source: finding.source,
					status: finding.status,
					reason: finding.reason,
					severity: finding.severity,
					kind: finding.kind,
				}))
				.sort((left, right) => left.server.localeCompare(right.server)),
		).toEqual([
			{
				kind: "mcp_tool_manifest_unverified",
				severity: "medium",
				server: "draft",
				source: inventoryPath,
				status: "unapproved",
				reason: "not_approved",
			},
			{
				kind: "mcp_tool_manifest_unverified",
				severity: "medium",
				server: "unsigned",
				source: inventoryPath,
				status: "unsigned",
				reason: "no_signed_manifest",
			},
		]);
		expect(result.coverageFindings?.some((finding) => finding.server === "filesystem")).toBe(false);
	});

	it("reports every discovered server as unverifiable when no tenant keyring is configured", async () => {
		const aidrDir = join(root, ".singularity-aidr");
		const threatsDir = join(root, "threats");
		const allowlistsDir = join(root, "allowlists");
		const inventoryPath = join(root, "mcp.json");
		const configPath = join(aidrDir, "config.json");
		await mkdir(aidrDir, { recursive: true });
		await mkdir(threatsDir, { recursive: true });
		await mkdir(allowlistsDir, { recursive: true });
		await writeFile(
			inventoryPath,
			JSON.stringify({ mcpServers: { filesystem: { command: "node", args: ["filesystem.js"] } } }),
			"utf-8",
		);

		const config = ConfigSchema.parse({
			policy: { enabled: true, mcp: { enabled: true, inventory_paths: [inventoryPath] } },
			control_plane: { enabled: false },
			url_check: { enabled: false },
			file_check: { enabled: false },
			package_check: { enabled: false },
			cache: { enabled: false },
			logging: { enabled: false },
		});
		await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf-8");
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ ok: true, version: "0.6.0" }),
		} as unknown as Response);

		const result = await runSessionStart({
			plugins: [],
			threatsDir,
			allowlistsDir,
			version: "0.6.0",
			agentRuntime: "claude-code",
			configPath,
			aidrDirPath: aidrDir,
		});

		expect(result.coverageFindings).toEqual([
			expect.objectContaining({
				kind: "mcp_tool_manifest_unverified",
				severity: "high",
				server: "filesystem",
				status: "unverifiable",
				reason: "no_keyring",
			}),
		]);
		expect(result.coverageFindings?.[0]?.detail).toContain("keyring");
	});
});
