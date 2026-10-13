import "./helpers/isolated-home.mjs";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { pathToFileURL } from "node:url";
import { signMcpToolsetApproval } from "@singularityrd/aidr-core";
import { buildGatewayPackageFixture } from "../../scripts/library-fixture.mjs";
import { approveQuarantinedToolset } from "../operator-approval.mjs";
import { TEST_APPROVAL_KEY, TEST_APPROVAL_KEYS } from "./helpers/approval-key.mjs";
import { fixture, rpc } from "./helpers/gateway-fixture.mjs";

/**
 * MSC-2 (gateway side): an agent that can run `node -e` with a computed import
 * path can load the installed library without any literal CLT-SELF-009 text.
 * The library must therefore carry no code path that signs or records an
 * operator approval, and the gateway it builds must honour nothing that is not
 * signed by a key in its own `approvalKeys`.
 */

// Functions that sign or record an approval; only the operator command may contain them.
const APPROVAL_WRITERS = [
	"approveQuarantinedToolset",
	"approveQuarantinedMcpToolset",
	"signMcpToolsetApproval",
];
// Bundles an agent can import or that serve agent traffic.
const NO_APPROVAL_BUNDLES = ["aidr-mcp-library.mjs", "aidr-mcp-gateway.mjs", "aidr-mcp-stdio.mjs"];

let root;
let installed;
let library;

before(async () => {
	root = await mkdtemp(join(tmpdir(), "aidr-mcp-library-approval-"));
	installed = await buildGatewayPackageFixture(root);
	// The library verifies its signed artifact against the installed HOME at import.
	const saved = { HOME: process.env.HOME, AIDR_COMMERCIAL: process.env.AIDR_COMMERCIAL };
	process.env.HOME = installed.home;
	process.env.AIDR_COMMERCIAL = "1";
	try {
		library = await import(pathToFileURL(join(installed.dist, "aidr-mcp-library.mjs")).href);
	} finally {
		process.env.HOME = saved.HOME;
		if (saved.AIDR_COMMERCIAL === undefined) delete process.env.AIDR_COMMERCIAL;
		else process.env.AIDR_COMMERCIAL = saved.AIDR_COMMERCIAL;
	}
});

after(async () => {
	if (root) await rm(root, { recursive: true, force: true });
});

/** An approval an importer can produce: the real signing code, but not the operator's key. */
function forgedApproval(quarantine, approvalKeyId) {
	const now = new Date();
	return signMcpToolsetApproval({
		serverId: "server-a",
		toolsetHash: quarantine.toolsetHash,
		keyId: quarantine.keyId,
		signerKeySha256: quarantine.signerKeySha256,
		bindingSha256: quarantine.bindingSha256,
		approvedBy: "agent",
		reason: "self",
		approvedAt: now,
		expiresAt: new Date(now.getTime() + 60_000),
		approvalKeyId,
		privateKey: generateKeyPairSync("ed25519").privateKey,
	});
}

describe("MSC-2: the importable library cannot approve a quarantined toolset", () => {
	it("exports only the gateway factory, and the gateway it builds has no approval writer", async () => {
		assert.deepEqual(Object.keys(library), ["createMcpGateway"]);
		const f = fixture({ createGateway: library.createMcpGateway });
		const approvalMembers = Object.keys(f.gateway).filter((name) => /approv/i.test(name));
		assert.deepEqual(approvalMembers, ["approvalTarget"]);
		assert.equal(f.gateway.approve, undefined);
	});

	it("keeps a pending toolset quarantined against an importer holding the library but not the operator key", async () => {
		const f = fixture({ createGateway: library.createMcpGateway });
		const base = await f.start();
		assert.match(
			(await rpc(base, f.tokenA, "tools/call", 1)).body.error.message,
			/manifest_quarantined/,
		);
		const store = f.gateway.storeFor("tenant-a");
		const pending = await store.read("server-a");

		// approvalTarget is read-only: describing the target writes nothing.
		const target = await f.gateway.approvalTarget({ tenantId: "tenant-a", serverId: "server-a" });
		assert.equal(target.bindingSha256, pending.quarantine.bindingSha256);
		assert.deepEqual(await store.read("server-a"), pending);

		// Write forged entries through the gateway's own store (which keeps any seal
		// valid): one under an unknown key id, one claiming the operator's key id.
		const [operatorKeyId] = Object.keys(TEST_APPROVAL_KEYS);
		await store.transact("server-a", (current) => ({
			state: {
				...current,
				approvedToolsets: [
					...current.approvedToolsets,
					forgedApproval(current.quarantine, "agent-key"),
					forgedApproval(current.quarantine, operatorKeyId),
				],
			},
			result: null,
		}));

		const after = await rpc(base, f.tokenA, "tools/call", 2);
		assert.ok(after.body.error, "a forged approval must not release the toolset");
		assert.match(after.body.error.message, /manifest_quarantined/);
		assert.equal(f.toolCalls, 0);
		const rejections = f.events
			.filter((event) => event.reason === "approval_entry_ignored")
			.map((event) => event.approvalRejection);
		assert.ok(rejections.includes("untrusted_approval_key"), JSON.stringify(rejections));
		assert.ok(rejections.includes("invalid_approval_signature"), JSON.stringify(rejections));

		// Benign twin: the operator path (approve.mjs only) still releases it.
		const approved = await approveQuarantinedToolset(f.gateway, {
			tenantId: "tenant-a",
			serverId: "server-a",
			toolsetHash: pending.quarantine.toolsetHash,
			bindingSha256: pending.quarantine.bindingSha256,
			approvedBy: "security-operator",
			reason: "reviewed",
			approvalKey: TEST_APPROVAL_KEY,
		});
		assert.equal(approved.approved, true);
		const delivered = await rpc(base, f.tokenA, "tools/call", 3);
		assert.equal(delivered.body.result.content[0].text, "Normal result");
	});
});

describe("MSC-2: built bundles and package exports", () => {
	it("no importable or serving bundle contains an approval-writing function", async () => {
		for (const name of NO_APPROVAL_BUNDLES) {
			const text = await readFile(join(installed.dist, name), "utf8");
			for (const writer of APPROVAL_WRITERS)
				assert.equal(new RegExp(`\\b${writer}\\b`).test(text), false, `${name} contains ${writer}`);
			assert.equal(/\bapprove\s*\(\s*\{/.test(text), false, `${name} defines an approve() method`);
		}
		// Positive control: the operator command still carries the signer, and exports nothing.
		const cli = await readFile(join(installed.dist, "aidr-mcp-approve.mjs"), "utf8");
		for (const writer of APPROVAL_WRITERS)
			assert.equal(
				new RegExp(`\\bfunction ${writer}\\b`).test(cli),
				true,
				`approve bundle lacks ${writer}`,
			);
		assert.equal(/^export\s/m.test(cli), false, "the approve bundle must not export anything");
	});

	it("exposes only the library entry; the approve command is not an importable subpath", async () => {
		const manifest = JSON.parse(await readFile(join(installed.installed, "package.json"), "utf8"));
		assert.deepEqual(manifest.exports, { ".": "./dist/aidr-mcp-library.mjs" });
		const consumer = join(root, "subpath-consumer.mjs");
		await writeFile(
			consumer,
			`try { await import("@singularityrd/aidr-mcp-gateway/dist/aidr-mcp-approve.mjs"); process.stdout.write("imported\\n"); }\ncatch (error) { process.stdout.write(error.code + "\\n"); }\n`,
		);
		const result = spawnSync(process.execPath, [consumer], {
			cwd: root,
			env: installed.environment,
			encoding: "utf8",
			timeout: 10_000,
		});
		assert.equal(result.stdout.trim(), "ERR_PACKAGE_PATH_NOT_EXPORTED", result.stderr);
	});
});
