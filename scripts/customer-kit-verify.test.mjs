import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { CUSTOMER_KIT_REQUIRED_FILES, renderCustomerKitDoc } from "./customer-kit-contract.mjs";

const repoRoot = resolve(import.meta.dirname, "..");
const verifier = join(repoRoot, "scripts", "customer-kit-verify.mjs");
const aliases = {
	"START-HERE.md": "deploy/FIRST_CUSTOMER.md",
	"INSTALLATION.md": "deploy/README.md",
	"RESTORE-DRILL.md": "docs/production-readiness/backup-restore-v6.md",
	"NATIVE-HOST-ACCEPTANCE.md": "docs/production-readiness/native-host-matrix-v6.md",
	"SUPPORT-RUNBOOK.md": "docs/runbooks/support-v7.md",
	"SECRETS-RUNBOOK.md": "docs/runbooks/secrets-management.md",
	"LICENSING.md": "docs/operations/licensing.md",
	"THREAT-SYNC.md": "docs/operations/threat-sync.md",
	"FIRST-CUSTOMER-SALES-PACKET.md": "docs/production-readiness/first-customer-buyer-handoff-2026-09-23.md",
	"CANDIDATE-STATUS.md": "docs/production-readiness/first-customer-ready.md",
	"RELEASE-EVIDENCE.md": "docs/release-evidence.md",
};

test("customer kit sources the current readiness profile, not an old candidate snapshot", () => {
	const assembler = readFileSync(join(repoRoot, "scripts", "customer-kit.mjs"), "utf8");
	assert.ok(assembler.includes('"docs/production-readiness/first-customer-ready.md", "CANDIDATE-STATUS.md"'));
	assert.ok(assembler.includes('"docs/production-readiness/first-customer-buyer-handoff-2026-09-23.md", "FIRST-CUSTOMER-SALES-PACKET.md"'));
	assert.ok(assembler.includes("worktree_dirty: releaseMetadata.worktree_dirty,"), "outer envelope must retain the source cleanliness proof");
});

// Build the smallest complete extracted-kit fixture from repository files. It
// has no release bundle, provider credentials, customer records or live input;
// the tests exercise only the local file contract and checksum walk.
function createKit() {
	const kit = mkdtempSync(join(tmpdir(), "aidr-customer-kit-verify-"));
	for (const target of CUSTOMER_KIT_REQUIRED_FILES) {
		const source = aliases[target] ?? target;
		const sourcePath = join(repoRoot, source);
		assert.ok(existsSync(sourcePath), `fixture source is missing: ${source}`);
		const destination = join(kit, target);
		mkdirSync(resolve(destination, ".."), { recursive: true });
		if (["START-HERE.md", "INSTALLATION.md"].includes(target)) {
			writeFileSync(destination, renderCustomerKitDoc(target, readFileSync(sourcePath, "utf8")));
		} else {
			copyFileSync(sourcePath, destination);
		}
	}
	writeFileSync(
		join(kit, "release-source.json"),
		`${JSON.stringify(
			{
				release_signed: false,
				inline_mcp_gateway_bundled: false,
				device_start_ingress_bundled: true,
				region_manifest_bundled: true,
				tls_renewal_bundled: true,
				provenance_tool_bundled: true,
				airgap_tool_bundled: true,
				benchmark_contract_bundled: true,
				provenance_statement_bundled: false,
				assurance: "Unsigned customer installation candidate. Checksums detect changes; they do not authenticate the publisher.",
			},
			null,
			2,
		)}\n`,
	);
	writeChecksums(kit);
	return kit;
}

function writeChecksums(kit) {
	const entries = [];
	for (const file of files(kit)) {
		if (file === "SHA256SUMS") continue;
		entries.push(`${sha256(readFileSync(join(kit, file)))}  ${file}`);
	}
	writeFileSync(join(kit, "SHA256SUMS"), `${entries.sort().join("\n")}\n`);
}

function addSignedGateway(kit) {
	const gateway = join(kit, "deploy", "gateway");
	mkdirSync(gateway, { recursive: true });
	const binaries = ["aidr-mcp-gateway.mjs", "aidr-mcp-approve.mjs", "aidr-mcp-stdio.mjs"];
	for (const name of binaries) writeFileSync(join(gateway, name), `// ${name}\n`);
	writeFileSync(join(gateway, "README.md"), "# Gateway fixture\n");
	writeFileSync(
		join(gateway, "aidr-artifact.manifest.json"),
		`${JSON.stringify({
			schema_version: 1,
			files: binaries.map((name) => ({ path: name, sha256: sha256(readFileSync(join(gateway, name))) })),
		})}\n`,
	);
	writeFileSync(join(gateway, "aidr-artifact.manifest.sig"), Buffer.alloc(64, 1).toString("base64"));
	const sourcePath = join(kit, "release-source.json");
	const source = JSON.parse(readFileSync(sourcePath, "utf8"));
	source.inline_mcp_gateway_bundled = true;
	writeFileSync(sourcePath, `${JSON.stringify(source, null, 2)}\n`);
	writeChecksums(kit);
}

function files(directory, prefix = "") {
	return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
		const file = join(directory, entry.name);
		const name = prefix ? `${prefix}/${entry.name}` : entry.name;
		return entry.isDirectory() ? files(file, name) : [name];
	});
}

function run(kit) {
	return spawnSync(process.execPath, [join(kit, "scripts", "customer-kit-verify.mjs"), "--kit", kit], {
		cwd: kit,
		encoding: "utf8",
		windowsHide: true,
	});
}

function runSourceVerifier(kit) {
	return spawnSync(process.execPath, [join(kit, "scripts", "verify-customer-kit.mjs"), kit], {
		cwd: kit,
		encoding: "utf8",
		windowsHide: true,
	});
}

function addReleaseArtifact(kit, name) {
	const artifacts = join(kit, "artifacts");
	mkdirSync(artifacts, { recursive: true });
	writeFileSync(join(artifacts, name), "synthetic release artifact\n");
	const digest = sha256(readFileSync(join(artifacts, name)));
	writeFileSync(join(artifacts, "release-metadata.json"), JSON.stringify({
		schema_version: 1,
		release_tag: "fixture-1",
		release_version: "1.0.0",
		git_sha: "a".repeat(40),
		source_date_epoch: 1,
		worktree_dirty: false,
		artifacts: [{ path: name, size: readFileSync(join(artifacts, name)).length, sha256: digest }],
	}));
	writeFileSync(join(artifacts, "release-inventory.json"), JSON.stringify({
		schema_version: 1,
		artifacts: [{ source_path: `release-output/${name}`, staged_path: name, kind: "release-artifact", sha256: digest }],
	}));
	writeChecksums(kit);
}

function sha256(bytes) {
	return createHash("sha256").update(bytes).digest("hex");
}

test("complete kit fixture carries every region, TLS, provenance, air-gap and benchmark artifact", () => {
	const kit = createKit();
	try {
		const result = run(kit);
		assert.equal(result.status, 0, result.stderr);
		const summary = JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
		assert.equal(summary.passed, true);
		assert.equal(summary.publisher_authenticated, false);
		assert.equal(summary.release_artifacts_verified, 0);
		assert.match(summary.note, /not proof of provider location/);
	} finally {
		rmSync(kit, { recursive: true, force: true });
	}
});

test("kit verifier rejects a false residency declaration disguised by a Frankfurt location", () => {
	const kit = createKit();
	try {
		const manifestPath = join(kit, "deploy", "regions.manifest.json");
		const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
		manifest.regions["self-hosted"].residency = { declared: false, location: "Frankfurt" };
		writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
		writeChecksums(kit);
		const result = run(kit);
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /self-hosted.*must have residency\.declared=true/);
	} finally {
		rmSync(kit, { recursive: true, force: true });
	}
});

test("restore drill imports from an extracted kit without starting a provider operation", async () => {
	const kit = createKit();
	try {
		const restoreDrill = await import(pathToFileURL(join(kit, "scripts", "deployment-restore-drill.mjs")).href);
		assert.equal(typeof restoreDrill.parseRecoveryTargets, "function");
	} finally {
		rmSync(kit, { recursive: true, force: true });
	}
});

test("extracted kit bootstrap resolves its local helper before deployment access", () => {
	const kit = createKit();
	try {
		const result = spawnSync(process.execPath, [join(kit, "scripts", "deployment-bootstrap.mjs")], {
			cwd: kit,
			encoding: "utf8",
			windowsHide: true,
		});
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /deployment\.json/);
		assert.doesNotMatch(result.stderr, /ERR_MODULE_NOT_FOUND/);
	} finally {
		rmSync(kit, { recursive: true, force: true });
	}
});

test("extracted kit guides contain only resolvable local links", () => {
	const kit = createKit();
	try {
		assert.equal(run(kit).status, 0);
		const guide = join(kit, "START-HERE.md");
		writeFileSync(guide, `${readFileSync(guide, "utf8")}\n[missing guide](../docs/missing.md)\n`);
		writeChecksums(kit);
		const result = run(kit);
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /unresolved local link/);
	} finally {
		rmSync(kit, { recursive: true, force: true });
	}
});

test("a regenerated checksum inventory cannot omit a required new artifact", () => {
	const kit = createKit();
	try {
		const missing = "scripts/generate-provenance.mjs";
		unlinkSync(join(kit, missing));
		writeChecksums(kit);
		const result = run(kit);
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, new RegExp(`Required customer acceptance artifact is missing: ${missing.replaceAll(".", "\\.")}`));
	} finally {
		rmSync(kit, { recursive: true, force: true });
	}
});

test("a regenerated checksum inventory cannot omit the installer or doctor", () => {
	for (const missing of ["scripts/deployment-prepare.mjs", "scripts/deployment-doctor.mjs"]) {
		const kit = createKit();
		try {
			unlinkSync(join(kit, missing));
			writeChecksums(kit);
			const result = run(kit);
			assert.notEqual(result.status, 0);
			assert.match(result.stderr, new RegExp(`Required customer acceptance artifact is missing: ${missing.replaceAll(".", "\\.")}`));
		} finally {
			rmSync(kit, { recursive: true, force: true });
		}
	}
});

test("an extra unlisted artifact fails the checksum set check", () => {
	const kit = createKit();
	try {
		writeFileSync(join(kit, "extra.txt"), "not part of the candidate\n");
		const result = run(kit);
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /Kit file set does not match SHA256SUMS/);
	} finally {
		rmSync(kit, { recursive: true, force: true });
	}
});

test("a bundled gateway requires its detached artifact signature", () => {
	const kit = createKit();
	try {
		addSignedGateway(kit);
		assert.equal(run(kit).status, 0);
		unlinkSync(join(kit, "deploy", "gateway", "aidr-artifact.manifest.sig"));
		writeChecksums(kit);
		const result = run(kit);
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /MCP gateway delivery status does not match bundled runtime/);
	} finally {
		rmSync(kit, { recursive: true, force: true });
	}
});

test("gateway-free kit rejects even one gateway runtime file", () => {
	const kit = createKit();
	try {
		assert.equal(run(kit).status, 0);
		mkdirSync(join(kit, "deploy", "gateway"), { recursive: true });
		writeFileSync(join(kit, "deploy", "gateway", "aidr-mcp-gateway.mjs"), "// partial gateway\n");
		writeChecksums(kit);
		for (const result of [run(kit), runSourceVerifier(kit)]) {
			assert.notEqual(result.status, 0);
			assert.match(result.stderr, /MCP gateway delivery status does not match bundled/);
		}
	} finally {
		rmSync(kit, { recursive: true, force: true });
	}
});

test("bundled gateway rejects undeclared files and malformed signature", () => {
	const kit = createKit();
	try {
		addSignedGateway(kit);
		assert.equal(run(kit).status, 0);
		const extra = join(kit, "deploy", "gateway", "untracked.mjs");
		writeFileSync(extra, "// not signed\n");
		writeChecksums(kit);
		for (const result of [run(kit), runSourceVerifier(kit)]) {
			assert.notEqual(result.status, 0);
			assert.match(result.stderr, /outside its signed artifact manifest/);
		}
		unlinkSync(extra);
		writeFileSync(join(kit, "deploy", "gateway", "aidr-artifact.manifest.sig"), "not-base64\n");
		writeChecksums(kit);
		for (const result of [run(kit), runSourceVerifier(kit)]) {
			assert.notEqual(result.status, 0);
			assert.match(result.stderr, /Gateway artifact signature is invalid/);
		}
	} finally {
		rmSync(kit, { recursive: true, force: true });
	}
});

test("gateway-free kit rejects an MCP gateway tarball in release inventory", () => {
	const kit = createKit();
	try {
		addReleaseArtifact(kit, "singularityrd-aidr-mcp-gateway-0.6.0.tgz");
		for (const result of [run(kit), runSourceVerifier(kit)]) {
			assert.notEqual(result.status, 0);
			assert.match(result.stderr, /Gateway-free kit cannot contain an MCP gateway release artifact/);
		}
	} finally {
		rmSync(kit, { recursive: true, force: true });
	}
});

test("release-bound kit rejects an uncommitted source before creating output", () => {
	const source = mkdtempSync(join(tmpdir(), "aidr-customer-kit-source-"));
	try {
		for (const args of [["init", "-q"], ["-c", "user.name=Kit Test", "-c", "user.email=kit@example.invalid", "commit", "--allow-empty", "-qm", "fixture"]]) {
			const git = spawnSync("git", args, { cwd: source, encoding: "utf8", windowsHide: true });
			assert.equal(git.status, 0, git.stderr);
		}
		writeFileSync(join(source, "uncommitted.txt"), "review required\n");
		const output = join(source, "customer-kit");
		const result = spawnSync(process.execPath, [join(repoRoot, "scripts", "customer-kit.mjs"), "--output", output, "--upstream-dir", source, "--release-dir", join(source, "release")], { cwd: source, encoding: "utf8", windowsHide: true });
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /Release-bound customer kit requires a clean source tree/);
		assert.equal(existsSync(output), false);
	} finally {
		rmSync(source, { recursive: true, force: true });
	}
});
