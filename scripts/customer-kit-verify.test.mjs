import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { CUSTOMER_KIT_PRIVACY_GATEWAY_FILES, CUSTOMER_KIT_PRIVACY_GATEWAY_RUNTIME, CUSTOMER_KIT_REQUIRED_FILES, CUSTOMER_KIT_RENDERED_GUIDES, renderCustomerKitDoc } from "./customer-kit-contract.mjs";
import { PRIVACY_GATEWAY_DEFINITION_FILES, PRIVACY_GATEWAY_REQUIRED_RUNTIME, privacyGatewayPackageEntries } from "../deploy/privacy-gateway/privacy-gateway.mjs";

const repoRoot = resolve(import.meta.dirname, "..");
const verifier = join(repoRoot, "scripts", "customer-kit-verify.mjs");
const aliases = {
	"START-HERE.md": "deploy/FIRST_CUSTOMER.md",
	"INSTALLATION.md": "deploy/README.md",
	"RESTORE-DRILL.md": "docs/production-readiness/backup-restore-v6.md",
	"RETENTION-HOLDS.md": "docs/production-readiness/retention-holds.md",
  "SAML-RECOVERY.md": "docs/operations/saml-outage-recovery.md",
  "RESPONSE-PLAYBOOKS.md": "docs/operations/response-playbooks.md",
  "CLOUD-DISCOVERY.md": "docs/runbooks/cloud-discovery.md",
  "BEHAVIORAL-LEARNING.md": "docs/runbooks/behavioral-learning.md",
  "PACKAGE-INSTALLATION.md": "docs/package-installation.md",
  "CODEX-CONNECTOR.md": "packages/codex/README.md",
  "CONTROL-PLANE.md": "supabase/README.md",
	"NATIVE-HOST-ACCEPTANCE.md": "docs/production-readiness/native-host-matrix-v6.md",
	"SUPPORT-RUNBOOK.md": "docs/runbooks/support-v7.md",
	"SECRETS-RUNBOOK.md": "docs/runbooks/secrets-management.md",
	"LICENSING.md": "docs/operations/licensing.md",
	"THREAT-SYNC.md": "docs/operations/threat-sync.md",
	"FIRST-CUSTOMER-SALES-PACKET.md": "docs/production-readiness/first-customer-buyer-handoff-2026-09-23.md",
	"CANDIDATE-STATUS.md": "docs/production-readiness/first-customer-ready.md",
	"RELEASE-EVIDENCE.md": "docs/release-evidence.md",
	"RELEASE-SIGNING.md": "docs/runbooks/portable-release-signing.md",
};

test("customer kit sources the current readiness profile, not an old candidate snapshot", () => {
	const assembler = readFileSync(join(repoRoot, "scripts", "customer-kit.mjs"), "utf8");
	assert.ok(assembler.includes('"docs/production-readiness/first-customer-ready.md", "CANDIDATE-STATUS.md"'));
	assert.ok(assembler.includes('"docs/production-readiness/first-customer-buyer-handoff-2026-09-23.md", "FIRST-CUSTOMER-SALES-PACKET.md"'));
	assert.ok(assembler.includes('"docs/production-readiness/retention-holds.md", "RETENTION-HOLDS.md"'));
	assert.ok(assembler.includes("worktree_dirty: releaseMetadata.worktree_dirty,"), "outer envelope must retain the source cleanliness proof");
});

test("signed kit assembly requires independent Windows receipt and publisher pins before copying staged scripts", () => {
	const assembler = readFileSync(join(repoRoot, "scripts", "customer-kit.mjs"), "utf8");
	const signedBlock = assembler.slice(assembler.indexOf("if (releaseSigned) {"), assembler.indexOf("for (const relative of CUSTOMER_KIT_REQUIRED_FILES)"));
	assert.ok(signedBlock.indexOf("validateSignedWindowsFleet(root,") >= 0);
	assert.match(signedBlock, /windows-authenticode-receipt-sha256[\s\S]*AIDR_EXPECTED_WINDOWS_AUTHENTICODE_RECEIPT_SHA256/);
	assert.match(signedBlock, /windows-code-signing-thumbprint[\s\S]*AIDR_WINDOWS_CODE_SIGNING_THUMBPRINT/);
	assert.ok(signedBlock.indexOf("validateSignedWindowsFleet(root,") < signedBlock.indexOf('copy(signedFleet, join(output, "deploy/fleet/windows"))'));
	assert.doesNotMatch(signedBlock, /catch|deploy\/fleet\/windows"\), join/);
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
		if (CUSTOMER_KIT_RENDERED_GUIDES.includes(target)) {
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
				inline_mcp_gateway_signature_present: false,
				device_start_ingress_bundled: true,
				privacy_gateway_runtime_bundled: false,
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
	source.inline_mcp_gateway_signature_present = true;
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

test("extracted kit carries the shared credential guard without relying on upstream source", async () => {
	const kit = createKit();
	try {
		const { deploymentCredentialFailures } = await import(pathToFileURL(join(kit, "scripts/lib/deployment-credentials.mjs")).href);
		assert.deepEqual(deploymentCredentialFailures({ ANON_KEY: "sb_publishable_customer_fixture", SERVICE_ROLE_KEY: "sb_secret_customer_fixture" }), []);
		assert.deepEqual(deploymentCredentialFailures({ ANON_KEY: "REPLACE_WITH_PROJECT_ANON_KEY", SERVICE_ROLE_KEY: "sb_secret_customer_fixture" }), ["ANON_KEY"]);
		const { cpSync } = await import(pathToFileURL(join(kit, "scripts/lib/deployment-input-copy.mjs")).href);
		const copied = join(kit, "copied-recovery-template.html");
		cpSync(join(kit, "supabase/templates/recovery.html"), copied);
		assert.deepEqual(readFileSync(copied), readFileSync(join(kit, "supabase/templates/recovery.html")));
	} finally {
		rmSync(kit, { recursive: true, force: true });
	}
});

test("extracted kit carries the real authentication helper and recovery template required by both preparation modes", async () => {
	const kit = createKit();
	try {
		const saml = await import(pathToFileURL(join(kit, "deploy/saml-config.mjs")).href);
		assert.deepEqual(saml.parseSamlRuntimeConfig({ domain: "customer.example" }), { samlDomain: "customer.example" });
		assert.deepEqual(saml.parseOidcRuntimeConfig("true"), { oidcSso: true });
		assert.equal(readFileSync(join(kit, "supabase/templates/recovery.html"), "utf8"), readFileSync(join(repoRoot, "supabase/templates/recovery.html"), "utf8"));
		const assembler = readFileSync(join(repoRoot, "scripts/customer-kit.mjs"), "utf8");
		assert.match(assembler, /"deploy\/saml-config\.mjs"/);
		assert.match(assembler, /"supabase\/templates"/);
	} finally { rmSync(kit, { recursive: true, force: true }); }
});

test("extracted kit guides contain only resolvable local links", () => {
	const kit = createKit();
	try {
		assert.equal(run(kit).status, 0);
		const guide = join(kit, "START-HERE.md");
		assert.match(readFileSync(guide, "utf8"), /\]\(RETENTION-HOLDS\.md#releasing-a-hold-after-offboarding-starts\)/);
		const holdRunbook = readFileSync(join(kit, "RETENTION-HOLDS.md"), "utf8");
		assert.equal(holdRunbook, readFileSync(join(repoRoot, "docs/production-readiness/retention-holds.md"), "utf8"));
		assert.match(holdRunbook, /^### Releasing a hold after offboarding starts$/m);
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

test("a regenerated checksum inventory cannot omit the installer, doctor or hold runbook", () => {
	for (const missing of ["scripts/deployment-prepare.mjs", "scripts/deployment-doctor.mjs", "scripts/lib/deployment-credentials.mjs", "scripts/lib/deployment-input-copy.mjs", "deploy/saml-config.mjs", "supabase/templates/recovery.html", "RETENTION-HOLDS.md", "SAML-RECOVERY.md", "scripts/saml-outage-recovery.mjs", "RESPONSE-PLAYBOOKS.md", "CLOUD-DISCOVERY.md", "BEHAVIORAL-LEARNING.md", "PACKAGE-INSTALLATION.md"]) {
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

test("a gateway declared signed requires its detached artifact signature", () => {
	const kit = createKit();
	try {
		addSignedGateway(kit);
		assert.equal(run(kit).status, 0);
		unlinkSync(join(kit, "deploy", "gateway", "aidr-artifact.manifest.sig"));
		writeChecksums(kit);
		const result = run(kit);
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /MCP gateway signature status does not match bundled runtime/);
	} finally {
		rmSync(kit, { recursive: true, force: true });
	}
});

test("unsigned gateway preparation remains explicit and cannot become a signed kit", () => {
	const kit = createKit();
	try {
		addSignedGateway(kit);
		unlinkSync(join(kit, "deploy/gateway/aidr-artifact.manifest.sig"));
		const sourceFile = join(kit, "release-source.json");
		const source = JSON.parse(readFileSync(sourceFile, "utf8"));
		source.inline_mcp_gateway_signature_present = false;
		writeFileSync(sourceFile, JSON.stringify(source));
		writeChecksums(kit);
		const result = run(kit);
		assert.equal(result.status, 0, result.stderr);
		const summary = JSON.parse(result.stdout.trim());
		assert.equal(summary.inline_mcp_gateway_signature, "absent");
		assert.equal(summary.publisher_authenticated, false);
		source.release_signed = true;
		writeFileSync(sourceFile, JSON.stringify(source));
		writeChecksums(kit);
		for (const rejected of [run(kit), runSourceVerifier(kit)]) {
			assert.notEqual(rejected.status, 0);
			assert.match(rejected.stderr, /gateway.*signature|signature.*runtime/i);
		}
	} finally { rmSync(kit, { recursive: true, force: true }); }
});

test("portable operations and native acceptance assets cannot be omitted with regenerated checksums", () => {
	for (const missing of ["RELEASE-SIGNING.md", "scripts/verify-support-ticket-drill.mjs", "deploy/native/README.md", "deploy/operations/operations.env.example", "deploy/operations/workload.soak-8h.example.json", "deploy/operations/support-ticket.receipt.example.json", "deploy/native/support-matrix.schema.json", "deploy/native/scenarios/TEMPLATE.json", "deploy/native/scenarios/README.md"]) {
		const kit = createKit();
		try {
			unlinkSync(join(kit, missing));
			writeChecksums(kit);
			assert.match(run(kit).stderr, /Required customer acceptance artifact is missing/);
		} finally { rmSync(kit, { recursive: true, force: true }); }
	}
});

test("documented support receipt validator runs from the extracted kit and rejects the unoperated template", () => {
	const kit = createKit();
	try {
		assert.match(readFileSync(join(kit, "deploy/operations/PORTABLE-LINUX.md"), "utf8"), /node scripts\/verify-support-ticket-drill\.mjs/);
		const result = spawnSync(process.execPath, [join(kit, "scripts/verify-support-ticket-drill.mjs"), join(kit, "deploy/operations/support-ticket.receipt.example.json"), "--candidate", "a".repeat(64)], { cwd: kit, env: { PATH: "" }, encoding: "utf8", windowsHide: true });
		assert.equal(result.status, 1);
		assert.match(result.stderr, /operated ticket system|named.*operators|candidate digest/);
		assert.doesNotMatch(result.stderr, /MODULE_NOT_FOUND|ENOENT/);
	} finally { rmSync(kit, { recursive: true, force: true }); }
});

test("portable native assets clearly leave interception source checking in the separate checkout", () => {
	const kit = createKit();
	try {
		assert.match(readFileSync(join(kit, "deploy/native/README.md"), "utf8"), /complete frozen source[\s\S]*checker is intentionally absent/);
		assert.equal(existsSync(join(kit, "deploy/native/verify-interception-matrix.mjs")), false);
		const assembler = readFileSync(join(repoRoot, "scripts/customer-kit.mjs"), "utf8");
		assert.doesNotMatch(assembler, /"deploy\/native"|"deploy\/native\/verify-interception-matrix\.mjs"/);
	} finally { rmSync(kit, { recursive: true, force: true }); }
});

test("extracted kit resolves the real native scenario template without claiming host acceptance", () => {
	const kit = createKit();
	const reportPath = `${kit}.validation.json`;
	try {
		const result = spawnSync(process.execPath, [join(kit, "scripts/verify-native-host-matrix-v6.mjs"), "--validate-only", "--scenario-file", join(kit, "deploy/native/scenarios/TEMPLATE.json"), "--output", reportPath], { cwd: kit, env: { PATH: "" }, encoding: "utf8", windowsHide: true });
		assert.equal(result.status, 0, result.stderr);
		const report = JSON.parse(readFileSync(reportPath, "utf8"));
		assert.equal(report.template, true);
		assert.notEqual(report.status, "PASS");
	} finally { rmSync(reportPath, { force: true }); rmSync(kit, { recursive: true, force: true }); }
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

// --- Optional privacy gateway --------------------------------------------------------

const privacyRuntimeBuilt = existsSync(join(repoRoot, "packages/privacy/dist/platform/serve.js"));

function setReleaseSource(kit, patch) {
	const path = join(kit, "release-source.json");
	writeFileSync(path, `${JSON.stringify({ ...JSON.parse(readFileSync(path, "utf8")), ...patch }, null, 2)}\n`);
}

function addPrivacyRuntime(kit) {
	for (const relative of privacyGatewayPackageEntries(repoRoot)) {
		const target = join(kit, "packages/privacy", relative);
		mkdirSync(resolve(target, ".."), { recursive: true });
		copyFileSync(join(repoRoot, "packages/privacy", relative), target);
	}
	setReleaseSource(kit, { privacy_gateway_runtime_bundled: true });
	writeChecksums(kit);
}

test("the kit contract pins the privacy gateway definition and runtime to the staging module", () => {
	assert.deepEqual([...CUSTOMER_KIT_PRIVACY_GATEWAY_FILES], [...PRIVACY_GATEWAY_DEFINITION_FILES]);
	assert.deepEqual([...CUSTOMER_KIT_PRIVACY_GATEWAY_RUNTIME], PRIVACY_GATEWAY_REQUIRED_RUNTIME.map((path) => `packages/privacy/${path}`));
	for (const path of CUSTOMER_KIT_PRIVACY_GATEWAY_FILES) assert.ok(CUSTOMER_KIT_REQUIRED_FILES.includes(path), path);
	const assembler = readFileSync(join(repoRoot, "scripts", "customer-kit.mjs"), "utf8");
	assert.match(assembler, /for \(const relative of privacyGatewayPackageEntries\(root\)\) copy\(join\(root, "packages\/privacy", relative\)/);
	assert.match(assembler, /privacy_gateway_runtime_bundled: true,/);
});

test("a kit without the privacy gateway runtime passes only when it declares none", () => {
	const kit = createKit();
	try {
		const summary = JSON.parse(run(kit).stdout.trim().split(/\r?\n/).at(-1));
		assert.equal(summary.privacy_gateway_runtime_bundled, false);
		mkdirSync(join(kit, "packages/privacy"), { recursive: true });
		writeFileSync(join(kit, "packages/privacy/package.json"), "{}\n");
		writeChecksums(kit);
		assert.match(run(kit).stderr, /Privacy gateway runtime files are present but release-source declares none/);
		setReleaseSource(kit, { privacy_gateway_runtime_bundled: undefined });
		writeChecksums(kit);
		assert.match(run(kit).stderr, /privacy_gateway_runtime_bundled must be a boolean/);
	} finally {
		rmSync(kit, { recursive: true, force: true });
	}
});

test("a declared privacy gateway runtime must be complete and compiled output only", { skip: privacyRuntimeBuilt ? false : "packages/privacy is not built" }, () => {
	const kit = createKit();
	try {
		addPrivacyRuntime(kit);
		assert.equal(run(kit).status, 0, run(kit).stderr);
		assert.equal(JSON.parse(run(kit).stdout.trim().split(/\r?\n/).at(-1)).privacy_gateway_runtime_bundled, true);
		writeFileSync(join(kit, "packages/privacy/dist/platform/serve.js.map"), "{}\n");
		writeChecksums(kit);
		assert.match(run(kit).stderr, /files outside its compiled package: packages\/privacy\/dist\/platform\/serve\.js\.map/);
		unlinkSync(join(kit, "packages/privacy/dist/platform/serve.js.map"));
		unlinkSync(join(kit, "packages/privacy/deployment/container-service-config.mjs"));
		writeChecksums(kit);
		assert.match(run(kit).stderr, /Privacy gateway runtime is missing: packages\/privacy\/deployment\/container-service-config\.mjs/);
	} finally {
		rmSync(kit, { recursive: true, force: true });
	}
});

test("the kit refuses a privacy gateway image or guide that loses its hardening or honesty", () => {
	const cases = [
		["deploy/privacy-gateway/Dockerfile", (text) => text.replace(/@sha256:[a-f0-9]{64}/, ""), /pinned by digest/],
		["deploy/privacy-gateway/Dockerfile", (text) => text.replace("USER 10001:10001", "USER root"), /numeric non-root user 10001/],
		["deploy/privacy-gateway/Dockerfile", (text) => text.replace(/^HEALTHCHECK .*$/m, ""), /HEALTHCHECK/],
		["deploy/privacy-gateway/Dockerfile", (text) => text.replaceAll("--require-hashes", ""), /hash-pinned Python wheels/],
		["deploy/privacy-gateway/README.md", (text) => text.replaceAll(/not a transparent proxy/gi, "a proxy"), /not a transparent proxy/],
	];
	for (const [path, mutate, expected] of cases) {
		const kit = createKit();
		try {
			writeFileSync(join(kit, path), mutate(readFileSync(join(kit, path), "utf8")));
			writeChecksums(kit);
			const result = run(kit);
			assert.notEqual(result.status, 0, `${path} mutation passed`);
			assert.match(result.stderr, expected);
		} finally {
			rmSync(kit, { recursive: true, force: true });
		}
	}
	const kit = createKit();
	try {
		unlinkSync(join(kit, "deploy/privacy-gateway/privacy-gateway.mjs"));
		writeChecksums(kit);
		assert.match(run(kit).stderr, /Required customer acceptance artifact is missing: deploy\/privacy-gateway\/privacy-gateway\.mjs/);
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
