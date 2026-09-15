import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { CUSTOMER_KIT_REQUIRED_FILES } from "./customer-kit-contract.mjs";

const repoRoot = resolve(import.meta.dirname, "..");
const verifier = join(repoRoot, "scripts", "customer-kit-verify.mjs");
const aliases = {
	"RESTORE-DRILL.md": "docs/production-readiness/backup-restore-v6.md",
	"NATIVE-HOST-ACCEPTANCE.md": "docs/production-readiness/native-host-matrix-v6.md",
	"SUPPORT-RUNBOOK.md": "docs/runbooks/support-v7.md",
	"FIRST-CUSTOMER-SALES-PACKET.md": "docs/production-readiness/first-customer-sales-packet-v7.md",
	"CANDIDATE-STATUS.md": "docs/production-readiness/2026-09-13-customer-candidate-v7.md",
	"RELEASE-EVIDENCE.md": "docs/release-evidence.md",
};

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
		copyFileSync(sourcePath, destination);
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
