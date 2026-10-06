import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
	existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync,
	symlinkSync, unlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
	WINDOWS_FLEET_SCRIPTS, consumeWindowsAuthenticodeInputs, prepareWindowsAuthenticodeInputs,
	validateSignedWindowsFleet, validateWindowsAuthenticodeStage,
} from "../.github/scripts/windows-authenticode-inputs.mjs";

const SCRIPT = fileURLToPath(new URL("../.github/scripts/windows-authenticode-inputs.mjs", import.meta.url));
const THUMBPRINT = "A".repeat(40);
const TIMESTAMP = "https://timestamp.example.invalid";
const UNSIGNED_SHA = "b".repeat(64);
const INPUT_PATHS = [
	...WINDOWS_FLEET_SCRIPTS.map((name) => `fleet/${name}`),
	"claude/native/Common.ps1", "claude/native/Invoke-AidrResponseAction.ps1",
].sort();
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const json = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);

function fixture(t) {
	const temporary = mkdtempSync(join(tmpdir(), "aidr-authenticode-"));
	t.after(() => {
		// The only recursively removed directory is this independently allocated test fixture.
		assert.equal(resolve(temporary), temporary);
		assert.ok(temporary.startsWith(`${resolve(tmpdir())}${sep}aidr-authenticode-`));
		rmSync(temporary, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});
	const repoRoot = join(temporary, "repo");
	const fleet = join(repoRoot, "deploy/fleet/windows");
	const native = join(repoRoot, "packages/claude-code/dist/native");
	mkdirSync(fleet, { recursive: true });
	mkdirSync(native, { recursive: true });
	const original = new Map();
	for (const name of WINDOWS_FLEET_SCRIPTS) {
		const bytes = Buffer.from(`# reviewed ${name}\r\nWrite-Output 'fixture'\r\n`);
		original.set(name, bytes);
		writeFileSync(join(fleet, name), bytes);
	}
	for (const name of ["Common.ps1", "Invoke-AidrResponseAction.ps1"])
		writeFileSync(join(native, name), original.get(name));
	writeFileSync(join(repoRoot, ".gitignore"), "packages/claude-code/dist/\n.release-evidence/\n");
	writeFileSync(join(repoRoot, "README.md"), "Reviewed fixture checkout.\n");
	const git = (...args) => execFileSync("git", ["-C", repoRoot, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
	git("init", "--quiet");
	git("config", "core.autocrlf", "false");
	git("add", ".");
	git("-c", "commit.gpgsign=false", "-c", "user.name=AIDR fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "fixture");
	const gitSha = git("rev-parse", "HEAD");
	const options = { repoRoot, stage: join(temporary, "signing-stage"), gitSha,
		unsignedReleaseSha256: UNSIGNED_SHA, thumbprint: THUMBPRINT, timestampServer: TIMESTAMP };
	return { temporary, repoRoot, fleet, native, original, options, git };
}

function signedFixture(t) {
	const f = fixture(t);
	prepareWindowsAuthenticodeInputs(f.options);
	const manifestBytes = readFileSync(join(f.options.stage, "input-manifest.json"));
	const manifest = JSON.parse(manifestBytes);
	const files = [];
	for (const item of manifest.files) {
		const path = join(f.options.stage, item.path);
		// A protected Windows job verifies real Authenticode. These fixtures exercise the transport proof boundary only.
		const signed = Buffer.concat([readFileSync(path), Buffer.from(
			`# SIG # Begin signature block\r\n# fixture ${item.path}\r\n# SIG # End signature block\r\n`)]);
		writeFileSync(path, signed);
		files.push({ ...item, sha256: hash(signed), size: signed.length });
	}
	f.manifest = manifest;
	f.receipt = { schema_version: 1, purpose: "aidr.windows-authenticode", signer_thumbprint: THUMBPRINT,
		timestamp_server: TIMESTAMP, verified_at: "2026-10-06T12:00:00.1234567+00:00", input_manifest_sha256: hash(manifestBytes), verified: true, files };
	f.repinReceipt = () => {
		const bytes = json(f.receipt);
		writeFileSync(join(f.options.stage, "authenticode-receipt.json"), bytes);
		f.options.receiptSha256 = hash(bytes);
	};
	f.repinReceipt();
	return f;
}

function unconsumed(f) {
	assert.equal(existsSync(join(f.repoRoot, ".release-evidence")), false);
	for (const name of ["Common.ps1", "Invoke-AidrResponseAction.ps1"])
		assert.deepEqual(readFileSync(join(f.native, name)), f.original.get(name));
}

test("prepare preserves exact bytes of all 14 reviewed preimages and binds both candidate pins", (t) => {
	const f = fixture(t);
	const result = prepareWindowsAuthenticodeInputs(f.options);
	assert.equal(result.files, 14);
	const bytes = readFileSync(join(f.options.stage, "input-manifest.json"));
	assert.equal(result.input_manifest_sha256, hash(bytes));
	const manifest = JSON.parse(bytes);
	assert.deepEqual(Object.keys(manifest).sort(), ["schema_version", "purpose", "git_sha", "unsigned_release_sha256", "files"].sort());
	assert.equal(manifest.git_sha, f.options.gitSha);
	assert.equal(manifest.unsigned_release_sha256, UNSIGNED_SHA);
	assert.deepEqual(manifest.files.map((item) => item.path).sort(), INPUT_PATHS);
	for (const item of manifest.files) {
		assert.equal(item.before_sha256, hash(f.original.get(basename(item.path))));
		assert.deepEqual(readFileSync(join(f.options.stage, item.path)), f.original.get(basename(item.path)));
	}
	assert.equal(existsSync(join(f.options.stage, "authenticode-receipt.json")), false);
	assert.throws(() => prepareWindowsAuthenticodeInputs(f.options), /stage must be new/);
});

test("consume validates every signed file before copying and persists both proof documents", (t) => {
	const f = signedFixture(t);
	const result = consumeWindowsAuthenticodeInputs(f.options);
	assert.equal(result.verified, true);
	assert.equal(result.files, 14);
	assert.equal(result.receipt_sha256, f.options.receiptSha256);
	assert.deepEqual(readFileSync(result.receipt), readFileSync(join(f.options.stage, "authenticode-receipt.json")));
	assert.deepEqual(readFileSync(result.input_manifest), readFileSync(join(f.options.stage, "input-manifest.json")));
	for (const name of INPUT_PATHS) {
		const target = name.startsWith("fleet/") ? join(result.fleet_root, basename(name)) : join(result.native_root, basename(name));
		assert.deepEqual(readFileSync(target), readFileSync(join(f.options.stage, name)));
	}
	assert.notDeepEqual(readFileSync(join(result.fleet_root, "Common.ps1")), readFileSync(join(result.native_root, "Common.ps1")));
	assert.equal(validateSignedWindowsFleet(f.repoRoot, f.options.receiptSha256, THUMBPRINT), result.fleet_root);
	assert.equal(validateSignedWindowsFleet(f.repoRoot, f.options.receiptSha256, THUMBPRINT.toLowerCase(), TIMESTAMP), result.fleet_root);
});

test("customer-kit helper validates source preimages while permitting unrelated tracked development edits", (t) => {
	const f = signedFixture(t);
	consumeWindowsAuthenticodeInputs(f.options);
	writeFileSync(join(f.repoRoot, "README.md"), "Unrelated development edit.\n");
	assert.equal(validateSignedWindowsFleet(f.repoRoot, f.options.receiptSha256, THUMBPRINT), join(f.repoRoot, ".release-evidence/windows-fleet"));
	writeFileSync(join(f.fleet, "Common.ps1"), "Tampered source.\n");
	assert.throws(() => validateSignedWindowsFleet(f.repoRoot, f.options.receiptSha256, THUMBPRINT), /preimage mismatch/);
});

test("receipt timestamp accepts the real PowerShell DateTimeOffset roundtrip and UTC DateTime format", (t) => {
	const f = signedFixture(t);
	assert.equal(validateWindowsAuthenticodeStage(f.options).receipt.verified_at, "2026-10-06T12:00:00.1234567+00:00");
	f.receipt.verified_at = "2026-10-06T12:00:00.1234567Z";
	f.repinReceipt();
	assert.equal(validateWindowsAuthenticodeStage(f.options).files.size, 14);
});

for (const [name, mutate, pattern] of [
	["missing independent receipt pin", (f) => { delete f.options.receiptSha256; }, /independent Windows receipt/],
	["receipt digest mismatch", (f) => { f.options.receiptSha256 = "c".repeat(64); }, /digest pin mismatch/],
	["wrong protected signer", (f) => { f.options.thumbprint = "B".repeat(40); }, /signer pin mismatch/],
	["wrong protected timestamp server", (f) => { f.options.timestampServer = "https://other.example.invalid"; }, /timestamp server pin mismatch/],
	["wrong reviewed git SHA", (f) => { f.options.gitSha = "a".repeat(40); }, /git SHA/],
	["wrong unsigned archive SHA", (f) => { f.options.unsignedReleaseSha256 = "d".repeat(64); }, /candidate pin mismatch/],
	["unprotected timestamp URL", (f) => { f.options.timestampServer = "http://timestamp.example.invalid"; }, /HTTPS timestamp/],
	["missing signed input", (f) => { unlinkSync(join(f.options.stage, "fleet/Update-Aidr.ps1")); }, /reviewed file set/],
	["extra signed input", (f) => { writeFileSync(join(f.options.stage, "fleet/extra.ps1"), "extra"); }, /reviewed file set/],
	["extra empty stage directory", (f) => { mkdirSync(join(f.options.stage, "extra")); }, /Unexpected input directory/],
	["tampered signed bytes", (f) => { writeFileSync(join(f.options.stage, "fleet/Update-Aidr.ps1"), "tampered"); }, /digest or size mismatch/],
	["dirty reviewed source", (f) => { writeFileSync(join(f.fleet, "Update-Aidr.ps1"), "tampered"); }, /clean tracked source/],
	["extra native destination script", (f) => { writeFileSync(join(f.native, "extra.ps1"), "extra"); }, /Native destination scripts/],
]) {
	test(`consume fails before mutation: ${name}`, (t) => {
		const f = signedFixture(t);
		mutate(f);
		assert.throws(() => consumeWindowsAuthenticodeInputs(f.options), pattern);
		unconsumed(f);
	});
}

for (const [name, mutate, pattern] of [
	["unverified receipt", (f) => { f.receipt.verified = false; }, /Invalid verified Authenticode receipt/],
	["unknown receipt fields", (f) => { f.receipt.fallback = true; }, /Invalid verified Authenticode receipt/],
	["invalid receipt timestamp", (f) => { f.receipt.verified_at = "2026-02-30T12:00:00Z"; }, /Invalid verified Authenticode receipt/],
	["input manifest digest mismatch", (f) => { f.receipt.input_manifest_sha256 = "e".repeat(64); }, /input manifest digest mismatch/],
	["duplicate paths", (f) => { f.receipt.files[0] = { ...f.receipt.files[1] }; }, /reviewed file set/],
	["escaping paths", (f) => { f.receipt.files[0].path = "../outside.ps1"; }, /reviewed file set/],
	["case aliases", (f) => { f.receipt.files[0].path = f.receipt.files[0].path.toUpperCase(); }, /reviewed file set/],
	["incorrect reviewed preimage", (f) => { f.receipt.files[0].before_sha256 = "f".repeat(64); }, /preimage mismatch/],
	["unsigned digest fallback", (f) => { f.receipt.files[0].sha256 = f.receipt.files[0].before_sha256; }, /Invalid or duplicate signed file receipt/],
]) {
	test(`a pinned receipt cannot weaken its schema: ${name}`, (t) => {
		const f = signedFixture(t);
		mutate(f);
		f.repinReceipt();
		assert.throws(() => consumeWindowsAuthenticodeInputs(f.options), pattern);
		unconsumed(f);
	});
}

test("an altered input manifest fails even when a receipt is re-pinned to it", (t) => {
	const f = signedFixture(t);
	f.manifest.files[0].before_sha256 = "f".repeat(64);
	f.receipt.files[0].before_sha256 = "f".repeat(64);
	const manifestBytes = json(f.manifest);
	writeFileSync(join(f.options.stage, "input-manifest.json"), manifestBytes);
	f.receipt.input_manifest_sha256 = hash(manifestBytes);
	f.repinReceipt();
	assert.throws(() => consumeWindowsAuthenticodeInputs(f.options), /preimage mismatch/);
	unconsumed(f);
});

test("changed bytes without an Authenticode block cannot be passed as signed", (t) => {
	const f = signedFixture(t);
	const item = f.receipt.files[0];
	const bytes = Buffer.from("Write-Output 'changed unsigned body'\r\n");
	writeFileSync(join(f.options.stage, item.path), bytes);
	item.sha256 = hash(bytes);
	item.size = bytes.length;
	f.repinReceipt();
	assert.throws(() => consumeWindowsAuthenticodeInputs(f.options), /Unsigned script cannot be consumed/);
	unconsumed(f);
});

test("hardlinked stage inputs are rejected before consumption", (t) => {
	const f = signedFixture(t);
	linkSync(join(f.options.stage, "fleet/Common.ps1"), join(f.temporary, "outside-linked.ps1"));
	assert.throws(() => consumeWindowsAuthenticodeInputs(f.options), /hardlinked input/);
	unconsumed(f);
});

test("junction or symlink stage directories cannot read outside the stage", (t) => {
	const f = signedFixture(t);
	const outside = join(f.temporary, "outside");
	mkdirSync(outside);
	symlinkSync(outside, join(f.options.stage, "linked"), process.platform === "win32" ? "junction" : "dir");
	assert.throws(() => consumeWindowsAuthenticodeInputs(f.options), /Linked input/);
	unconsumed(f);
});

test("hardlinked existing targets are rejected before any validated file is copied", (t) => {
	const f = signedFixture(t);
	linkSync(join(f.native, "Invoke-AidrResponseAction.ps1"), join(f.temporary, "outside-native.ps1"));
	assert.throws(() => consumeWindowsAuthenticodeInputs(f.options), /hardlinked input|Unsafe/);
	unconsumed(f);
});

test("source extra scripts and byte-different generated native helpers fail before staging", (t) => {
	const f = fixture(t);
	writeFileSync(join(f.fleet, "extra.ps1"), "extra");
	assert.throws(() => prepareWindowsAuthenticodeInputs(f.options), /Windows source scripts/);
	assert.equal(existsSync(f.options.stage), false);
	unlinkSync(join(f.fleet, "extra.ps1"));
	writeFileSync(join(f.native, "Common.ps1"), "different\n");
	assert.throws(() => prepareWindowsAuthenticodeInputs(f.options), /native preimage differs/);
	assert.equal(existsSync(f.options.stage), false);
});

test("bounded inputs reject oversized scripts and oversized proof metadata", (t) => {
	const f = signedFixture(t);
	const path = join(f.options.stage, "fleet/Common.ps1");
	const signed = readFileSync(path);
	writeFileSync(path, Buffer.alloc(1024 * 1024 + 1, 65));
	assert.throws(() => consumeWindowsAuthenticodeInputs(f.options), /oversized regular file/);
	writeFileSync(path, signed);
	writeFileSync(join(f.options.stage, "authenticode-receipt.json"), Buffer.alloc(64 * 1024 + 1, 32));
	assert.throws(() => consumeWindowsAuthenticodeInputs(f.options), /oversized regular file/);
	unconsumed(f);
});

test("customer-kit has no unsigned source fallback and revalidates signed native bytes", (t) => {
	const f = signedFixture(t);
	assert.throws(() => validateSignedWindowsFleet(f.repoRoot, f.options.receiptSha256, THUMBPRINT), /ENOENT/);
	consumeWindowsAuthenticodeInputs(f.options);
	assert.throws(() => validateSignedWindowsFleet(f.repoRoot, "c".repeat(64), THUMBPRINT), /digest pin mismatch/);
	assert.throws(() => validateSignedWindowsFleet(f.repoRoot, f.options.receiptSha256, "B".repeat(40)), /signer pin mismatch/);
	writeFileSync(join(f.native, "Common.ps1"), f.original.get("Common.ps1"));
	assert.throws(() => validateSignedWindowsFleet(f.repoRoot, f.options.receiptSha256, THUMBPRINT), /digest or size mismatch/);
});

test("the CLI accepts protected release pins and reports the exact validated count", (t) => {
	const f = signedFixture(t);
	const args = [SCRIPT, "check", "--stage", f.options.stage, "--repo-root", f.repoRoot, "--git-sha", f.options.gitSha,
		"--unsigned-release-sha256", UNSIGNED_SHA, "--receipt-sha256", f.options.receiptSha256,
		"--thumbprint", THUMBPRINT, "--timestamp-server", TIMESTAMP];
	const result = JSON.parse(execFileSync(process.execPath, args, { encoding: "utf8" }));
	assert.deepEqual(result, { verified: true, files: 14, receipt_sha256: f.options.receiptSha256 });
	assert.throws(() => execFileSync(process.execPath, [SCRIPT, "check", "--stage", f.options.stage], { stdio: "pipe" }));
	unconsumed(f);
});
