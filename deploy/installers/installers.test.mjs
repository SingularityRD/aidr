// Desktop installer builders: input contracts, the Linux package layout and
// the maintainer-hook behaviour, run against temporary roots and fake homes.
// The bundle here is a small stand-in for the release-flavour SEA directory
// (the real one is one ~120 MB multi-call binary plus rules), signed with a
// test release key; its `aidr` is a shell script that records how it was
// called, so the tests prove WHO the hook runs setup/uninstall for, never
// touching a real HOME.
//
//   node --test deploy/installers/installers.test.mjs

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
	chmodSync,
	chownSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	readlinkSync,
	rmSync,
	statSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { after, describe, test } from "node:test";
import {
	signDistribution,
	writeDistributionManifest,
	writeRuntimeManifest,
} from "../../packages/claude-code/scripts/build-sea.mjs";
import {
	CUSTOMER_PACKET_MAX_BYTES,
	checkCustomerPacket,
	checkSeaBundle,
	checkTrustKey,
	checkVersion,
	customerArtifactName,
	InstallerInputError,
	LINUX_CUSTOMER_PACKET,
} from "./lib/common.mjs";
import {
	ASSISTANT_DESKTOP,
	buildLinuxPackages,
	DEB_POSTINST,
	DEB_PRERM,
	debConffiles,
	packageVersion,
	rpmSpec,
} from "./linux/build-linux-packages.mjs";
import { MSI_CULTURES, msiInputs, WIZARD_URL_PATTERN, wizardCustomerName } from "./windows/msi-inputs.mjs";
import { bmpInfo, renderSvgToBmp, WIZARD_BITMAPS } from "./windows/ui/render-bitmaps.mjs";
import { EULA_PAGES, renderEulaRtf } from "./windows/ui/render-eula.mjs";

const scratch = [];
after(() => {
	for (const dir of scratch) rmSync(dir, { recursive: true, force: true });
});
function tempDir(label) {
	const dir = mkdtempSync(join(tmpdir(), `aidr-installers-${label}-`));
	chmodSync(dir, 0o755);
	scratch.push(dir);
	return dir;
}
const have = (tool) => spawnSync("sh", ["-c", `command -v ${tool}`]).status === 0;

function trustKey() {
	const dir = tempDir("key");
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	const path = join(dir, "release-public.pem");
	writeFileSync(path, publicKey.export({ type: "spki", format: "pem" }));
	const privatePath = join(dir, "private.pem");
	writeFileSync(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }));
	const fingerprint = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
	return { path, privatePath, fingerprint };
}

/** The fake `aidr`: append "<uid> HOME=<home> OP=<noninteractive> <args>" to $HOME/aidr-calls.log. */
const FAKE_AIDR = `#!/bin/sh
printf '%s HOME=%s OP=%s %s\\n' "$(id -u)" "$HOME" "\${AIDR_OPERATOR_NONINTERACTIVE:-}" "$*" >> "$HOME/aidr-calls.log"
[ "$1" != "--version" ] || echo 0.0.0-test
[ "$1" != "setup" ] || exit "\${FAKE_AIDR_SETUP_EXIT:-0}"
exit 0
`;

/** The release key every fake bundle is signed with (tests pass its public half as the trust key). */
const releaseKey = trustKey();

function fakeSeaBundle({ platform = "linux", arch = "x64", flavor = "release", key = releaseKey } = {}) {
	const dir = tempDir(`sea-${platform}`);
	const exe = platform === "win32" ? ".exe" : "";
	for (const sub of ["bin", "dist/resources/threats", "dist/resources/allowlists"]) mkdirSync(join(dir, sub), { recursive: true });
	writeFileSync(join(dir, "dist/resources/threats/rules.yaml"), "- id: TEST-1\n");
	writeFileSync(join(dir, "dist/resources/allowlists/domains.yaml"), "domains: []\n");
	writeFileSync(join(dir, "dist/response-worker.cjs"), "");
	writeFileSync(join(dir, "bin", `aidr${exe}`), FAKE_AIDR, { mode: 0o755 });
	const createdAt = "2026-01-01T00:00:00.000Z";
	writeRuntimeManifest(dir, { version: "0.6.0", createdAt });
	writeDistributionManifest(dir, { version: "0.6.0", platform, arch, nodeVersion: "v22.0.0", flavor, createdAt });
	if (key) signDistribution(dir, { privateKeyPem: readFileSync(key.privatePath, "utf8") });
	return dir;
}
const releasePem = () => readFileSync(releaseKey.path, "utf8");

describe("installer inputs", () => {
	test("the trust key must be the Ed25519 public key with the expected fingerprint", () => {
		const key = trustKey();
		assert.equal(checkTrustKey(key.path, key.fingerprint).fingerprint, key.fingerprint);
		assert.equal(checkTrustKey(key.path, `sha256:${key.fingerprint.toUpperCase()}`).fingerprint, key.fingerprint);
		assert.throws(() => checkTrustKey(key.path, "0".repeat(64)), /fingerprint mismatch/);
		assert.throws(() => checkTrustKey(key.path, ""), /fingerprint is required/);
		assert.throws(() => checkTrustKey(key.privatePath, key.fingerprint), /private key/);
		const rsa = join(tempDir("rsa"), "rsa.pem");
		writeFileSync(rsa, generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "pem" }));
		assert.throws(() => checkTrustKey(rsa, key.fingerprint), /must be Ed25519/);
	});

	test("versions are release or prerelease semver only", () => {
		assert.equal(checkVersion("0.6.0"), "0.6.0");
		assert.equal(checkVersion("0.6.0-rc.2"), "0.6.0-rc.2");
		for (const bad of ["v0.6.0", "0.6", "0.6.0;rm", "", undefined]) assert.throws(() => checkVersion(bad), InstallerInputError);
		assert.equal(packageVersion("0.6.0-rc.2"), "0.6.0~rc.2");
	});

	test("a tampered, foreign-platform or incomplete SEA bundle is refused", () => {
		const trustKeyPem = releasePem();
		const linux = fakeSeaBundle();
		assert.equal(checkSeaBundle(linux, { platform: "linux", trustKeyPem }).artifact_id, "claude-code/sea");
		assert.throws(() => checkSeaBundle(linux, { platform: "win32", trustKeyPem }), /built for linux, not win32/);
		writeFileSync(join(linux, "bin", "aidr"), "tampered");
		assert.throws(() => checkSeaBundle(linux, { platform: "linux", trustKeyPem }), /does not match its manifest digest/);
		const incomplete = fakeSeaBundle();
		rmSync(join(incomplete, "bin", "aidr"));
		writeDistributionManifest(incomplete, { version: "0.6.0", platform: "linux", arch: "x64", flavor: "release" });
		assert.throws(() => checkSeaBundle(incomplete, { platform: "linux", trustKeyPem }), /bin\/aidr/);
	});

	test("only a release-flavour bundle signed by the embedded release key is packaged", () => {
		const trustKeyPem = releasePem();
		assert.throws(() => checkSeaBundle(fakeSeaBundle({ flavor: "development" }), { platform: "linux", trustKeyPem }), /development-flavour build; installers ship the release flavour/);
		assert.throws(() => checkSeaBundle(fakeSeaBundle({ key: null }), { platform: "linux", trustKeyPem }), /not signed by the release key[\s\S]*is not signed/);
		assert.throws(() => checkSeaBundle(fakeSeaBundle({ key: trustKey() }), { platform: "linux", trustKeyPem }), /signature does not verify against the release key/);
		const key = trustKey();
		const out = tempDir("out-unsigned");
		assert.throws(
			() => buildLinuxPackages({ seaDir: fakeSeaBundle(), trustKey: key.path, trustKeyFingerprint: key.fingerprint, version: "0.6.0", out, formats: "tar" }),
			/not signed by the release key/,
		);
	});
});

// --- WiX source helpers (structural checks; WiX itself runs on the Windows release job) ---
const windowsFile = (path) => readFileSync(new URL(`./windows/${path}`, import.meta.url), "utf8");
const repoFile = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), "utf8");
/** Body of the first <tag>...</tag> element. */
function sequence(xml, tag) {
	const match = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`).exec(xml);
	assert.ok(match, `no <${tag}>`);
	return match[1];
}
/** Attributes of a start tag, XML entities decoded. */
function attrs(tag) {
	const out = {};
	for (const m of tag.matchAll(/([A-Za-z][\w:-]*)=(?:"([^"]*)"|'([^']*)')/g)) {
		out[m[1]] = (m[2] ?? m[3]).replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
	}
	return out;
}
/** Attributes of the element `<name ... Id="id" ...>`. */
function element(xml, name, id) {
	const match = new RegExp(`<${name}\\b[^>]*\\bId="${id}"[^>]*>`).exec(xml);
	assert.ok(match, `no <${name} Id="${id}">`);
	return attrs(match[0]);
}
function wxlStrings(culture) {
	const xml = windowsFile(`ui/aidr.${culture}.wxl`);
	const root = attrs(/<WixLocalization\b[^>]*>/.exec(xml)[0]);
	const strings = new Map();
	for (const m of xml.matchAll(/<String\b[^>]*>/g)) {
		const { Id, Value } = attrs(m[0]);
		assert.ok(!strings.has(Id), `${culture}: duplicate ${Id}`);
		strings.set(Id, Value);
	}
	return { root, strings };
}
/** Characters a Windows ANSI code page can encode. */
function codepageChars(codepage) {
	return new Set(new TextDecoder(`windows-${codepage}`).decode(Uint8Array.from({ length: 256 }, (_, i) => i)));
}

describe("Windows MSI inputs", () => {
	test("derive the MSI variables from a verified win32 bundle and mark unsigned builds", () => {
		const key = releaseKey;
		const sea = fakeSeaBundle({ platform: "win32" });
		const signed = msiInputs({ seaDir: sea, trustKey: key.path, trustKeyFingerprint: key.fingerprint, version: "0.6.0-rc.3", signing: "signed" });
		assert.equal(signed.productVersion, "0.6.0");
		assert.equal(signed.activeSetupVersion, "0,6,0");
		assert.equal(signed.outputName, "singularity-aidr-0.6.0-rc.3-windows-x64.msi");
		const unsigned = msiInputs({ seaDir: sea, trustKey: key.path, trustKeyFingerprint: key.fingerprint, version: "0.6.0", signing: "unsigned" });
		assert.match(unsigned.outputName, /-UNSIGNED\.msi$/);
		// A new ProductCode per build (WiX's default before), shared by every culture of that build.
		assert.match(signed.productCode, /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/);
		assert.notEqual(signed.productCode, unsigned.productCode);
		assert.deepEqual(signed.cultures, MSI_CULTURES.map((culture) => ({ ...culture, customerName: null })));
		assert.equal(signed.customerServer, null);
		assert.equal(signed.customerUpdatesUntil, null);
		assert.throws(() => msiInputs({ seaDir: sea, trustKey: key.path, trustKeyFingerprint: key.fingerprint, version: "0.6.0", signing: "" }), /--signing/);
		assert.throws(() => msiInputs({ seaDir: fakeSeaBundle(), trustKey: key.path, trustKeyFingerprint: key.fingerprint, version: "0.6.0", signing: "signed" }), /not win32/);
		assert.throws(() => msiInputs({ seaDir: sea, trustKey: key.path, trustKeyFingerprint: "1".repeat(64), version: "0.6.0", signing: "signed" }), /fingerprint mismatch/);
	});

	test("the WiX source runs setup for the interactive user only and uninstall before removal", () => {
		const wxs = readFileSync(new URL("./windows/aidr.wxs", import.meta.url), "utf8");
		assert.match(wxs, /Scope="perUserOrMachine"/);
		assert.match(wxs, /<CustomAction Id="AidrSetupForUser"[\s\S]*?ExeCommand="setup"[\s\S]*?Impersonate="yes"/);
		// Never as LocalSystem: every action of the execute sequence (setup,
		// uninstall and the company-connection handoff) is guarded on the SYSTEM SID.
		// Two deliberate exceptions: the machine-hooks actions write system-wide
		// policy, run elevated (Impersonate="no") and must also run under an
		// Intune/SCCM install in the system context; the profile-cleanup
		// registration runs as LocalSystem and only writes HKLM (asserted in the
		// machine-wide removal test below). Neither runs anything for a user.
		const customs = [...sequence(wxs, "InstallExecuteSequence").matchAll(/<Custom\b[^>]*>/g)]
			.map((m) => m[0])
			.filter((custom) => !/Action="AidrMachineHooks/.test(custom) && !/ProfileCleanup"/.test(custom));
		assert.equal(customs.length, 6);
		for (const custom of customs) assert.match(custom, /UserSID &lt;&gt; &quot;S-1-5-18&quot;/, custom);
		assert.match(wxs, /AIDR_OPERATOR_NONINTERACTIVE=1&amp;&amp; &quot;\[#AidrExe\]&quot; uninstall --yes --keep-data/);
		assert.match(wxs, /Action="AidrUninstallForUser" Before="RemoveFiles"[\s\S]*?NOT UPGRADINGPRODUCTCODE/);
		assert.match(wxs, /Active Setup\\Installed Components/);
		assert.match(wxs, /Name="release-public.pem"/);
		// A device-managed install marks itself for `aidr update` (HKLM policy value).
		assert.match(wxs, /<Property Id="AIDR_MDM_MANAGED" Secure="yes" \/>/);
		assert.match(wxs, /Condition="ALLUSERS=1 AND AIDR_MDM_MANAGED=1"[\s\S]*?Key="Software\\Policies\\Singularity AIDR" Name="MdmManaged" Type="integer" Value="1"/);
		assert.match(wxs, /<ComponentRef Id="MdmManagedMarker" \/>/);
		// Machine policy: one HKLM value per contract key, per-machine only, never dropped by an upgrade.
		const coreSource = readFileSync(new URL("../../packages/core/src/machine-policy.ts", import.meta.url), "utf8");
		const schemaBody = /const MachinePolicySchema = z\s*\.object\(\{([\s\S]*?)\n\t\}\)/.exec(coreSource)[1];
		// protection_locked is a DWORD written by the ProtectionLocked component (AIDR_PROTECTION_LOCKED).
		const contractKeys = [...schemaBody.matchAll(/^\t\t(\w+):/gm)].map((m) => m[1]).filter((key) => key !== "protection_locked").sort();
		const policyValues = [...wxs.matchAll(/<Component Id="AidrPolicy\w+" Directory="INSTALLFOLDER" Condition="ALLUSERS=1 AND (AIDR_POLICY_\w+)"[^>]*>\s*<RegistryValue Root="HKLM" Key="Software\\Policies\\Singularity AIDR" Name="(\w+)" Type="string" Value="\[(AIDR_POLICY_\w+)\]" KeyPath="yes" \/>/g)];
		assert.deepEqual(policyValues.map((m) => m[2]).sort(), contractKeys);
		const hook = readFileSync(new URL("./linux/package-hook.sh", import.meta.url), "utf8");
		for (const [, condition, name, value] of policyValues) {
			assert.equal(condition, value, name);
			assert.match(wxs, new RegExp(`<Property Id="${value}" Secure="yes"( Hidden="yes")? />`), value);
			assert.match(wxs, new RegExp(`<SetProperty Id="${value}" Value="\\[${value}_SAVED\\]" After="AppSearch" Sequence="both"\\s+Condition="NOT ${value} AND ${value}_SAVED" />`), `${value} is remembered`);
			assert.match(wxs, new RegExp(`<Property Id="${value}_SAVED"[^>]*>\\s*<RegistrySearch [^>]*Root="HKLM" Key="Software\\\\Policies\\\\Singularity AIDR" Name="${name}"`), `${value} is read back`);
			assert.match(wxs, new RegExp(`<ComponentRef Id="AidrPolicy\\w+" />`));
			// The Linux package hook takes the same variables.
			assert.ok(hook.includes(value) || hook.includes(value.replace("AIDR_POLICY_", "")), `${value} in package-hook.sh`);
		}
		assert.match(wxs, /<Property Id="AIDR_POLICY_ENROLLMENT_KEY" Secure="yes" Hidden="yes" \/>/);
		assert.match(wxs, /<Property Id="AIDR_POLICY_ENROLLMENT_KEY_SAVED" Hidden="yes">/);
		// A SYSTEM install turns its company address (and a fleet key) into the machine policy.
		assert.match(wxs, /Action="AidrPolicyFromEnrollmentUrl" Value="\[ENROLLMENT_URL\]"[^>]*Condition="ALLUSERS=1 AND UserSID = &quot;S-1-5-18&quot; AND ENROLLMENT_URL AND NOT AIDR_POLICY_CONTROL_PLANE_URL"/);
		assert.match(wxs, /Action="AidrPolicyFromEnrollmentCode" Value="\[ENROLLMENT_CODE\]"[^>]*ENROLLMENT_CODE &lt;&lt; &quot;aidr_fleet_&quot;/);
		const ps1 = readFileSync(new URL("./windows/build-msi.ps1", import.meta.url), "utf8").replace(/\r\n/g, "\n");
		assert.match(ps1, /Pass -SignThumbprint for a release build or -Unsigned for a local build/);
		assert.match(ps1, /--remanifest/);
		assert.match(ps1, /'verify', '\/pa', \$msi/);
	});

	test("final removal cleans every other profile at its next sign-in, as that user, never by editing profiles as SYSTEM", () => {
		const wxs = readFileSync(new URL("./windows/aidr.wxs", import.meta.url), "utf8");
		const execute = sequence(wxs, "InstallExecuteSequence");
		const removal = 'REMOVE=&quot;ALL&quot; AND NOT UPGRADINGPRODUCTCODE AND ALLUSERS=1';
		assert.match(execute, new RegExp(`<Custom Action="AidrRegisterProfileCleanup" After="AidrUninstallForUser"\\s+Condition="${removal}" />`), "final per-machine removal only, after the uninstalling user's own `aidr uninstall`");
		assert.match(execute, new RegExp(`<Custom Action="AidrPrepareProfileCleanup" Before="AidrRegisterProfileCleanup"\\s+Condition="${removal}" />`));
		assert.match(execute, /<Custom Action="AidrUnregisterProfileCleanup" After="InstallInitialize"\s+Condition="NOT REMOVE AND ALLUSERS=1" \/>/, "a reinstall removes the cleanup registration");
		assert.match(wxs, /<CustomAction Id="AidrRegisterProfileCleanup"[\s\S]*?DllEntry="RegisterProfileCleanup"[\s\S]*?Impersonate="no"[\s\S]*?Return="ignore"/);
		assert.match(wxs, /Value="install=\[INSTALLFOLDER\];system=\[System64Folder\]"/);
		// The script stays after removal and is the signed staged copy.
		assert.match(wxs, /<Component Id="ProfileCleanupScript" Directory="CLEANUPDIR" Condition="ALLUSERS=1" Permanent="yes"[\s\S]*?Source="\$\(var\.ProfileCleanupScript\)" Name="Remove-AidrUserRegistrations\.ps1"/);
		assert.match(wxs, /<ComponentRef Id="ProfileCleanupScript" \/>/);
		const ps1 = readFileSync(new URL("./windows/build-msi.ps1", import.meta.url), "utf8").replace(/\r\n/g, "\n");
		assert.ok(ps1.indexOf("Invoke-AidrAuthenticodeSign -Signer $Signer -Files @($profileCleanup)") < ps1.indexOf("'-d', \"ProfileCleanupScript=$profileCleanup\""), "signed before it is packaged");
		// The LocalSystem action writes one HKLM Active Setup key; it never opens a file.
		const ca = readFileSync(new URL("./windows/ca/ProfileCleanupActions.cs", import.meta.url), "utf8");
		assert.match(ca, /RegistryHive\.LocalMachine/);
		assert.doesNotMatch(ca, /\bFile\.|\bDirectory\.|FileStream|Process\.Start|RegistryHive\.Users|CurrentUser/);
		assert.match(ca, /-ExecutionPolicy RemoteSigned -File/);
		// The script runs as the signed-in user, edits only that user's files and only AIDR's entries.
		const cleanup = readFileSync(new URL("./windows/Remove-AidrUserRegistrations.ps1", import.meta.url), "utf8");
		assert.match(cleanup, /\$Marker = 'Singularity AIDR managed installation'/);
		assert.match(cleanup, /\$CodexHook = '\\baidr-codex-hook\\b'/);
		assert.match(cleanup, /LocalSystemSid[\s\S]*?never as SYSTEM/);
		assert.match(cleanup, /'bundle\\bin\\aidr\.exe'[\s\S]*?nothing to clean up/, "a reinstalled AIDR owns its registrations");
		assert.match(cleanup, /ReparsePoint/);
		assert.match(cleanup, /changed while it was read; left unchanged/);
		assert.doesNotMatch(cleanup, /HKLM|Registry::|Set-ItemProperty|Remove-Item -Recurse/);
		const docs = readFileSync(new URL("../../docs/installation/desktop-installers.md", import.meta.url), "utf8");
		assert.doesNotMatch(docs, /Other users of the machine who ran `aidr setup` must run `aidr uninstall`\s+before the package is removed/);
	});
});

describe("Windows MSI install wizard", () => {
	const wxs = windowsFile("aidr.wxs");
	const ui = windowsFile("ui/AidrUI.wxs");
	const en = wxlStrings("en-US");
	const tr = wxlStrings("tr-TR");

	test("every wizard string has an English and a Turkish entry, in the culture's code page", () => {
		assert.equal(en.root.Culture, "en-US");
		assert.equal(en.root.Codepage, "1252");
		assert.equal(tr.root.Culture, "tr-TR");
		assert.equal(tr.root.Codepage, "1254");
		assert.deepEqual([...tr.strings.keys()].sort(), [...en.strings.keys()].sort());
		const used = new Set([...`${wxs}\n${ui}`.matchAll(/!\(loc\.(\w+)\)/g)].map((m) => m[1]));
		const stock = new Set(["WixUIBack", "WixUINext", "WixUICancel", "WixUIFinish", "WixUIOK"]);
		for (const id of used) {
			if (stock.has(id)) continue;
			assert.ok(en.strings.get(id), `en-US has no ${id}`);
			assert.ok(tr.strings.get(id), `tr-TR has no ${id}`);
		}
		for (const id of en.strings.keys()) assert.ok(used.has(id), `${id} is never used`);
		const cp1252 = codepageChars(1252);
		const cp1254 = codepageChars(1254);
		for (const [id, value] of en.strings) for (const ch of value) assert.ok(cp1252.has(ch), `en-US ${id}: ${ch}`);
		for (const [id, value] of tr.strings) {
			for (const ch of value) assert.ok(cp1254.has(ch), `tr-TR ${id}: ${ch}`);
			// Translated, not copied (the language number aside).
			if (!/^\d+$/.test(value)) assert.notEqual(value, en.strings.get(id), `tr-TR ${id} is the English text`);
			// Plain Turkish, and the brand as written (never Turkish upper case).
			assert.doesNotMatch(value, /\bajan\b|actionId|heuristic|bant dışı|S[Iİ]NGULAR[Iİ]TY|sıngular/u, `tr-TR ${id}`);
		}
		assert.equal(en.strings.get("AidrPackageLanguage"), "1033");
		assert.equal(tr.strings.get("AidrPackageLanguage"), "1055");
		assert.deepEqual(
			MSI_CULTURES.map((c) => [c.culture, c.lcid]),
			[
				["en-US", 1033],
				["tr-TR", 1055],
			],
		);
		// No dialog text is hard-coded: a Text attribute is a loc string, a bitmap or an Edit length limit.
		for (const m of ui.matchAll(/<Control\b[^>]*>/g)) {
			const { Text, Type } = attrs(m[0]);
			if (Text === undefined) continue;
			const allowed =
				/^!\(loc\.\w+\)$/.test(Text) ||
				(Type === "Bitmap" && /^WixUI_Bmp_(Banner|Dialog)$/.test(Text)) ||
				(Type === "Edit" && /^\{\d+\}$/.test(Text));
			assert.ok(allowed, `hard-coded text: ${m[0]}`);
		}
	});

	test("the company connection never logs or passes the enrollment code in clear", () => {
		assert.deepEqual(element(wxs, "Property", "ENROLLMENT_CODE"), { Id: "ENROLLMENT_CODE", Secure: "yes", Hidden: "yes" });
		assert.deepEqual(element(wxs, "Property", "ENROLLMENT_URL"), { Id: "ENROLLMENT_URL", Secure: "yes" });
		// The CustomActionData that carries it is hidden too, and so is the action setting it.
		assert.equal(element(wxs, "Property", "AidrWriteEnrollmentHandoff").Hidden, "yes");
		const prepare = element(wxs, "CustomAction", "AidrPrepareEnrollmentHandoff");
		assert.equal(prepare.Property, "AidrWriteEnrollmentHandoff");
		assert.equal(prepare.HideTarget, "yes");
		const write = element(wxs, "CustomAction", "AidrWriteEnrollmentHandoff");
		assert.deepEqual(
			[write.Execute, write.Impersonate, write.HideTarget, write.DllEntry],
			["deferred", "yes", "yes", "WriteEnrollmentHandoff"],
		);
		const rollback = element(wxs, "CustomAction", "AidrRollbackEnrollmentHandoff");
		assert.deepEqual([rollback.Execute, rollback.Impersonate, rollback.DllEntry], ["rollback", "yes", "RemoveEnrollmentHandoff"]);
		// Never on a command line: no ExeCommand references the company fields.
		for (const m of `${wxs}${ui}`.matchAll(/ExeCommand="[^"]*"/g)) assert.doesNotMatch(m[0], /ENROLLMENT/);
		// Masked in the wizard.
		const code = attrs(/<Control Id="Code"[^>]*>/.exec(ui)[0]);
		assert.equal(code.Password, "yes");
		assert.equal(code.Property, "ENROLLMENT_CODE");
		// Setup applies it only as the confirmed operator; plain setup otherwise.
		const connect = element(wxs, "CustomAction", "AidrSetupForUserConnect");
		assert.match(connect.ExeCommand, /set AIDR_OPERATOR_NONINTERACTIVE=1&& "\[#AidrExe\]" setup --yes"$/);
		assert.equal(connect.Impersonate, "yes");
		// The C# action and `aidr setup` agree on the format and the file.
		const cs = windowsFile("ca/EnrollmentActions.cs");
		const ts = repoFile("packages/cli/src/utils/installer-enrollment.ts");
		const csConst = (name) => new RegExp(`const string ${name} = @?"([^"]*)"`).exec(cs)[1];
		const tsRegex = (name) => new RegExp(`${name} =\\s*/(.*)/;`).exec(ts)[1].replaceAll("\\/", "/");
		assert.equal(csConst("UrlPattern"), tsRegex("INSTALLER_ENROLLMENT_URL_PATTERN"));
		assert.equal(csConst("CodePattern"), tsRegex("INSTALLER_ENROLLMENT_CODE_PATTERN"));
		assert.ok(ts.includes(`"${csConst("HandoffDirectory")}", "${csConst("HandoffFile")}"`));
		assert.ok(ts.includes(`FORMAT = "${csConst("HandoffFormat")}"`));
		assert.match(cs, /SetAccessRuleProtection\(true, false\)/);
		for (const m of cs.matchAll(/session\.Log\(([^;]*)\);/g)) assert.doesNotMatch(m[1], /\+ code\b|\+ url\b/, "values are never logged");
		// The prefilled company address is the product's default control plane.
		const defaultEndpoint = /DEFAULT_CONTROL_PLANE_ENDPOINT = "([^"]+)"/.exec(repoFile("packages/core/src/clients/control-plane-url.ts"))[1];
		assert.equal(element(ui, "Property", "AIDR_DEFAULT_CONTROL_PLANE").Value, defaultEndpoint);
	});

	test("the Finish page opens the Setup Assistant as the interactive user, never elevated or as SYSTEM", () => {
		assert.deepEqual(element(ui, "CustomAction", "AidrLaunchAssistant"), {
			Id: "AidrLaunchAssistant",
			FileRef: "AidrExe",
			ExeCommand: "assistant",
			Execute: "immediate",
			Return: "asyncNoWait",
		});
		// Only from the wizard's Finish button (the wizard process, not the installation service).
		assert.doesNotMatch(wxs, /AidrLaunchAssistant/);
		assert.equal((ui.match(/Value="AidrLaunchAssistant"/g) ?? []).length, 1);
		const finish = /<Control Id="Finish"[\s\S]*?<\/Control>/.exec(ui)[0];
		const doAction = attrs(/<Publish Event="DoAction" Value="AidrLaunchAssistant"[^>]*>/.exec(finish)[0]);
		assert.match(doAction.Condition, /AIDR_LAUNCH_ASSISTANT = 1/);
		assert.match(doAction.Condition, /NOT MsiRunningElevated/);
		assert.match(doAction.Condition, /NOT Installed/);
		// An elevated wizard hides the checkbox and says how to open it instead.
		const checkbox = attrs(/<Control Id="LaunchAssistant"[^>]*>/.exec(ui)[0]);
		assert.equal(checkbox.Property, "AIDR_LAUNCH_ASSISTANT");
		assert.match(checkbox.HideCondition, /MsiRunningElevated/);
		assert.equal(element(ui, "Property", "AIDR_LAUNCH_ASSISTANT").Value, "1", "checked by default");
		assert.match(en.strings.get("AidrExitLaunchAssistant"), /Open the Singularity AIDR Setup Assistant/);
		assert.match(en.strings.get("AidrExitQuickStart"), /href="\[#AidrQuickStartEn\]">View quick start</);
		assert.match(tr.strings.get("AidrExitQuickStart"), /href="\[#AidrQuickStartTr\]">/);
		assert.match(wxs, /File Id="AidrQuickStartEn"[^>]*quick-start\.en-US\.html/);
		assert.match(wxs, /File Id="AidrQuickStartTr"[^>]*quick-start\.tr-TR\.html/);
	});

	test("a per-machine install deploys the system-wide hooks elevated, and removes them on final uninstall only (C10)", () => {
		const execute = sequence(wxs, "InstallExecuteSequence");
		for (const [id, command] of [
			["AidrMachineHooksInstall", "machine-hooks install --heartbeat"],
			["AidrMachineHooksInstallLocked", "machine-hooks install --heartbeat --lock-other-hooks"],
			["AidrMachineHooksRemove", "machine-hooks remove --heartbeat"],
		]) {
			assert.deepEqual(element(wxs, "CustomAction", id), {
				Id: id,
				FileRef: "AidrExe",
				ExeCommand: command,
				Execute: "deferred",
				Impersonate: "no",
				Return: "ignore",
			});
			const custom = attrs(new RegExp(`<Custom Action="${id}"[^>]*>`).exec(execute)[0]);
			assert.match(custom.Condition, /ALLUSERS=1/, id);
		}
		const remove = attrs(/<Custom Action="AidrMachineHooksRemove"[^>]*>/.exec(execute)[0]);
		assert.match(remove.Condition, /REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE/);
		const install = attrs(/<Custom Action="AidrMachineHooksInstall"[^>]*>/.exec(execute)[0]);
		assert.match(install.Condition, /AIDR_MACHINE_HOOKS <> "0"/);
		assert.equal(element(wxs, "Property", "AIDR_MACHINE_HOOKS").Value, "1");
		const lock = /<Component Id="ProtectionLocked"[\s\S]*?<\/Component>/.exec(wxs)[0];
		assert.match(lock, /Condition="ALLUSERS=1 AND AIDR_PROTECTION_LOCKED=1"/);
		assert.match(lock, /Key="Software\\Policies\\Singularity AIDR" Name="protection_locked" Type="integer" Value="1"/);
	});

	test("a silent install behaves as before: same setup action, no new required property", () => {
		const execute = sequence(wxs, "InstallExecuteSequence");
		const setup = attrs(/<Custom Action="AidrSetupForUser"[^>]*>/.exec(execute)[0]);
		// The original condition, plus "not when the optional company fields are given".
		assert.equal(
			setup.Condition,
			'NOT REMOVE AND NOT AIDR_SKIP_SETUP AND UserSID <> "S-1-5-18" AND NOT ENROLLMENT_URL AND NOT ENROLLMENT_CODE',
		);
		assert.deepEqual(element(wxs, "CustomAction", "AidrSetupForUser"), {
			Id: "AidrSetupForUser",
			FileRef: "AidrExe",
			ExeCommand: "setup",
			Execute: "deferred",
			Impersonate: "yes",
			Return: "ignore",
		});
		// Everything new in the execute sequence runs only when a company field is set.
		for (const action of ["AidrPrepareEnrollmentHandoff", "AidrRollbackEnrollmentHandoff", "AidrWriteEnrollmentHandoff", "AidrSetupForUserConnect"]) {
			const custom = attrs(new RegExp(`<Custom Action="${action}"[^>]*>`).exec(execute)[0]);
			assert.match(custom.Condition, /\(ENROLLMENT_URL OR ENROLLMENT_CODE\)/, action);
			assert.match(custom.Condition, /NOT REMOVE/, action);
		}
		// Public properties a command line may set are optional (no Value means unset).
		for (const id of ["AIDR_SKIP_SETUP", "AIDR_MDM_MANAGED", "ENROLLMENT_URL", "ENROLLMENT_CODE"]) {
			assert.equal(element(wxs, "Property", id).Value, undefined, id);
		}
		// The wizard lives in the UI sequence only and sets the documented command-line properties.
		assert.doesNotMatch(ui, /<InstallExecuteSequence>/);
		for (const m of ui.matchAll(/<SetProperty\b[^>]*>/g)) assert.equal(attrs(m[0]).Sequence, "ui", m[0]);
		const scopeNext = /<Dialog Id="AidrScopeDlg"[\s\S]*?<Control Id="Next"[\s\S]*?<\/Control>/.exec(ui)[0];
		assert.match(scopeNext, /Property="ALLUSERS" Value="2"[^>]*AIDR_SCOPE = "user"/);
		assert.match(scopeNext, /Property="MSIINSTALLPERUSER" Value="1"[^>]*AIDR_SCOPE = "user"/);
		assert.match(scopeNext, /Property="ALLUSERS" Value="1"[^>]*AIDR_SCOPE = "machine"/);
		assert.match(scopeNext, /Property="MSIINSTALLPERUSER" Value="\{\}"[^>]*AIDR_SCOPE = "machine"/);
		assert.match(scopeNext, /Event="SetTargetPath" Value="INSTALLFOLDER"/);
		// Per-machine shows the UAC shield; "local only" clears the company fields at Install.
		assert.match(ui, /<Control Id="Install"[^>]*ElevationShield="yes"[^>]*\s+ShowCondition='AIDR_SCOPE = "machine"'/);
		for (const id of ["Install", "InstallNoShield"]) {
			const button = new RegExp(`<Control Id="${id}"[\\s\\S]*?</Control>`).exec(ui)[0];
			assert.match(button, /Property="ENROLLMENT_CODE" Value="\{\}"[^>]*AIDR_CONNECTION = "local"/, id);
			assert.match(button, /Property="ENROLLMENT_URL" Value="\{\}"[^>]*AIDR_CONNECTION = "local"/, id);
		}
		// One package per build: the ProductCode is per build and shared by both cultures.
		assert.match(wxs, /ProductCode="\$\(var\.ProductCode\)"/);
		assert.match(wxs, /Language="!\(loc\.AidrPackageLanguage\)"/);
		assert.match(wxs, /<UIRef Id="AidrUI" \/>/);
		// Without it the Turkish install (ProductLanguage 1055) would not upgrade an English one.
		assert.match(wxs, /<MajorUpgrade AllowSameVersionUpgrades="yes"\s+IgnoreLanguage="yes"/);
		const ps1 = windowsFile("build-msi.ps1");
		assert.match(ps1, /'-ext', \$WixUiExtension/);
		assert.match(ps1, /\$WixUiExtensionVersion = '5\.0\.2'/);
		assert.match(ps1, /'-culture', \$culture\.culture, '-loc'/);
		assert.match(ps1, /Add-LanguageTransform -Base[\s\S]*Set-PackageLanguages -Msi[\s\S]*Test-LanguageTransforms -Msi[\s\S]*Invoke-AidrAuthenticodeSign -Signer \$Signer -Files @\(\$msi\)/, "the language transforms are embedded before the MSI is signed");
		assert.match(ps1, /render-bitmaps\.mjs'\), '--check'/);
	});

	test("the wizard bitmaps have the exact WiX sizes and are what their SVG sources render to", () => {
		assert.deepEqual(
			WIZARD_BITMAPS.map((b) => [b.width, b.height]),
			[
				[493, 58],
				[493, 312],
			],
		);
		for (const bitmap of WIZARD_BITMAPS) {
			const committed = readFileSync(bitmap.bmp);
			assert.deepEqual(bmpInfo(committed), { width: bitmap.width, height: bitmap.height, bitsPerPixel: 24 });
			assert.ok(renderSvgToBmp(readFileSync(bitmap.svg, "utf8")).equals(committed), `${bitmap.bmp} is stale: run render-bitmaps.mjs`);
		}
		assert.match(wxs, /Id="WixUIBannerBmp" Value="\$\(sys\.SOURCEFILEDIR\)ui\\banner\.bmp"/);
		assert.match(wxs, /Id="WixUIDialogBmp" Value="\$\(sys\.SOURCEFILEDIR\)ui\\dialog\.bmp"/);
		assert.throws(() => renderSvgToBmp('<svg width="2" height="2" viewBox="0 0 2 2"><text>x</text></svg>'), /not supported/);
	});

	test("the WiX sources are XML that WiX's reader accepts (no double hyphen inside a comment)", () => {
		for (const path of ["aidr.wxs", "bundle.wxs", "ui/AidrUI.wxs", "ui/aidr.en-US.wxl", "ui/aidr.tr-TR.wxl"]) {
			const xml = windowsFile(path);
			assert.match(xml, /^<\?xml version="1\.0" encoding="utf-8"\?>/, path);
			for (const m of xml.matchAll(/<!--([\s\S]*?)-->/g)) assert.ok(!m[1].includes("--"), `${path}: "--" in a comment`);
		}
	});

	test("the licence page is the draft EULA rendered from docs/legal, marked as a draft, with the required clauses", () => {
		const decode = (rtf) => rtf.replace(/\\u(\d+)\?/g, (_, n) => String.fromCharCode(Number(n))).replace(/\\\\/g, "\\");
		const clauses = {
			"en-US": [
				"DRAFT - LEGAL REVIEW REQUIRED",
				"reverse engineer, decompile or disassemble",
				"Licence Term",
				"up to the number of Seats",
				"entitled to Updates only during a paid Licence Term",
				"Data Processing Agreement",
				"Local detection on endpoints keeps working",
			],
			"tr-TR": [
				"TASLAK - HUKUK/\u0130\u015e ONAYI GEREK\u0130R",
				"tersine m\u00fchendisli\u011fe tabi tutamaz",
				"Lisans S\u00fcresi",
				"Koltuk say\u0131s\u0131na kadar",
				"G\u00fcncellemelere yaln\u0131z \u00fccretli bir Lisans S\u00fcresi boyunca",
				"Veri \u0130\u015fleme S\u00f6zle\u015fmesi",
				"yerel tespit",
			],
		};
		for (const page of EULA_PAGES) {
			const rtf = readFileSync(page.rtf, "utf8");
			assert.match(rtf, /^\{\\rtf1\\ansi/);
			assert.match(rtf, /^[\t\n\r\x20-\x7e]*$/, `${page.culture} RTF must be ASCII (\\u escapes)`);
			assert.equal(rtf, renderEulaRtf(readFileSync(page.markdown, "utf8"), page), `${page.rtf} is stale: run render-eula.mjs`);
			const text = decode(rtf);
			assert.ok(!text.includes("<EULA TEXT"), `${page.culture}: the old placeholder is gone`);
			for (const clause of clauses[page.culture]) assert.ok(text.includes(clause), `${page.culture}: ${clause}`);
			assert.ok(text.includes("THIRD_PARTY_NOTICES.txt"), page.culture);
			assert.ok(text.includes("C:\\Program Files\\Singularity AIDR\\docs\\THIRD_PARTY_NOTICES.txt"), page.culture);
		}
		assert.throws(() => renderEulaRtf("| a | b |\n", EULA_PAGES[0]), /unsupported Markdown/);
		assert.throws(() => renderEulaRtf("**open\n", EULA_PAGES[0]), /unbalanced/);
		assert.match(windowsFile("build-msi.ps1"), /render-eula\.mjs'\), '--check'/);
		assert.match(ui, /<Text SourceFile="\$\(sys\.SOURCEFILEDIR\)eula\.\$\(var\.AidrCulture\)\.rtf" \/>/);
		assert.match(wxs, /Source="\$\(sys\.SOURCEFILEDIR\)\.\.\\\.\.\\\.\.\\THIRD_PARTY_NOTICES" Name="THIRD_PARTY_NOTICES\.txt"/);
	});
});

describe("Linux packages", () => {
	test("the RPM spec keeps the SEA bytes as built and removes connectors only on erase", () => {
		const spec = rpmSpec({ version: "0.6.0-rc.1", arch: "x86_64", stagedRoot: "/stage" });
		assert.match(spec, /^Version: 0\.6\.0~rc\.1$/m);
		assert.match(spec, /%global __os_install_post %\{nil\}/);
		assert.match(spec, /%global debug_package %\{nil\}/);
		assert.match(spec, /AutoReqProv: no/);
		assert.match(spec, /^\/usr\/share\/applications\/singularity-aidr-assistant\.desktop$/m);
		assert.match(ASSISTANT_DESKTOP, /^Exec=\/usr\/bin\/aidr assistant$/m);
		assert.match(ASSISTANT_DESKTOP, /^Name=Singularity AIDR Setup Assistant$/m);
		assert.match(ASSISTANT_DESKTOP, /^Name\[tr\]=Singularity AIDR Kurulum Yardımcısı$/m);
		assert.match(spec, /%preun\nif \[ "\$1" = "0" \]; then "\/opt\/singularity-aidr\/libexec\/package-hook.sh" preremove 1; fi/);
		assert.match(DEB_POSTINST, /configure\) "\/opt\/singularity-aidr\/libexec\/package-hook.sh" postinstall/);
		assert.match(DEB_PRERM, /remove\|deconfigure\) "\/opt\/singularity-aidr\/libexec\/package-hook.sh" preremove 1/);
		assert.doesNotMatch(DEB_PRERM, /upgrade\)/);
	});

	test("the .deb carries the bundle, the trust key and the aidr link", { skip: !have("dpkg-deb") && "dpkg-deb not installed" }, () => {
		const key = releaseKey;
		const sea = fakeSeaBundle();
		const out = tempDir("out");
		const { files, sums } = buildLinuxPackages({ seaDir: sea, trustKey: key.path, trustKeyFingerprint: key.fingerprint, version: "0.6.0-rc.1", out, formats: "deb,tar" });
		const deb = files.find((file) => file.endsWith(".deb"));
		assert.match(deb, /singularity-aidr_0\.6\.0~rc\.1_amd64\.deb$/);
		const info = spawnSync("dpkg-deb", ["-f", deb, "Package", "Version", "Architecture"], { encoding: "utf8" }).stdout;
		assert.match(info, /Package: singularity-aidr\nVersion: 0\.6\.0~rc\.1\nArchitecture: amd64/);
		const root = tempDir("deb-x");
		assert.equal(spawnSync("dpkg-deb", ["-x", deb, root]).status, 0);
		const prefix = join(root, "opt/singularity-aidr");
		assert.deepEqual(readFileSync(join(prefix, "bundle/aidr-artifact.manifest.json")), readFileSync(join(sea, "aidr-artifact.manifest.json")));
		assert.deepEqual(checkSeaBundle(join(prefix, "bundle"), { platform: "linux", trustKeyPem: releasePem() }).files.length > 0, true);
		assert.equal(readFileSync(join(prefix, "config/release-public.pem"), "utf8"), readFileSync(key.path, "utf8"));
		assert.equal(statSync(join(prefix, "bundle/bin/aidr")).mode & 0o777, 0o755);
		assert.equal(statSync(join(prefix, "config/release-public.pem")).mode & 0o777, 0o644);
		assert.equal(readlinkSync(join(root, "usr/bin/aidr")), "/opt/singularity-aidr/bundle/bin/aidr");
		const desktop = join(root, "usr/share/applications/singularity-aidr-assistant.desktop");
		assert.equal(readFileSync(desktop, "utf8"), ASSISTANT_DESKTOP);
		assert.equal(statSync(desktop).mode & 0o777, 0o644);
		const sumsText = readFileSync(sums, "utf8");
		for (const file of files) assert.match(sumsText, new RegExp(`${createHash("sha256").update(readFileSync(file)).digest("hex")}  ${file.split("/").pop().replace(/[.~]/g, "\\$&")}`));
	});

	describe("maintainer hook", () => {
		const root = tempDir("hook-root");
		const prefix = join(root, "opt/singularity-aidr");
		mkdirSync(join(prefix, "libexec"), { recursive: true });
		mkdirSync(join(prefix, "bundle/bin"), { recursive: true });
		writeFileSync(join(prefix, "bundle/bin/aidr"), FAKE_AIDR, { mode: 0o755 });
		writeFileSync(join(prefix, "libexec/package-hook.sh"), readFileSync(new URL("./linux/package-hook.sh", import.meta.url)), { mode: 0o755 });
		const asRoot = process.getuid?.() === 0;
		const invoker = asRoot ? "nobody" : userInfo().username;
		const canSwitch = !asRoot || have("runuser");
		// Never touch the real /etc marker from a test.
		const mdmMarker = join(root, "etc/singularity-aidr/mdm-managed");
		const machinePolicy = join(root, "etc/singularity-aidr/managed.json");

		function hook(args, env) {
			const home = tempDir("home");
			chmodSync(home, 0o777);
			const clean = Object.fromEntries(Object.entries(process.env).filter(([name]) => !["SUDO_USER", "AIDR_INSTALL_SKIP_SETUP", "AIDR_MDM_MANAGED"].includes(name) && !name.startsWith("AIDR_POLICY_")));
			const result = spawnSync("sh", [join(prefix, "libexec/package-hook.sh"), ...args], {
				encoding: "utf8",
				// System-wide hooks are off unless a test asks for them; HOME points at
				// the temp home so a root run of the fake binary logs there.
				env: { ...clean, AIDR_PREFIX: prefix, AIDR_PACKAGE_HOOK_TARGET_HOME: home, AIDR_MDM_MARKER: mdmMarker, AIDR_MACHINE_POLICY: machinePolicy, AIDR_MACHINE_HOOKS: "0", HOME: home, ...env },
			});
			const log = existsSync(join(home, "aidr-calls.log")) ? readFileSync(join(home, "aidr-calls.log"), "utf8") : "";
			return { ...result, log, home };
		}

		test("postinstall runs setup for the invoking SUDO_USER with that user's HOME", { skip: !canSwitch && "runuser not available" }, () => {
			const run = hook(["postinstall"], { SUDO_USER: invoker });
			assert.equal(run.status, 0, run.stderr);
			const uid = spawnSync("id", ["-u", invoker], { encoding: "utf8" }).stdout.trim();
			assert.match(run.log, new RegExp(`^${uid} HOME=${run.home} OP= setup$`, "m"));
			assert.notEqual(uid, "0");
		});

		test("postinstall tells 'no AI tool yet' apart from a failed setup, and the install succeeds either way", { skip: !canSwitch && "runuser not available" }, () => {
			const none = hook(["postinstall"], { SUDO_USER: invoker, FAKE_AIDR_SETUP_EXIT: "3" });
			assert.equal(none.status, 0);
			assert.match(none.stdout, /No AI tool .* was found for .* yet/);
			assert.match(none.stdout, /runs once: aidr setup/);
			assert.doesNotMatch(`${none.stdout}${none.stderr}`, /did not finish/);
			const failed = hook(["postinstall"], { SUDO_USER: invoker, FAKE_AIDR_SETUP_EXIT: "1" });
			assert.equal(failed.status, 0);
			assert.match(failed.stderr, /setup did not finish for/);
			const ok = hook(["postinstall"], { SUDO_USER: invoker });
			assert.match(ok.stdout, /done\. Restart your AI tools/);
			assert.match(ok.stdout, /Singularity AIDR Setup Assistant.*aidr assistant/);
		});

		test("postinstall never runs setup as root or without an invoking user; it prints the command", () => {
			for (const env of [{}, { SUDO_USER: "root" }, { SUDO_USER: "no-such-user-aidr" }, { SUDO_USER: "a;b" }]) {
				const run = hook(["postinstall"], env);
				assert.equal(run.status, 0);
				assert.equal(run.log, "", `setup ran for ${JSON.stringify(env)}`);
				assert.match(run.stdout, /aidr setup/);
			}
			const skipped = hook(["postinstall"], { SUDO_USER: invoker, AIDR_INSTALL_SKIP_SETUP: "1" });
			assert.equal(skipped.log, "");
			assert.match(skipped.stdout, /setup skipped/);
		});

		test("AIDR_MDM_MANAGED=1 writes the device-management marker; final removal deletes it", () => {
			const plain = hook(["postinstall"], { AIDR_INSTALL_SKIP_SETUP: "1" });
			assert.equal(plain.status, 0);
			assert.equal(existsSync(mdmMarker), false);
			const managed = hook(["postinstall"], { AIDR_INSTALL_SKIP_SETUP: "1", AIDR_MDM_MANAGED: "1" });
			assert.equal(managed.status, 0, managed.stderr);
			assert.equal(existsSync(mdmMarker), true);
			assert.match(managed.stdout, /device-managed install/);
			hook(["preremove", "0"], {});
			assert.equal(existsSync(mdmMarker), true, "an upgrade keeps the marker");
			hook(["preremove", "1"], {});
			assert.equal(existsSync(mdmMarker), false);
		});

		test("AIDR_POLICY_* variables write the machine policy before setup; an upgrade without them keeps it", () => {
			rmSync(machinePolicy, { force: true });
			const keyFile = join(tempDir("policy-keys"), "licensing-public-keys.pem");
			const pems = [generateKeyPairSync("ed25519"), generateKeyPairSync("ed25519")].map(({ publicKey }) => publicKey.export({ type: "spki", format: "pem" }));
			writeFileSync(keyFile, pems.join(""));
			const fleetKey = `aidr_fleet_${"k".repeat(43)}`;
			const run = hook(["postinstall"], {
				AIDR_INSTALL_SKIP_SETUP: "1",
				AIDR_POLICY_CONTROL_PLANE_URL: "https://aidr.corp.example/functions/v1",
				AIDR_POLICY_ENROLLMENT_KEY: fleetKey,
				AIDR_POLICY_LICENSING_PUBLIC_KEYS_FILE: keyFile,
				AIDR_POLICY_CA_FILE: "/etc/pki/corp-ca.pem",
				AIDR_POLICY_USE_OS_TRUST_STORE: "1",
				AIDR_POLICY_HTTPS_PROXY: "http://proxy.corp.example:3128",
				AIDR_POLICY_NO_PROXY: "corp.example,10.0.0.5",
				AIDR_POLICY_OFFLINE_POLICY: "keep_enforcing_local",
				AIDR_POLICY_APPROVALS_MODE: "dashboard_only",
			});
			assert.equal(run.status, 0, run.stderr);
			assert.match(run.stdout, /machine policy written to/);
			const policy = JSON.parse(readFileSync(machinePolicy, "utf8"));
			assert.deepEqual(Object.keys(policy).sort(), ["approvals_mode", "ca_file", "control_plane_url", "enrollment_key", "https_proxy", "licensing_public_keys_pem", "no_proxy", "offline_policy", "use_os_trust_store"]);
			assert.equal(policy.enrollment_key, fleetKey);
			assert.equal(policy.use_os_trust_store, true);
			assert.deepEqual(policy.licensing_public_keys_pem, pems.map((pem) => pem.replace(/-----[A-Z ]+-----|\s/g, "")));
			assert.equal(statSync(machinePolicy).mode & 0o777, 0o644);
			// An upgrade (no variables) keeps the administrator's policy as it is.
			const before = readFileSync(machinePolicy, "utf8");
			assert.equal(hook(["postinstall"], { AIDR_INSTALL_SKIP_SETUP: "1" }).status, 0);
			assert.equal(readFileSync(machinePolicy, "utf8"), before);
			// A value that would break the JSON is refused; the install still succeeds and the old policy stays.
			const bad = hook(["postinstall"], { AIDR_INSTALL_SKIP_SETUP: "1", AIDR_POLICY_SUPPORT_CONTACT_URL: 'https://x.example/"}' });
			assert.equal(bad.status, 0);
			assert.match(bad.stderr, /AIDR_POLICY_SUPPORT_CONTACT_URL contains a quote/);
			assert.equal(readFileSync(machinePolicy, "utf8"), before);
			const badKey = hook(["postinstall"], { AIDR_INSTALL_SKIP_SETUP: "1", AIDR_POLICY_LICENSING_PUBLIC_KEYS: "not a key!" });
			assert.match(badKey.stderr, /not a base64 public key/);
			assert.equal(readFileSync(machinePolicy, "utf8"), before);
			rmSync(machinePolicy, { force: true });
		});

		test("as root, postinstall deploys the system-wide hooks and final removal takes them away (C10)", () => {
			const install = hook(["postinstall"], { AIDR_INSTALL_SKIP_SETUP: "1", AIDR_MACHINE_HOOKS: "1", AIDR_LOCK_OTHER_HOOKS: "1" });
			assert.equal(install.status, 0, install.stderr);
			if (asRoot) {
				assert.match(install.log, /^0 HOME=\S+ OP= machine-hooks install --heartbeat --lock-other-hooks$/m);
			} else {
				assert.equal(install.log, "");
				assert.match(install.stdout, /system-wide hooks not deployed \(not root\)/);
			}
			const upgrade = hook(["preremove", "0"], { AIDR_MACHINE_HOOKS: "1" });
			assert.equal(upgrade.log, "", "an upgrade keeps the system-wide hooks");
			const removal = hook(["preremove", "1"], { AIDR_MACHINE_HOOKS: "1" });
			assert.equal(removal.status, 0);
			if (asRoot) assert.match(removal.log, /^0 HOME=\S+ OP= machine-hooks remove --heartbeat$/m);
			const off = hook(["postinstall"], { AIDR_INSTALL_SKIP_SETUP: "1" });
			assert.equal(off.log, "", "AIDR_MACHINE_HOOKS=0 deploys nothing");
		});

		/** A passwd-format account list whose homes are temp dirs, each with or without ~/.singularity-aidr. */
		function accounts(entries) {
			const lines = [];
			const homes = {};
			for (const { name, uid, state = "dir", owner = uid } of entries) {
				const home = tempDir(`acct-${name}`);
				chmodSync(home, 0o777);
				if (state === "dir") {
					mkdirSync(join(home, ".singularity-aidr"));
					if (asRoot) chownSync(join(home, ".singularity-aidr"), Number(owner), Number(owner));
				} else if (state === "link") {
					mkdirSync(join(home, "elsewhere"));
					symlinkSync(join(home, "elsewhere"), join(home, ".singularity-aidr"));
				}
				homes[name] = home;
				lines.push(`${name}:x:${uid}:${uid}::${home}:/bin/sh`);
			}
			const passwd = join(tempDir("passwd"), "passwd");
			writeFileSync(passwd, `${lines.join("\n")}\n`);
			return { passwd, homes };
		}
		const callsIn = (home) => (existsSync(join(home, "aidr-calls.log")) ? readFileSync(join(home, "aidr-calls.log"), "utf8") : "");

		test("final removal uninstalls the connectors of EVERY account that ran setup, each as that account", { skip: !canSwitch && "runuser not available" }, () => {
			const me = spawnSync("id", ["-u", invoker], { encoding: "utf8" }).stdout.trim();
			const other = asRoot ? [{ name: "root", uid: "0" }] : [];
			const { passwd, homes } = accounts([
				{ name: invoker, uid: me },
				...other,
				{ name: "linked", uid: me, state: "link" },
				{ name: "never-setup", uid: me, state: "none" },
				...(asRoot ? [{ name: "foreign", uid: me, owner: "0" }] : []),
			]);
			const upgrade = hook(["preremove", "0"], { AIDR_PACKAGE_HOOK_PASSWD: passwd });
			assert.equal(upgrade.status, 0);
			assert.equal(callsIn(homes[invoker]), "", "an upgrade keeps every registration");
			const removal = hook(["preremove", "1"], { AIDR_PACKAGE_HOOK_PASSWD: passwd });
			assert.equal(removal.status, 0, removal.stderr);
			assert.match(callsIn(homes[invoker]), new RegExp(`^${me} HOME=${homes[invoker]} OP=1 uninstall --yes --keep-data$`, "m"), "runs as the account, with its HOME");
			if (asRoot) assert.match(callsIn(homes.root), new RegExp(`^0 HOME=${homes.root} OP=1 uninstall --yes --keep-data$`, "m"), "a second profile is cleaned too");
			for (const skipped of ["linked", "never-setup", ...(asRoot ? ["foreign"] : [])]) assert.equal(callsIn(homes[skipped]), "", `${skipped} is skipped`);
			assert.match(removal.stdout, new RegExp(`connectors removed for ${asRoot ? 2 : 1} of ${asRoot ? 2 : 1} account\\(s\\)`));
			assert.doesNotMatch(removal.stdout, /must run 'aidr uninstall' before the package is removed/);
			// Fleet removal without removing the package: same set, and a failure is reported.
			const fleet = hook(["deregister-all"], { AIDR_PACKAGE_HOOK_PASSWD: passwd });
			assert.equal(fleet.status, 0, fleet.stderr);
			assert.equal(callsIn(homes[invoker]).split("\n").filter(Boolean).length, 2);
			const none = hook(["deregister-all"], { AIDR_PACKAGE_HOOK_PASSWD: accounts([{ name: "never-setup", uid: me, state: "none" }]).passwd });
			assert.equal(none.status, 0);
			assert.match(none.stdout, /no account on this machine has AIDR connectors registered/);
		});
	});

	test("an optional `aidr update` catalog key is validated and placed next to the release key", () => {
		const catalog = trustKey();
		const out = tempDir("catalog-out");
		const base = { seaDir: fakeSeaBundle(), trustKey: releaseKey.path, trustKeyFingerprint: releaseKey.fingerprint, version: "0.6.0", formats: "tar" };
		assert.throws(() => buildLinuxPackages({ ...base, out, catalogKey: catalog.privatePath }), /catalog key file contains a private key/);
		const { files } = buildLinuxPackages({ ...base, out, catalogKey: catalog.path });
		const unpack = tempDir("catalog-x");
		assert.equal(spawnSync("tar", ["-xzf", files[0], "-C", unpack]).status, 0);
		const placed = join(unpack, "singularity-aidr-0.6.0-linux-x64", "config", "installer-catalog-public.pem");
		assert.equal(readFileSync(placed, "utf8"), readFileSync(catalog.path, "utf8"));
		const without = buildLinuxPackages({ ...base, out: tempDir("catalog-none") });
		const bare = tempDir("catalog-none-x");
		assert.equal(spawnSync("tar", ["-xzf", without.files[0], "-C", bare]).status, 0);
		assert.ok(!existsSync(join(bare, "singularity-aidr-0.6.0-linux-x64", "config", "installer-catalog-public.pem")));
		const msi = msiInputs({ seaDir: fakeSeaBundle({ platform: "win32" }), trustKey: releaseKey.path, trustKeyFingerprint: releaseKey.fingerprint, version: "0.6.0", signing: "signed", catalogKey: catalog.path });
		assert.equal(msi.hasCatalogKey, "1");
		assert.equal(msi.catalogKeyFingerprint, catalog.fingerprint);
		const wxs = readFileSync(new URL("./windows/aidr.wxs", import.meta.url), "utf8");
		assert.match(wxs, /<\?if \$\(var\.HasCatalogKey\) = 1 \?>[\s\S]*Name="installer-catalog-public\.pem"/);
	});

	test("the tarball installs into a prefix, links aidr and uninstalls cleanly", () => {
		const key = releaseKey;
		const out = tempDir("tar-out");
		const { files } = buildLinuxPackages({ seaDir: fakeSeaBundle(), trustKey: key.path, trustKeyFingerprint: key.fingerprint, version: "0.6.0", out, formats: "tar" });
		const tarball = files[0];
		assert.match(tarball, /singularity-aidr-0\.6\.0-linux-x64\.tar\.gz$/);
		const unpack = tempDir("tar-x");
		assert.equal(spawnSync("tar", ["-xzf", tarball, "-C", unpack]).status, 0);
		const top = join(unpack, "singularity-aidr-0.6.0-linux-x64");
		const target = join(tempDir("tar-prefix"), "aidr");
		const link = join(tempDir("tar-bin"), "aidr");
		const env = { ...process.env, AIDR_PREFIX: target, AIDR_BIN_LINK: link, AIDR_INSTALL_SKIP_SETUP: "1" };
		delete env.SUDO_USER;
		const install = spawnSync("sh", [join(top, "install.sh")], { encoding: "utf8", env });
		assert.equal(install.status, 0, install.stderr);
		assert.equal(readlinkSync(link), join(target, "bundle/bin/aidr"));
		assert.ok(existsSync(join(target, "config/release-public.pem")));
		const again = spawnSync("sh", [join(top, "install.sh")], { encoding: "utf8", env });
		assert.notEqual(again.status, 0, "a second install over an existing prefix must refuse");
		const remove = spawnSync("sh", [join(top, "uninstall.sh")], { encoding: "utf8", env });
		assert.equal(remove.status, 0, remove.stderr);
		assert.ok(!existsSync(join(target, "bundle")));
		assert.ok(!existsSync(link));
	});
});

// ─── per-customer installers (docs/operations/customer-builds.md) ─────────

/**
 * A customer packet in the contract's shape. The builders check shape and
 * customer id only (the signature is scripts/customer-packet-verify.mjs's job),
 * so the signature here is a placeholder.
 */
function customerPacket({ customerId = "bilgem", payload = {}, document = {} } = {}) {
	const dir = tempDir("packet");
	const path = join(dir, "customer-packet.json");
	const license = { format: "aidr-license-v1", key_id: "vendor-2026", payload: { customer_id: customerId, expires_at: "2027-01-01T00:00:00Z" }, sig: "AA==" };
	const body = {
		format: "aidr-customer-packet-v1",
		key_id: "vendor-2026",
		payload: { customer_id: customerId, packet_id: `${customerId}-2026-001`, issued_at: "2026-10-01T00:00:00Z", license, display_name: "TÜBİTAK BİLGEM", ...payload },
		sig: "c2lnbmF0dXJl",
		...document,
	};
	writeFileSync(path, `${JSON.stringify(body, null, 2)}\n`);
	return path;
}

describe("customer packet inputs", () => {
	test("a packet in the contract's shape is accepted for its own customer only", () => {
		const path = customerPacket();
		const packet = checkCustomerPacket(path);
		assert.equal(packet.customerId, "bilgem");
		assert.equal(packet.packetId, "bilgem-2026-001");
		assert.equal(packet.sha256, createHash("sha256").update(readFileSync(path)).digest("hex"));
		assert.ok(packet.bytes.equals(readFileSync(path)), "embedded byte for byte");
		assert.equal(checkCustomerPacket(path, { expectedCustomerId: "bilgem" }).customerId, "bilgem");
		assert.throws(() => checkCustomerPacket(path, { expectedCustomerId: "havelsan" }), /is for bilgem, not havelsan/);
		assert.throws(() => checkCustomerPacket(path, { expectedCustomerId: "BILGEM" }), /invalid customer id/);
	});

	test("anything else is refused before it is embedded", () => {
		const refused = [
			[customerPacket({ document: { format: "aidr-license-v1" } }), /not an aidr-customer-packet-v1 document/],
			[customerPacket({ document: { sig: "" } }), /no key_id or signature/],
			[customerPacket({ customerId: "Bilgem" }), /invalid customer id/],
			[customerPacket({ customerId: "x" }), /invalid customer id/],
			[customerPacket({ payload: { packet_id: "../x" } }), /invalid packet_id/],
			[customerPacket({ payload: { enrollment_code: "never-in-a-packet" } }), /unknown keys: enrollment_code/],
			[customerPacket({ payload: { license: { format: "aidr-license-v1", payload: { customer_id: "havelsan" } } } }), /license for bilgem/],
			[customerPacket({ payload: { license: null } }), /license for bilgem/],
		];
		for (const [path, reason] of refused) assert.throws(() => checkCustomerPacket(path), reason);
		const dir = tempDir("packet-bad");
		writeFileSync(join(dir, "empty.json"), "");
		assert.throws(() => checkCustomerPacket(join(dir, "empty.json")), /1 to 65536 bytes/);
		writeFileSync(join(dir, "big.json"), " ".repeat(CUSTOMER_PACKET_MAX_BYTES + 1));
		assert.throws(() => checkCustomerPacket(join(dir, "big.json")), /not 65537/);
		writeFileSync(join(dir, "text.json"), "not json");
		assert.throws(() => checkCustomerPacket(join(dir, "text.json")), /not UTF-8 JSON/);
		writeFileSync(join(dir, "latin1.json"), Buffer.from([0x7b, 0xff, 0x7d]));
		assert.throws(() => checkCustomerPacket(join(dir, "latin1.json")), /not UTF-8 JSON/);
	});

	test("per-customer files are named SingularityAIDR-<CUSTOMER>-<version>-<arch>.<ext>", () => {
		assert.equal(customerArtifactName({ customerId: "bilgem", version: "1.0.0", arch: "x64", ext: "msi" }), "SingularityAIDR-BILGEM-1.0.0-x64.msi");
		assert.equal(customerArtifactName({ customerId: "havelsan-ank", version: "1.0.0", arch: "arm64", ext: "tar.gz" }), "SingularityAIDR-HAVELSAN-ANK-1.0.0-arm64.tar.gz");
		assert.equal(customerArtifactName({ customerId: "bilgem", version: "1.0.0", arch: "x64", ext: "exe", suffix: "-UNSIGNED" }), "SingularityAIDR-BILGEM-1.0.0-x64-UNSIGNED.exe");
		assert.throws(() => customerArtifactName({ customerId: "bilgem", version: "1.0.0", arch: "amd64", ext: "deb" }), /unsupported architecture/);
		assert.throws(() => customerArtifactName({ customerId: "../x", version: "1.0.0", arch: "x64", ext: "deb" }), /invalid customer id/);
	});
});

describe("per-customer Windows installer", () => {
	const wxs = readFileSync(new URL("./windows/aidr.wxs", import.meta.url), "utf8");
	const bundle = readFileSync(new URL("./windows/bundle.wxs", import.meta.url), "utf8");
	const ps1 = readFileSync(new URL("./windows/build-msi.ps1", import.meta.url), "utf8").replace(/\r\n/g, "\n");

	test("msi-inputs names the product and files after the customer and keeps the upgrade identity", () => {
		const base = { seaDir: fakeSeaBundle({ platform: "win32" }), trustKey: releaseKey.path, trustKeyFingerprint: releaseKey.fingerprint, version: "0.6.0" };
		const generic = msiInputs({ ...base, signing: "signed" });
		assert.equal(generic.productName, "Singularity AIDR");
		assert.equal(generic.hasCustomerPacket, "0");
		assert.equal(generic.customerId, null);
		assert.equal(generic.bundleOutputName, "singularity-aidr-0.6.0-windows-x64.exe");
		const packet = customerPacket();
		const customer = msiInputs({ ...base, signing: "signed", customerPacket: packet, customerId: "bilgem" });
		assert.equal(customer.productName, "Singularity AIDR (BILGEM)");
		assert.equal(customer.outputName, "SingularityAIDR-BILGEM-0.6.0-x64.msi");
		assert.equal(customer.bundleOutputName, "SingularityAIDR-BILGEM-0.6.0-x64.exe");
		assert.equal(customer.hasCustomerPacket, "1");
		assert.equal(customer.customerId, "bilgem");
		assert.equal(customer.customerPacketSha256, createHash("sha256").update(readFileSync(packet)).digest("hex"));
		// Generic and customer MSIs upgrade each other; the EXE has its own stable identity.
		assert.equal(customer.upgradeCode, generic.upgradeCode);
		assert.equal(customer.bundleUpgradeCode, generic.bundleUpgradeCode);
		assert.notEqual(customer.bundleUpgradeCode, customer.upgradeCode);
		const unsigned = msiInputs({ ...base, signing: "unsigned", customerPacket: packet });
		assert.equal(unsigned.outputName, "SingularityAIDR-BILGEM-0.6.0-x64-UNSIGNED.msi");
		assert.equal(unsigned.bundleOutputName, "SingularityAIDR-BILGEM-0.6.0-x64-UNSIGNED.exe");
		assert.throws(() => msiInputs({ ...base, signing: "signed", customerPacket: packet, customerId: "havelsan" }), /is for bilgem, not havelsan/);
		assert.throws(() => msiInputs({ ...base, signing: "signed", customerId: "bilgem" }), /--customer-id needs --customer-packet/);
		assert.throws(() => msiInputs({ ...base, signing: "signed", customerPacket: customerPacket({ document: { format: "x" } }) }), /aidr-customer-packet-v1/);
	});

	test("the packet goes to CONFIGDIR and, per-machine and permanently, to ProgramData", () => {
		assert.match(wxs, /<Package Name="\$\(var\.ProductName\)"/);
		const block = /<\?if \$\(var\.HasCustomerPacket\) = 1 \?>([\s\S]*?)<\?endif\?>/.exec(wxs)[1];
		const config = attrs(/<Component Id="CustomerPacket"[^>]*>/.exec(block)[0]);
		assert.equal(config.Directory, "CONFIGDIR");
		assert.equal(config.Permanent, undefined, "the install-prefix copy goes with the product");
		const machine = attrs(/<Component Id="CustomerPacketMachine"[^>]*>/.exec(block)[0]);
		assert.equal(machine.Directory, "AIDRMACHINEDATA");
		assert.equal(machine.Permanent, "yes", "survives removal and a generic `aidr update` upgrade");
		assert.equal(machine.Condition, "ALLUSERS=1", "ProgramData is written by a per-machine (elevated) install only");
		assert.match(machine.Guid, /^[0-9A-F-]{36}$/, "a permanent component needs a stable GUID");
		assert.match(block, /<StandardDirectory Id="CommonAppDataFolder">\s*<Directory Id="AIDRMACHINEDATA" Name="Singularity AIDR" \/>/);
		for (const file of block.matchAll(/<File\b[^>]*>/g)) {
			const { Source, Name } = attrs(file[0]);
			assert.equal(Source, "$(var.CustomerPacket)");
			assert.equal(Name, "customer-packet.json");
		}
		assert.match(wxs, /<\?if \$\(var\.HasCustomerPacket\) = 1 \?>\s*<ComponentRef Id="CustomerPacket" \/>\s*<ComponentRef Id="CustomerPacketMachine" \/>\s*<\?endif\?>/);
		// build-msi passes the variables, embedding the private stage copy msi-inputs checked.
		assert.match(ps1, /'-d', "HasCustomerPacket=\$\(\$inputs\.hasCustomerPacket\)"/);
		assert.match(ps1, /'-d', "CustomerPacket=\$packet"/);
		assert.match(ps1, /'-d', "ProductName=\$\(\$inputs\.productName\)"/);
		assert.match(ps1, /Copy-Item -LiteralPath \(Resolve-Path \$CustomerPacket\)\.Path -Destination \$packet[\s\S]*--customer-packet', \$packet/);
	});

	test("the wizard names the customer, its company address and the update date from the packet", () => {
		const base = { seaDir: fakeSeaBundle({ platform: "win32" }), trustKey: releaseKey.path, trustKeyFingerprint: releaseKey.fingerprint, version: "0.6.0", signing: "signed" };
		const license = { format: "aidr-license-v1", key_id: "vendor-2026", payload: { customer_id: "bilgem", expires_at: "2027-01-01T00:00:00Z", grace_days: 30 }, sig: "AA==" };
		const inputs = msiInputs({
			...base,
			customerPacket: customerPacket({ payload: { license, control_plane_url: "https://aidr.bilgem.example/" } }),
		});
		// Each culture gets the name its code page holds: Turkish letters in the Turkish wizard,
		// spelled in ASCII in the English one (Windows-1252 has no İ).
		assert.deepEqual(
			inputs.cultures.map((c) => [c.culture, c.customerName]),
			[
				["en-US", "TUBITAK BILGEM"],
				["tr-TR", "TÜBİTAK BİLGEM"],
			],
		);
		assert.equal(inputs.customerServer, "https://aidr.bilgem.example/");
		assert.equal(inputs.customerUpdatesUntil, "2027-01-31", "expires_at + grace_days");
		// No address, no grace days: the generic company page, and no update line.
		const plain = msiInputs({ ...base, customerPacket: customerPacket() });
		assert.equal(plain.customerServer, null);
		assert.equal(plain.customerUpdatesUntil, null);
		// An address the enrollment handoff would refuse fails the build, not the endpoint.
		for (const url of ["https://aidr.example/?x=1", "https://user@aidr.example/"]) {
			assert.throws(() => msiInputs({ ...base, customerPacket: customerPacket({ payload: { control_plane_url: url } }) }), /not an address the installer accepts/);
		}
		assert.equal(WIZARD_URL_PATTERN.source, /^https:\/\/[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::[0-9]{1,5})?(?:\/[A-Za-z0-9._~%/-]*)?$/u.source);
		const cs = windowsFile("ca/EnrollmentActions.cs");
		assert.equal(new RegExp('const string UrlPattern = @"([^"]*)"').exec(cs)[1], WIZARD_URL_PATTERN.source.replaceAll("\\/", "/"));
		// Never text WiX would expand; else the customer label.
		assert.equal(wizardCustomerName("Acme $(var.ProductCode)", "ACME", 1252), "ACME");
		assert.equal(wizardCustomerName("Acme !(loc.AidrDialogTitle)", "ACME", 1254), "ACME");
		assert.equal(wizardCustomerName("北京", "BEIJING", 1254), "BEIJING");
		assert.equal(wizardCustomerName(null, "BILGEM", 1252), "BILGEM");
		// build-msi defines the variables only when set, the name once per culture build.
		assert.match(ps1, /if \(\$inputs\.customerServer\) \{ \$common \+= @\('-d', "CustomerServer=/);
		assert.match(ps1, /if \(\$inputs\.customerUpdatesUntil\) \{ \$common \+= @\('-d', "CustomerUpdatesUntil=/);
		assert.match(ps1, /if \(\$culture\.customerName\) \{ \$customerName = @\('-d', "CustomerName=\$\(\$culture\.customerName\)"\) \}/);
	});

	test("the customer company page hands the packet's address to setup like a typed one", () => {
		const ui = windowsFile("ui/AidrUI.wxs");
		for (const [variable, property] of [
			["CustomerName", "AidrCustomerName"],
			["CustomerServer", "AidrCustomerServer"],
			["CustomerUpdatesUntil", "AidrUpdatesUntil"],
		]) {
			assert.match(ui, new RegExp(`<\\?ifdef ${variable} \\?>\\s*<Property Id="${property}" Value="\\$\\(var\\.${variable}\\)" />\\s*<\\?endif\\?>`), variable);
			assert.match(property, /[a-z]/, "private: a command line cannot set it");
		}
		// A command-line ENROLLMENT_URL wins over the packet (the generic company page then shows it).
		assert.deepEqual(element(ui, "SetProperty", "AidrUsePacketServer"), {
			Id: "AidrUsePacketServer",
			Value: "1",
			Sequence: "ui",
			After: "AppSearch",
			Condition: "AidrCustomerServer AND NOT ENROLLMENT_URL",
		});
		const scopeNext = /<Dialog Id="AidrScopeDlg"[\s\S]*?<Control Id="Next"[\s\S]*?<\/Control>/.exec(ui)[0];
		assert.match(scopeNext, /Value="AidrCompanyDlg"[^>]*Condition="NOT AidrUsePacketServer"/);
		assert.match(scopeNext, /Value="AidrCustomerCompanyDlg"[^>]*Condition="AidrUsePacketServer"/);
		assert.match(scopeNext, /Value="\[AIDR_DEFAULT_CONTROL_PLANE\]"[^>]*Condition="NOT ENROLLMENT_URL AND NOT AidrUsePacketServer"/);
		const readyBack = /<Dialog Id="AidrReadyDlg"[\s\S]*?<Control Id="Back"[\s\S]*?<\/Control>/.exec(ui)[0];
		assert.match(readyBack, /Value="AidrCompanyDlg"[^>]*Condition="NOT AidrUsePacketServer"/);
		assert.match(readyBack, /Value="AidrCustomerCompanyDlg"[^>]*Condition="AidrUsePacketServer"/);
		const page = /<Dialog Id="AidrCustomerCompanyDlg"[\s\S]*?<\/Dialog>/.exec(ui)[0];
		const code = attrs(/<Control Id="CustomerCode"[^>]*>/.exec(page)[0]);
		assert.deepEqual([code.Property, code.Password], ["ENROLLMENT_CODE", "yes"]);
		const next = /<Control Id="Next"[\s\S]*?<\/Control>/.exec(page)[0];
		const events = [...next.matchAll(/<Publish\b[^>]*>/g)].map((m) => attrs(m[0]));
		assert.deepEqual(
			events.map((e) => [e.Property ?? e.Event, e.Value, e.Condition]),
			[
				["ENROLLMENT_URL", "[AidrCustomerServer]", undefined],
				["DoAction", "AidrValidateEnrollmentInput", undefined],
				["SpawnDialog", "AidrEnrollmentInvalidDlg", "AIDR_ENROLLMENT_ERROR"],
				["NewDialog", "AidrReadyDlg", "NOT AIDR_ENROLLMENT_ERROR"],
			],
		);
		// The connection is "company", so Install never clears the address it set.
		assert.equal(element(ui, "SetProperty", "AIDR_CONNECTION").Condition, "ENROLLMENT_URL OR ENROLLMENT_CODE OR AidrCustomerServer");
		// The generic build shows none of it.
		for (const id of ["Customer", "UpdatesUntil"]) {
			const control = attrs(new RegExp(`<Control Id="${id}"[^>]*>`).exec(/<Dialog Id="AidrReadyDlg"[\s\S]*?<\/Dialog>/.exec(ui)[0])[0]);
			assert.match(control.HideCondition, /^NOT Aidr/, id);
		}
	});

	test("the setup EXE wraps exactly the signed MSI and is Authenticode-signed engine first", () => {
		assert.match(bundle, /<bal:WixInternalUIBootstrapperApplication \/>/, "the MSI's own EN/TR wizard");
		assert.deepEqual([...bundle.matchAll(/<MsiPackage\b[^>]*>/g)].map((m) => attrs(m[0]).SourceFile), ["$(var.MsiPath)"]);
		const root = attrs(/<Bundle\b[^>]*>/.exec(bundle)[0]);
		assert.equal(root.UpgradeCode, "$(var.BundleUpgradeCode)");
		assert.equal(root.Name, "$(var.ProductName)");
		// Built after the MSI is signed, from that file.
		const bundleStart = ps1.indexOf("if ($Bundle) {\n    # The EXE embeds the MSI");
		assert.ok(bundleStart > ps1.indexOf("'verify', '/pa', $msi"), "the EXE embeds the signed MSI");
		const steps = ps1.slice(bundleStart);
		const order = ["'burn', 'detach'", "Invoke-AuthenticodeSign $signtool @($engine)", "'burn', 'reattach'", "Invoke-AuthenticodeSign $signtool @($stagedExe)", "Move-Item -LiteralPath $stagedExe"];
		const positions = order.map((needle) => steps.indexOf(needle));
		assert.ok(positions.every((at) => at > 0), positions.join(","));
		assert.deepEqual([...positions].sort((a, b) => a - b), positions, "detach, sign engine, reattach, sign EXE");
		assert.match(ps1, /function Invoke-AuthenticodeSign[\s\S]*?'verify', '\/pa'/);
		assert.match(ps1, /\$WixBalExtension = 'WixToolset\.Bal\.wixext'/);
		assert.match(ps1, /if \(\$Bundle\) \{ Install-WixExtension \$WixBalExtension \}/);
	});
});

describe("per-customer Linux packages", () => {
	test("the packet is a dpkg conffile and RPM %config(noreplace); generic RPMs keep it as %ghost", () => {
		assert.equal(LINUX_CUSTOMER_PACKET, "/etc/singularity-aidr/customer-packet.json");
		assert.equal(debConffiles({}), "/etc/singularity-aidr/customer-packet.json\n");
		assert.equal(debConffiles(undefined), null);
		const customer = rpmSpec({ version: "0.6.0", arch: "x86_64", stagedRoot: "/stage", customerPacket: true });
		assert.match(customer, /^%dir \/etc\/singularity-aidr$/m);
		assert.match(customer, /^%config\(noreplace\) %attr\(0644,root,root\) \/etc\/singularity-aidr\/customer-packet\.json$/m);
		const generic = rpmSpec({ version: "0.6.0", arch: "x86_64", stagedRoot: "/stage" });
		assert.match(generic, /^%ghost %config\(noreplace\) %attr\(0644,root,root\) \/etc\/singularity-aidr\/customer-packet\.json$/m);
	});

	test("the customer .deb carries the packet in /etc as a conffile, under the customer file name", { skip: !have("dpkg-deb") && "dpkg-deb not installed" }, () => {
		const packet = customerPacket();
		const out = tempDir("customer-deb");
		const base = { seaDir: fakeSeaBundle(), trustKey: releaseKey.path, trustKeyFingerprint: releaseKey.fingerprint, version: "0.6.0", formats: "deb" };
		const { files, customerPacket: checked } = buildLinuxPackages({ ...base, out, customerPacket: packet, customerId: "bilgem" });
		assert.equal(checked.customerId, "bilgem");
		assert.deepEqual(files.map((file) => file.split("/").pop()), ["SingularityAIDR-BILGEM-0.6.0-x64.deb"]);
		// The same package, so generic and customer packages upgrade each other.
		assert.equal(spawnSync("dpkg-deb", ["-f", files[0], "Package"], { encoding: "utf8" }).stdout, "singularity-aidr\n");
		const root = tempDir("customer-deb-x");
		assert.equal(spawnSync("dpkg-deb", ["-x", files[0], root]).status, 0);
		assert.deepEqual(readFileSync(join(root, LINUX_CUSTOMER_PACKET.slice(1))), readFileSync(packet));
		assert.equal(statSync(join(root, LINUX_CUSTOMER_PACKET.slice(1))).mode & 0o777, 0o644);
		const control = tempDir("customer-deb-control");
		assert.equal(spawnSync("dpkg-deb", ["-e", files[0], control]).status, 0);
		assert.equal(readFileSync(join(control, "conffiles"), "utf8"), "/etc/singularity-aidr/customer-packet.json\n");
		// A generic .deb has no packet and no conffile entry.
		const generic = buildLinuxPackages({ ...base, out: tempDir("generic-deb") });
		const genericControl = tempDir("generic-deb-control");
		assert.equal(spawnSync("dpkg-deb", ["-e", generic.files[0], genericControl]).status, 0);
		assert.equal(existsSync(join(genericControl, "conffiles")), false);
		assert.throws(() => buildLinuxPackages({ ...base, out: tempDir("wrong-customer"), customerPacket: packet, customerId: "havelsan" }), /is for bilgem, not havelsan/);
		assert.throws(() => buildLinuxPackages({ ...base, out: tempDir("id-only"), customerId: "bilgem" }), /--customer-id needs --customer-packet/);
	});

	test("the customer tarball installs the packet to <prefix>/config", () => {
		const packet = customerPacket({ customerId: "havelsan" });
		const out = tempDir("customer-tar");
		const { files } = buildLinuxPackages({ seaDir: fakeSeaBundle(), trustKey: releaseKey.path, trustKeyFingerprint: releaseKey.fingerprint, version: "0.6.0", out, formats: "tar", customerPacket: packet });
		assert.deepEqual(files.map((file) => file.split("/").pop()), ["SingularityAIDR-HAVELSAN-0.6.0-x64.tar.gz"]);
		assert.match(readFileSync(join(out, "SHA256SUMS"), "utf8"), /  SingularityAIDR-HAVELSAN-0\.6\.0-x64\.tar\.gz\n$/);
		const unpack = tempDir("customer-tar-x");
		assert.equal(spawnSync("tar", ["-xzf", files[0], "-C", unpack]).status, 0);
		const top = join(unpack, "SingularityAIDR-HAVELSAN-0.6.0-x64");
		assert.deepEqual(readFileSync(join(top, "config", "customer-packet.json")), readFileSync(packet));
		const target = join(tempDir("customer-tar-prefix"), "aidr");
		const env = { ...process.env, AIDR_PREFIX: target, AIDR_BIN_LINK: join(tempDir("customer-tar-bin"), "aidr"), AIDR_INSTALL_SKIP_SETUP: "1" };
		delete env.SUDO_USER;
		const install = spawnSync("sh", [join(top, "install.sh")], { encoding: "utf8", env });
		assert.equal(install.status, 0, install.stderr);
		// First in `aidr setup`'s discovery order: <install prefix>/config/customer-packet.json.
		assert.deepEqual(readFileSync(join(target, "config", "customer-packet.json")), readFileSync(packet));
	});
});
