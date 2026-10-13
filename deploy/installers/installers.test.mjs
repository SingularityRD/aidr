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
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	readlinkSync,
	rmSync,
	statSync,
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
import { checkSeaBundle, checkTrustKey, checkVersion, InstallerInputError } from "./lib/common.mjs";
import {
	ASSISTANT_DESKTOP,
	buildLinuxPackages,
	DEB_POSTINST,
	DEB_PRERM,
	packageVersion,
	rpmSpec,
} from "./linux/build-linux-packages.mjs";
import { MSI_CULTURES, msiInputs } from "./windows/msi-inputs.mjs";
import { bmpInfo, renderSvgToBmp, WIZARD_BITMAPS } from "./windows/ui/render-bitmaps.mjs";

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
		assert.deepEqual(signed.cultures, MSI_CULTURES);
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
		const customs = [...sequence(wxs, "InstallExecuteSequence").matchAll(/<Custom\b[^>]*>/g)].map((m) => m[0]);
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
		const ps1 = readFileSync(new URL("./windows/build-msi.ps1", import.meta.url), "utf8");
		assert.match(ps1, /Pass -SignThumbprint for a release build or -Unsigned for a local build/);
		assert.match(ps1, /--remanifest/);
		assert.match(ps1, /'verify', '\/pa', \$msi/);
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
		assert.match(ps1, /Add-LanguageTransform -Base[\s\S]*Set-PackageLanguages -Msi[\s\S]*Test-LanguageTransforms -Msi[\s\S]*'sign', '\/sha1'/);
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
		for (const path of ["aidr.wxs", "ui/AidrUI.wxs", "ui/aidr.en-US.wxl", "ui/aidr.tr-TR.wxl"]) {
			const xml = windowsFile(path);
			assert.match(xml, /^<\?xml version="1\.0" encoding="utf-8"\?>/, path);
			for (const m of xml.matchAll(/<!--([\s\S]*?)-->/g)) assert.ok(!m[1].includes("--"), `${path}: "--" in a comment`);
		}
	});

	test("the licence page is a marked placeholder and points at the shipped third-party notices", () => {
		const decode = (rtf) => rtf.replace(/\\u(\d+)\?/g, (_, n) => String.fromCharCode(Number(n)));
		for (const culture of ["en-US", "tr-TR"]) {
			const rtf = windowsFile(`ui/eula.${culture}.rtf`);
			assert.match(rtf, /^\{\\rtf1\\ansi/);
			assert.match(rtf, /^[\t\n\r\x20-\x7e]*$/, `${culture} RTF must be ASCII (\\u escapes)`);
			const text = decode(rtf);
			assert.ok(text.includes("<EULA TEXT \u2014 legal review required>"), culture);
			assert.ok(text.includes("THIRD_PARTY_NOTICES.txt"), culture);
		}
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

		function hook(args, env) {
			const home = tempDir("home");
			chmodSync(home, 0o777);
			const clean = Object.fromEntries(Object.entries(process.env).filter(([name]) => !["SUDO_USER", "AIDR_INSTALL_SKIP_SETUP", "AIDR_MDM_MANAGED"].includes(name)));
			const result = spawnSync("sh", [join(prefix, "libexec/package-hook.sh"), ...args], {
				encoding: "utf8",
				env: { ...clean, AIDR_PREFIX: prefix, AIDR_PACKAGE_HOOK_TARGET_HOME: home, AIDR_MDM_MARKER: mdmMarker, ...env },
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

		test("preremove uninstalls with operator confirmation on final removal only", { skip: !canSwitch && "runuser not available" }, () => {
			const upgrade = hook(["preremove", "0"], { SUDO_USER: invoker });
			assert.equal(upgrade.status, 0);
			assert.equal(upgrade.log, "");
			const removal = hook(["preremove", "1"], { SUDO_USER: invoker });
			assert.equal(removal.status, 0);
			assert.match(removal.log, / OP=1 uninstall --yes --keep-data$/m);
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
