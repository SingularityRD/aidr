// Desktop installer builders: input contracts, the Linux package layout and
// the maintainer-hook behaviour, run against temporary roots and fake homes.
// The bundle here is a small stand-in SEA directory (the real one is ~900 MB);
// its `aidr` is a shell script that records how it was called, so the tests
// prove WHO the hook runs setup/uninstall for, never touching a real HOME.
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
import { writeDistributionManifest } from "../../packages/claude-code/scripts/build-sea.mjs";
import { checkSeaBundle, checkTrustKey, checkVersion, InstallerInputError } from "./lib/common.mjs";
import {
	buildLinuxPackages,
	DEB_POSTINST,
	DEB_PRERM,
	packageVersion,
	rpmSpec,
} from "./linux/build-linux-packages.mjs";
import { msiInputs } from "./windows/msi-inputs.mjs";

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
exit 0
`;

function fakeSeaBundle({ platform = "linux", arch = "x64" } = {}) {
	const dir = tempDir(`sea-${platform}`);
	const exe = platform === "win32" ? ".exe" : "";
	for (const sub of ["bin", "dist/resources/threats", "dist/resources/allowlists"]) mkdirSync(join(dir, sub), { recursive: true });
	writeFileSync(join(dir, "dist/resources/threats/rules.yaml"), "- id: TEST-1\n");
	writeFileSync(join(dir, "dist/resources/allowlists/domains.yaml"), "domains: []\n");
	writeFileSync(join(dir, "dist/response-worker.cjs"), "");
	for (const name of ["aidr", "aidr-pre-tool-use", "aidr-post-tool-use", "aidr-session-start", "aidr-user-prompt-submit", "aidr-health", "aidr-mcp-server"]) {
		writeFileSync(join(dir, "bin", `${name}${exe}`), name === "aidr" ? FAKE_AIDR : "#!/bin/sh\nexit 0\n", { mode: 0o755 });
	}
	writeDistributionManifest(dir, { version: "0.6.0", platform, arch, nodeVersion: "v22.0.0", createdAt: "2026-01-01T00:00:00.000Z" });
	return dir;
}

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
		const linux = fakeSeaBundle();
		assert.equal(checkSeaBundle(linux, { platform: "linux" }).artifact_id, "claude-code/sea");
		assert.throws(() => checkSeaBundle(linux, { platform: "win32" }), /built for linux, not win32/);
		writeFileSync(join(linux, "bin", "aidr-pre-tool-use"), "tampered");
		assert.throws(() => checkSeaBundle(linux, { platform: "linux" }), /does not match its manifest digest/);
		const incomplete = fakeSeaBundle();
		rmSync(join(incomplete, "bin", "aidr"));
		writeDistributionManifest(incomplete, { version: "0.6.0", platform: "linux", arch: "x64" });
		assert.throws(() => checkSeaBundle(incomplete, { platform: "linux" }), /lacks bin\/aidr/);
	});
});

describe("Windows MSI inputs", () => {
	test("derive the MSI variables from a verified win32 bundle and mark unsigned builds", () => {
		const key = trustKey();
		const sea = fakeSeaBundle({ platform: "win32" });
		const signed = msiInputs({ seaDir: sea, trustKey: key.path, trustKeyFingerprint: key.fingerprint, version: "0.6.0-rc.3", signing: "signed" });
		assert.equal(signed.productVersion, "0.6.0");
		assert.equal(signed.activeSetupVersion, "0,6,0");
		assert.equal(signed.outputName, "singularity-aidr-0.6.0-rc.3-windows-x64.msi");
		const unsigned = msiInputs({ seaDir: sea, trustKey: key.path, trustKeyFingerprint: key.fingerprint, version: "0.6.0", signing: "unsigned" });
		assert.match(unsigned.outputName, /-UNSIGNED\.msi$/);
		assert.throws(() => msiInputs({ seaDir: sea, trustKey: key.path, trustKeyFingerprint: key.fingerprint, version: "0.6.0", signing: "" }), /--signing/);
		assert.throws(() => msiInputs({ seaDir: fakeSeaBundle(), trustKey: key.path, trustKeyFingerprint: key.fingerprint, version: "0.6.0", signing: "signed" }), /not win32/);
		assert.throws(() => msiInputs({ seaDir: sea, trustKey: key.path, trustKeyFingerprint: "1".repeat(64), version: "0.6.0", signing: "signed" }), /fingerprint mismatch/);
	});

	test("the WiX source runs setup for the interactive user only and uninstall before removal", () => {
		const wxs = readFileSync(new URL("./windows/aidr.wxs", import.meta.url), "utf8");
		assert.match(wxs, /Scope="perUserOrMachine"/);
		assert.match(wxs, /<CustomAction Id="AidrSetupForUser"[\s\S]*?ExeCommand="setup"[\s\S]*?Impersonate="yes"/);
		// Never as LocalSystem: both per-user actions are guarded on the SYSTEM SID.
		assert.equal((wxs.match(/UserSID &lt;&gt; &quot;S-1-5-18&quot;/g) ?? []).length, 2);
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

describe("Linux packages", () => {
	test("the RPM spec keeps the SEA bytes as built and removes connectors only on erase", () => {
		const spec = rpmSpec({ version: "0.6.0-rc.1", arch: "x86_64", stagedRoot: "/stage" });
		assert.match(spec, /^Version: 0\.6\.0~rc\.1$/m);
		assert.match(spec, /%global __os_install_post %\{nil\}/);
		assert.match(spec, /%global debug_package %\{nil\}/);
		assert.match(spec, /AutoReqProv: no/);
		assert.match(spec, /%preun\nif \[ "\$1" = "0" \]; then "\/opt\/singularity-aidr\/libexec\/package-hook.sh" preremove 1; fi/);
		assert.match(DEB_POSTINST, /configure\) "\/opt\/singularity-aidr\/libexec\/package-hook.sh" postinstall/);
		assert.match(DEB_PRERM, /remove\|deconfigure\) "\/opt\/singularity-aidr\/libexec\/package-hook.sh" preremove 1/);
		assert.doesNotMatch(DEB_PRERM, /upgrade\)/);
	});

	test("the .deb carries the bundle, the trust key and the aidr link", { skip: !have("dpkg-deb") && "dpkg-deb not installed" }, () => {
		const key = trustKey();
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
		assert.deepEqual(checkSeaBundle(join(prefix, "bundle"), { platform: "linux" }).files.length > 0, true);
		assert.equal(readFileSync(join(prefix, "config/release-public.pem"), "utf8"), readFileSync(key.path, "utf8"));
		assert.equal(statSync(join(prefix, "bundle/bin/aidr")).mode & 0o777, 0o755);
		assert.equal(statSync(join(prefix, "config/release-public.pem")).mode & 0o777, 0o644);
		assert.equal(readlinkSync(join(root, "usr/bin/aidr")), "/opt/singularity-aidr/bundle/bin/aidr");
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

	test("the tarball installs into a prefix, links aidr and uninstalls cleanly", () => {
		const key = trustKey();
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
