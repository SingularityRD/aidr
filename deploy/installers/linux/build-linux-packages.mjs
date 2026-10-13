#!/usr/bin/env node
// Build the Linux desktop installers (.deb, .rpm and a tarball) from a
// release-flavour SEA bundle built on Linux and signed with the release key
// (`build-sea.mjs --flavor release`, then `--sign`). All three carry the same layout:
//
//   /opt/singularity-aidr/bundle/...                  the SEA directory, unchanged
//                                                     (one multi-call bin/aidr)
//   /opt/singularity-aidr/config/release-public.pem   release trust key
//   /opt/singularity-aidr/config/installer-catalog-public.pem  `aidr update` catalog key (optional, --catalog-key)
//   /opt/singularity-aidr/libexec/package-hook.sh     postinstall / preremove
//   /usr/bin/aidr -> /opt/singularity-aidr/bundle/bin/aidr   (.deb / .rpm)
//   /usr/share/applications/singularity-aidr-assistant.desktop  menu entry for
//                                                     `aidr assistant` (.deb / .rpm)
//
// Usage:
//   node deploy/installers/linux/build-linux-packages.mjs \
//     --sea-dir bin/aidr-sea --trust-key release-public.pem \
//     --trust-key-fingerprint <sha256> --version 0.6.0 --out dist-installers \
//     [--formats deb,rpm,tar] [--maintainer "Name <address>"] [--catalog-key catalog-public.pem]
//
// .deb needs dpkg-deb and .rpm needs rpmbuild on PATH; a requested format whose
// tool is missing fails the build. Signing is a separate step (CI signs the
// outputs with the Linux package key, see .github/workflows/release-rc.yml).

import { spawnSync } from "node:child_process";
import {
	chmodSync,
	copyFileSync,
	cpSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
	CATALOG_KEY_FILE,
	checkCatalogKey,
	checkSeaBundle,
	checkTrustKey,
	checkVersion,
	InstallerInputError,
	LINUX_PREFIX,
	MAINTAINER,
	PACKAGE_NAME,
	parseFlags,
	sha256Of,
} from "../lib/common.mjs";

const here = dirname(fileURLToPath(import.meta.url));
export const PACKAGE_HOOK = join(here, "package-hook.sh");
export const FORMATS = Object.freeze(["deb", "rpm", "tar"]);

/** Application-menu entry that opens the Setup Assistant (`aidr assistant`) in the browser. */
export const ASSISTANT_DESKTOP_FILE = "/usr/share/applications/singularity-aidr-assistant.desktop";
export const ASSISTANT_DESKTOP = `[Desktop Entry]
Type=Application
Version=1.0
Name=Singularity AIDR Setup Assistant
Name[tr]=Singularity AIDR Kurulum Yardımcısı
Comment=Protect the AI tools on this computer
Comment[tr]=Bu bilgisayardaki yapay zekâ araçlarını koruyun
Exec=/usr/bin/aidr assistant
Icon=security-high
Terminal=false
Categories=Utility;Security;
Keywords=AIDR;AI;security;setup;
StartupNotify=false
`;

const ARCH = {
	x64: { deb: "amd64", rpm: "x86_64", tar: "x64" },
	arm64: { deb: "arm64", rpm: "aarch64", tar: "arm64" },
};

export function archNames(seaArch) {
	const names = ARCH[seaArch];
	if (!names) throw new InstallerInputError(`unsupported SEA architecture ${seaArch}`);
	return names;
}

/** Debian and RPM order a prerelease before its release only with `~`. */
export const packageVersion = (version) => version.replace("-", "~");

function setModes(root) {
	for (const name of readdirSync(root, { withFileTypes: true })) {
		const path = join(root, name.name);
		if (name.isSymbolicLink()) continue;
		if (name.isDirectory()) {
			chmodSync(path, 0o755);
			setModes(path);
		} else {
			const executable = /\/bin\/[^/]+$/u.test(path) || path.endsWith(".sh");
			chmodSync(path, executable ? 0o755 : 0o644);
		}
	}
}

/**
 * Stage the file tree every format shares under `<root>`.
 * @returns {{ prefix: string }} the staged prefix directory
 */
export function stageLinuxRoot({ root, seaDir, trustKeyPem, catalogKeyPem, withUsrBin = true }) {
	const prefix = join(root, LINUX_PREFIX.slice(1));
	mkdirSync(join(prefix, "config"), { recursive: true });
	mkdirSync(join(prefix, "libexec"), { recursive: true });
	cpSync(seaDir, join(prefix, "bundle"), { recursive: true });
	writeFileSync(join(prefix, "config", "release-public.pem"), trustKeyPem);
	if (catalogKeyPem) writeFileSync(join(prefix, "config", CATALOG_KEY_FILE), catalogKeyPem);
	copyFileSync(PACKAGE_HOOK, join(prefix, "libexec", "package-hook.sh"));
	setModes(root);
	if (withUsrBin) {
		mkdirSync(join(root, "usr", "bin"), { recursive: true });
		chmodSync(join(root, "usr"), 0o755);
		chmodSync(join(root, "usr", "bin"), 0o755);
		symlinkSync(`${LINUX_PREFIX}/bundle/bin/aidr`, join(root, "usr", "bin", "aidr"));
		const applications = join(root, ASSISTANT_DESKTOP_FILE.slice(1, ASSISTANT_DESKTOP_FILE.lastIndexOf("/")));
		mkdirSync(applications, { recursive: true });
		for (const dir of [join(root, "usr", "share"), applications]) chmodSync(dir, 0o755);
		writeFileSync(join(root, ASSISTANT_DESKTOP_FILE.slice(1)), ASSISTANT_DESKTOP, { mode: 0o644 });
	}
	return { prefix };
}

export function debControl({ version, arch, maintainer = MAINTAINER, installedSizeKb }) {
	return [
		`Package: ${PACKAGE_NAME}`,
		`Version: ${packageVersion(version)}`,
		`Architecture: ${arch}`,
		`Maintainer: ${maintainer}`,
		`Installed-Size: ${installedSizeKb}`,
		"Section: utils",
		"Priority: optional",
		"Homepage: https://singularityrd.com",
		"Description: Singularity AIDR - AI agent detection and response",
		" Guards the commands, files and web requests of AI coding agents (Claude Code,",
		" Cursor, VS Code, Codex, OpenCode, OpenClaw). Self-contained: no Node.js needed.",
		"",
	].join("\n");
}

/** dpkg maintainer scripts: setup on configure; connector removal only on a real removal. */
export const DEB_POSTINST = `#!/bin/sh
set -e
case "$1" in
configure) "${LINUX_PREFIX}/libexec/package-hook.sh" postinstall ;;
esac
exit 0
`;
export const DEB_PRERM = `#!/bin/sh
set -e
case "$1" in
remove|deconfigure) "${LINUX_PREFIX}/libexec/package-hook.sh" preremove 1 ;;
esac
exit 0
`;

function duKb(path) {
	const result = spawnSync("du", ["-sk", path], { encoding: "utf8" });
	return Number.parseInt(`${result.stdout}`.split(/\s/u)[0], 10) || 0;
}

function tool(name) {
	const found = spawnSync("sh", ["-c", `command -v ${name}`], { encoding: "utf8" });
	return found.status === 0 ? found.stdout.trim() : null;
}

function run(command, args, options = {}) {
	const result = spawnSync(command, args, { stdio: ["ignore", "inherit", "inherit"], ...options });
	if (result.error) throw result.error;
	if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} exited with ${result.status}`);
}

export function buildDeb({ seaDir, trustKeyPem, catalogKeyPem, version, arch, out, work, maintainer }) {
	if (!tool("dpkg-deb")) throw new InstallerInputError("dpkg-deb is required to build the .deb");
	const root = join(work, "deb-root");
	stageLinuxRoot({ root, seaDir, trustKeyPem, catalogKeyPem });
	mkdirSync(join(root, "DEBIAN"), { mode: 0o755 });
	writeFileSync(join(root, "DEBIAN", "control"), debControl({ version, arch, maintainer, installedSizeKb: duKb(root) }));
	writeFileSync(join(root, "DEBIAN", "postinst"), DEB_POSTINST, { mode: 0o755 });
	writeFileSync(join(root, "DEBIAN", "prerm"), DEB_PRERM, { mode: 0o755 });
	const file = join(out, `${PACKAGE_NAME}_${packageVersion(version)}_${arch}.deb`);
	run("dpkg-deb", ["--root-owner-group", "-Zxz", "--build", root, file]);
	return file;
}

/**
 * RPM spec. rpmbuild's post-install processing (strip, build-id links,
 * debuginfo, automatic dependencies) would rewrite or misdescribe the SEA
 * binaries, so all of it is off: the payload is the verified bundle as built.
 */
export function rpmSpec({ version, arch, stagedRoot, maintainer = MAINTAINER }) {
	const rpmVersion = packageVersion(version);
	return `%global __os_install_post %{nil}
%global debug_package %{nil}
%define _build_id_links none
%define _binaries_in_noarch_packages_terminate_build 0
Name: ${PACKAGE_NAME}
Version: ${rpmVersion}
Release: 1
Summary: Singularity AIDR - AI agent detection and response
License: Proprietary
Packager: ${maintainer}
URL: https://singularityrd.com
BuildArch: ${arch}
AutoReqProv: no

%description
Guards the commands, files and web requests of AI coding agents (Claude Code,
Cursor, VS Code, Codex, OpenCode, OpenClaw). Self-contained: no Node.js needed.

%install
mkdir -p %{buildroot}
cp -a "${stagedRoot}/." %{buildroot}/

%post
"${LINUX_PREFIX}/libexec/package-hook.sh" postinstall

%preun
if [ "$1" = "0" ]; then "${LINUX_PREFIX}/libexec/package-hook.sh" preremove 1; fi

%files
%defattr(-,root,root,-)
${LINUX_PREFIX}
/usr/bin/aidr
${ASSISTANT_DESKTOP_FILE}
`;
}

export function buildRpm({ seaDir, trustKeyPem, catalogKeyPem, version, arch, out, work, maintainer }) {
	if (!tool("rpmbuild")) throw new InstallerInputError("rpmbuild is required to build the .rpm");
	const root = join(work, "rpm-root");
	stageLinuxRoot({ root, seaDir, trustKeyPem, catalogKeyPem });
	const top = join(work, "rpmbuild");
	for (const dir of ["BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS", "BUILDROOT"]) mkdirSync(join(top, dir), { recursive: true });
	const spec = join(top, "SPECS", `${PACKAGE_NAME}.spec`);
	writeFileSync(spec, rpmSpec({ version, arch, stagedRoot: root, maintainer }));
	run("rpmbuild", ["-bb", "--define", `_topdir ${top}`, "--target", arch, spec]);
	const built = join(top, "RPMS", arch, `${PACKAGE_NAME}-${packageVersion(version)}-1.${arch}.rpm`);
	if (!existsSync(built)) throw new Error(`rpmbuild did not produce ${built}`);
	const file = join(out, basename(built));
	copyFileSync(built, file);
	return file;
}

export const TAR_INSTALL = `#!/bin/sh
# Install Singularity AIDR from this tarball (run with sudo for /opt).
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFIX=\${AIDR_PREFIX:-${LINUX_PREFIX}}
BIN_LINK=\${AIDR_BIN_LINK:-/usr/local/bin/aidr}
[ ! -e "$PREFIX/bundle" ] || { echo "$PREFIX/bundle exists; run uninstall.sh first" >&2; exit 1; }
mkdir -p "$PREFIX"
cp -R "$HERE/bundle" "$HERE/config" "$HERE/libexec" "$PREFIX/"
"$PREFIX/bundle/bin/aidr" --version >/dev/null
mkdir -p "$(dirname "$BIN_LINK")" && ln -sf "$PREFIX/bundle/bin/aidr" "$BIN_LINK"
AIDR_PREFIX="$PREFIX" "$PREFIX/libexec/package-hook.sh" postinstall
`;

export const TAR_UNINSTALL = `#!/bin/sh
# Remove Singularity AIDR installed from this tarball.
set -eu
PREFIX=\${AIDR_PREFIX:-${LINUX_PREFIX}}
BIN_LINK=\${AIDR_BIN_LINK:-/usr/local/bin/aidr}
[ -d "$PREFIX/bundle" ] || { echo "$PREFIX/bundle not found" >&2; exit 1; }
AIDR_PREFIX="$PREFIX" "$PREFIX/libexec/package-hook.sh" preremove 1
rm -f "$BIN_LINK"
rm -rf "$PREFIX/bundle" "$PREFIX/config" "$PREFIX/libexec"
rmdir "$PREFIX" 2>/dev/null || true
`;

export function buildTarball({ seaDir, trustKeyPem, catalogKeyPem, version, arch, out, work }) {
	const name = `${PACKAGE_NAME}-${version}-linux-${arch}`;
	const stage = join(work, "tar-root");
	const root = join(stage, "staged");
	const { prefix } = stageLinuxRoot({ root, seaDir, trustKeyPem, catalogKeyPem, withUsrBin: false });
	const top = join(stage, name);
	cpSync(prefix, top, { recursive: true });
	writeFileSync(join(top, "install.sh"), TAR_INSTALL, { mode: 0o755 });
	writeFileSync(join(top, "uninstall.sh"), TAR_UNINSTALL, { mode: 0o755 });
	const file = join(out, `${name}.tar.gz`);
	const epoch = process.env.SOURCE_DATE_EPOCH;
	run("tar", [
		"--sort=name",
		"--owner=0",
		"--group=0",
		"--numeric-owner",
		...(epoch ? [`--mtime=@${epoch}`] : []),
		"-C",
		stage,
		"-czf",
		file,
		name,
	]);
	return file;
}

export function writeSha256Sums(out, files) {
	const lines = files.map((file) => `${sha256Of(file)}  ${basename(file)}`).sort((a, b) => a.slice(66).localeCompare(b.slice(66)));
	const path = join(out, "SHA256SUMS");
	writeFileSync(path, `${lines.join("\n")}\n`);
	return path;
}

export function buildLinuxPackages(options) {
	const version = checkVersion(options.version);
	const seaDir = resolve(options.seaDir);
	const { pem } = checkTrustKey(options.trustKey, options.trustKeyFingerprint);
	const manifest = checkSeaBundle(seaDir, { platform: "linux", trustKeyPem: pem });
	if (manifest.artifact_version !== version.replace(/-.*$/u, "") && manifest.artifact_version !== version) {
		throw new InstallerInputError(`SEA bundle version ${manifest.artifact_version} does not match ${version}`);
	}
	const formats = (options.formats ?? FORMATS.join(",")).split(",").map((entry) => entry.trim());
	for (const format of formats) if (!FORMATS.includes(format)) throw new InstallerInputError(`unknown format ${format}`);
	const names = archNames(manifest.sea.arch);
	const out = resolve(options.out);
	mkdirSync(out, { recursive: true });
	const work = mkdtempSync(join(options.workRoot ?? tmpdir(), "aidr-linux-installers-"));
	const catalogKeyPem = options.catalogKey ? checkCatalogKey(options.catalogKey).pem : undefined;
	const common = { seaDir, trustKeyPem: pem, catalogKeyPem, version, out, work, maintainer: options.maintainer };
	try {
		const files = [];
		if (formats.includes("deb")) files.push(buildDeb({ ...common, arch: names.deb }));
		if (formats.includes("rpm")) files.push(buildRpm({ ...common, arch: names.rpm }));
		if (formats.includes("tar")) files.push(buildTarball({ ...common, arch: names.tar }));
		const sums = writeSha256Sums(out, files);
		return { files, sums, manifest };
	} finally {
		rmSync(work, { recursive: true, force: true });
	}
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	try {
		const flags = parseFlags(process.argv.slice(2), ["sea-dir", "trust-key", "trust-key-fingerprint", "version", "out", "formats", "maintainer", "catalog-key"]);
		for (const required of ["sea-dir", "trust-key", "trust-key-fingerprint", "version", "out"]) {
			if (!flags[required]) throw new InstallerInputError(`--${required} is required`);
		}
		const { files, sums } = buildLinuxPackages({
			seaDir: flags["sea-dir"],
			trustKey: flags["trust-key"],
			trustKeyFingerprint: flags["trust-key-fingerprint"],
			version: flags.version,
			out: flags.out,
			formats: flags.formats,
			maintainer: flags.maintainer,
			catalogKey: flags["catalog-key"],
		});
		for (const file of [...files, sums]) console.log(`built ${file}`);
		console.log("UNSIGNED: sign the packages (rpm --addsign, detached .asc for .deb/.tar.gz) before distribution.");
	} catch (error) {
		console.error(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
		process.exit(1);
	}
}
