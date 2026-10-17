#!/usr/bin/env node
import { lstatSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: { "state-root": { type: "string" }, "install-root": { type: "string" }, write: { type: "string" } } });
if (!values["state-root"] || !values["install-root"]) throw new Error("--state-root and --install-root are required");
const stateRoot = resolve(values["state-root"]);
const installRoot = resolve(values["install-root"]);
const usersDir = join(stateRoot, "users");
const users = [];
let healthy = true;
const entryInfo = (path) => {
	try { return lstatSync(path); }
	catch (error) { if (error.code === "ENOENT") return null; throw error; }
};
const regularFile = (path) => entryInfo(path)?.isFile() === true;
const regularDirectory = (path) => entryInfo(path)?.isDirectory() === true;

if (entryInfo(usersDir)) {
	for (const encoded of readdirSync(usersDir).sort()) {
		const currentPath = join(usersDir, encoded, "release-state");
		const pendingPath = join(usersDir, encoded, "pending");
		const pending = entryInfo(pendingPath) !== null;
		if (!entryInfo(currentPath) && !pending) continue;
		const release = regularFile(currentPath) ? readFileSync(currentPath, "utf8").match(/^current=([a-f0-9]{64})\nprevious=(?:[a-f0-9]{64})?\n$/)?.[1] ?? "" : "";
		const validId = /^[a-f0-9]{64}$/.test(release);
		const packagePath = validId ? join(installRoot, "releases", release, "package") : "";
		const releasePresent = validId && regularDirectory(join(installRoot, "releases", release)) && regularDirectory(packagePath);
		const ok = !pending && releasePresent && regularFile(join(packagePath, "package.json")) &&
			regularDirectory(join(packagePath, "dist")) &&
			["pre-tool-use.cjs", "pre-tool-use.bundle.cjs", "post-tool-use.cjs", "post-tool-use.bundle.cjs", "session-start.cjs", "session-start.bundle.cjs"].every((bundle) => regularFile(join(packagePath, "dist", bundle))) &&
			regularDirectory(join(packagePath, "resources"));
		healthy &&= ok;
		users.push({ user_id: encoded, release_sha256: validId ? release : null, release_present: releasePresent, lifecycle_pending: pending });
	}
}

// Machine scope: the standalone bundle registered in each host's system-wide policy.
const machineDir = join(stateRoot, "machine");
const machineStatePath = join(machineDir, "release-state");
const machinePending = entryInfo(join(machineDir, "pending")) !== null;
let machine = null;
if (entryInfo(machineStatePath) || machinePending) {
	const release = regularFile(machineStatePath) ? readFileSync(machineStatePath, "utf8").match(/^current=([a-f0-9]{64})\nprevious=(?:[a-f0-9]{64})?\n$/)?.[1] ?? "" : "";
	const validId = /^[a-f0-9]{64}$/.test(release);
	const bundlePath = validId ? join(installRoot, "releases", release, "bundle") : "";
	const releasePresent = validId && regularDirectory(join(installRoot, "releases", release)) && regularDirectory(bundlePath) &&
		["bin/aidr", "aidr-artifact.manifest.json", "dist/aidr-artifact.manifest.json"].every((file) => regularFile(join(bundlePath, file)));
	healthy &&= !machinePending && releasePresent;
	machine = { release_sha256: validId ? release : null, release_present: releasePresent, lifecycle_pending: machinePending };
}

const evidence = {
	schema_version: 1,
	checked_at: new Date().toISOString(),
	healthy,
	machine,
	registered_users: users.length,
	users,
	scope: "Installed release presence only. Host hook execution and MDM adoption require external acceptance evidence.",
};
const rendered = `${JSON.stringify(evidence, null, 2)}\n`;
if (values.write) {
	const output = resolve(values.write);
	mkdirSync(dirname(output), { recursive: true, mode: 0o750 });
	const temporary = `${output}.${process.pid}.tmp`;
	writeFileSync(temporary, rendered, { flag: "wx", mode: 0o640 });
	renameSync(temporary, output);
} else process.stdout.write(rendered);
if (!healthy) process.exitCode = 2;
