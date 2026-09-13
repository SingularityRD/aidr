#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: { "state-root": { type: "string" }, "install-root": { type: "string" }, write: { type: "string" } } });
if (!values["state-root"] || !values["install-root"]) throw new Error("--state-root and --install-root are required");
const stateRoot = resolve(values["state-root"]);
const installRoot = resolve(values["install-root"]);
const usersDir = join(stateRoot, "users");
const users = [];
let healthy = true;

if (existsSync(usersDir)) {
	for (const encoded of readdirSync(usersDir).sort()) {
		const currentPath = join(usersDir, encoded, "release-state");
		const pendingPath = join(usersDir, encoded, "pending");
		const pending = existsSync(pendingPath) && statSync(pendingPath).isFile();
		if ((!existsSync(currentPath) || !statSync(currentPath).isFile()) && !pending) continue;
		const release = existsSync(currentPath) ? readFileSync(currentPath, "utf8").match(/^current=([a-f0-9]{64})$/m)?.[1] ?? "" : "";
		const validId = /^[a-f0-9]{64}$/.test(release);
		const packagePath = validId ? join(installRoot, "releases", release, "package") : "";
		const ok = !pending && validId && existsSync(join(packagePath, "package.json")) && existsSync(join(packagePath, "dist", "pre-tool-use.cjs"));
		healthy &&= ok;
		users.push({ user_id: encoded, release_sha256: validId ? release : null, release_present: validId && existsSync(packagePath), lifecycle_pending: pending });
	}
}

const evidence = {
	schema_version: 1,
	checked_at: new Date().toISOString(),
	healthy,
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
