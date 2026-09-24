#!/usr/bin/env node
import { constants, realpathSync } from "node:fs";
import { chmod, open, rename, rm } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { platform } from "node:os";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: { "health-file": { type: "string" } } });
if (!values["health-file"] || !isAbsolute(values["health-file"])) throw new Error("--health-file must be absolute");
const healthFile = resolve(values["health-file"]);
if (realpathSync(dirname(healthFile)) !== dirname(healthFile)) throw new Error("Health directory contains a symbolic-link ancestor");
const temporary = `${healthFile}.${process.pid}.failed.tmp`;
const timestamp = new Date().toISOString();
try {
	const handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
	try {
		await handle.writeFile(`${JSON.stringify({ schema_version: 1, status: "failed", completed_at: timestamp, verified_at: timestamp }, null, 2)}\n`);
		await handle.sync();
	} finally {
		await handle.close();
	}
	await chmod(temporary, 0o644);
	await rename(temporary, healthFile);
	const directory = await open(dirname(healthFile), "r");
	try {
		try { await directory.sync(); } catch (error) { if (platform() !== "win32") throw error; }
	} finally { await directory.close(); }
} catch (error) {
	await rm(temporary, { force: true });
	throw error;
}
