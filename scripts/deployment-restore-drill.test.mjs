import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { hardenWorkDirectory, validateLocation } from "./deployment-restore-drill.mjs";

test("restore workspace stays outside key custody and filesystem backup target", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-restore-location-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const target = join(root, "offsite");
	const custody = join(root, "custody");
	const work = join(root, "work");
	await Promise.all([mkdir(target), mkdir(custody)]);
	const key = join(custody, "recovery.key");
	await writeFile(key, "fixture\n");
	assert.equal(await validateLocation(work, key, { kind: "filesystem", root: target }), work);
	await assert.rejects(validateLocation(join(target, "unsafe"), key, { kind: "filesystem", root: target }), /separate from the backup target/);
	await assert.rejects(validateLocation(work, key, { kind: "filesystem", root: custody }), /recovery key separate from the backup target/);
	await mkdir(work);
	await assert.rejects(validateLocation(work, key, { kind: "filesystem", root: target }), /new, unused work directory/);
});

test("restore work directory ACL excludes inherited readers before secrets are written", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-restore-acl-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const work = join(root, "work");
	await mkdir(work, { mode: 0o700 });
	assert.equal(await hardenWorkDirectory(work), platform() === "win32" ? "windows-current-user-only" : "posix-owner-only");
});
