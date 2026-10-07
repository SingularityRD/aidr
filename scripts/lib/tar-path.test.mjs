import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import test from "node:test";
import { systemTar, tarDirectory } from "./tar-path.mjs";

test("systemTar uses the System32 bsdtar by absolute path on Windows", () => {
	assert.equal(systemTar({ platform: "win32", env: { SystemRoot: "D:\\Win" } }), "D:\\Win\\System32\\tar.exe");
	assert.equal(systemTar({ platform: "win32", env: {} }), "C:\\Windows\\System32\\tar.exe");
	assert.equal(systemTar({ platform: "linux", env: {} }), "tar");
	assert.equal(systemTar({ platform: "darwin", env: {} }), "tar");
});

test("systemTar resolves a runnable tar on this host", { skip: process.platform === "win32" && !existsSync(systemTar()) }, () => {
	const result = spawnSync(systemTar(), ["--version"], { encoding: "utf8" });
	assert.equal(result.status, 0, result.stderr);
	if (process.platform === "win32") assert.match(result.stdout, /bsdtar/);
});

test("tarDirectory is an identity on POSIX separators", () => {
	assert.equal(tarDirectory("a/b"), "a/b");
});
