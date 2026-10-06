import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("./check-no-leaky-paths.mjs", import.meta.url));

function scan(t, files) {
	const root = mkdtempSync(join(tmpdir(), "aidr-leaky-paths-"));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	for (const [name, text] of Object.entries(files)) writeFileSync(join(root, name), text);
	const result = spawnSync(process.execPath, [script, root], { encoding: "utf8" });
	assert.equal(result.error, undefined);
	return result;
}

const genericHomeRule = String.raw`ssh.{0,300}/home/[^\s/]{1,64}/\.ssh/`;

test("release scan accepts generic threat regex data without a concrete username", (t) => {
	const result = scan(t, {
		"cache.js": `export const rules = ${JSON.stringify([{ pattern: genericHomeRule }])};\n`,
		"rules.md": genericHomeRule,
	});
	assert.equal(result.status, 0, result.stderr);
});

test("an allowed threat regex cannot hide a concrete host path in the same artifact", (t) => {
	const result = scan(t, {
		"cache.js": `export const rules = ${JSON.stringify([{ pattern: genericHomeRule, path: "/home/alice/private/project" }])};\n`,
	});
	assert.equal(result.status, 1);
	assert.match(result.stderr, /cache\.js \(linux_home\)/u);
});

test("every artifact is checked independently even when identical home paths repeat", (t) => {
	const source = 'export const path = "/home/alice/private/project";\n';
	const result = scan(t, { "first.js": source, "second.js": source });
	assert.equal(result.status, 1);
	assert.match(result.stderr, /first\.js \(linux_home\)/u);
	assert.match(result.stderr, /second\.js \(linux_home\)/u);
});

test("concrete Windows and macOS homes fail in raw and escaped release text", (t) => {
	const windowsHome = String.raw`C:\Users\sam\private\project`;
	const result = scan(t, {
		"windows.md": windowsHome,
		"windows.js": `export const path = ${JSON.stringify(windowsHome)};\n`,
		"mac.js": 'export const path = "/Users/alice/private/project";\n',
	});
	assert.equal(result.status, 1);
	assert.match(result.stderr, /windows\.md \(win_users\)/u);
	assert.match(result.stderr, /windows\.js \(win_users\)/u);
	assert.match(result.stderr, /mac\.js \(mac_users\)/u);
});

test("the shared Windows Public threat title is accepted without exempting user-name prefixes", (t) => {
	const title = String.raw`Script execution from C:\Users\Public (suspicious staging location)`;
	const allowed = scan(t, { "cache.js": `export const rules = ${JSON.stringify([{ title }])};\n` });
	assert.equal(allowed.status, 0, allowed.stderr);
	for (const path of [String.raw`C:\Users\Public-private\project`, String.raw`C:\Users\Public\private-project`]) {
		const leaked = scan(t, { "cache.js": `export const rules = ${JSON.stringify([{ title, path }])};\n` });
		assert.equal(leaked.status, 1);
		assert.match(leaked.stderr, /cache\.js \(win_users\)/u);
	}
});
