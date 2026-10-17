// Platform helpers of the real-host E2E tier (node --test). The Windows branches
// are exercised here on any OS; the real Windows run is .github/workflows/windows-real-host-e2e.yml.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ADAPTERS, baseEnv, launcher } from "./hosts.mjs";
import { shellFor } from "./run.mjs";

const sandbox = { home: "D:\\t\\home", tmp: "D:\\t\\tmp" };

test("the Windows child environment keeps the sandbox profile, system and Git Bash, and nothing else", () => {
	const env = baseEnv(sandbox, [], "win32", {
		SystemRoot: "C:\\Windows",
		PATHEXT: ".COM;.EXE",
		HTTPS_PROXY: "http://proxy.invalid:8080",
		ANTHROPIC_API_KEY: "operator-key",
		USERPROFILE: "C:\\Users\\user",
	});
	assert.equal(env.HOME, sandbox.home);
	assert.equal(env.USERPROFILE, sandbox.home, "never the operator's profile");
	assert.equal(env.APPDATA, "D:\\t\\home\\AppData\\Roaming");
	assert.equal(env.LOCALAPPDATA, "D:\\t\\home\\AppData\\Local");
	assert.equal(env.TEMP, sandbox.tmp);
	assert.equal(env.SystemRoot, "C:\\Windows");
	assert.equal(env.ComSpec, "C:\\Windows\\System32\\cmd.exe");
	assert.equal(env.CLAUDE_CODE_GIT_BASH_PATH, "C:\\Program Files\\Git\\bin\\bash.exe");
	const entries = env.PATH.split(";");
	for (const entry of ["C:\\Program Files\\Git\\bin", "C:\\Program Files\\Git\\usr\\bin", "C:\\Windows\\System32"]) assert.ok(entries.includes(entry), entry);
	assert.equal(env.HTTPS_PROXY, undefined, "no proxy");
	assert.equal(env.ANTHROPIC_API_KEY, undefined, "no operator credential");
	// The POSIX environment is unchanged.
	const posix = baseEnv({ home: "/t/home", tmp: "/t/tmp" }, [], "linux");
	assert.deepEqual(Object.keys(posix).sort(), ["CI", "HOME", "LANG", "NO_COLOR", "PATH", "TMPDIR", "USERPROFILE"]);
});

test("a JavaScript host entry point runs under this Node.js; a native binary runs directly", () => {
	assert.deepEqual(launcher("C:\\hosts\\codex\\node_modules\\@openai\\codex\\bin\\codex.js", ["exec"]), [process.execPath, ["C:\\hosts\\codex\\node_modules\\@openai\\codex\\bin\\codex.js", "exec"]]);
	assert.deepEqual(launcher("C:\\tools\\claude.exe", ["-p", "x"]), ["C:\\tools\\claude.exe", ["-p", "x"]]);
	assert.deepEqual(launcher("/usr/bin/claude", ["-p"]), ["/usr/bin/claude", ["-p"]]);
});

test("scripted commands follow the host's shell; the pipe-to-shell shape is identical in both", () => {
	const posix = shellFor({});
	assert.equal(`${posix.touch("/w/a.marker")}${posix.then}${posix.echo("ok")}`, "touch '/w/a.marker' && echo ok");
	const powershell = shellFor({ shellDialect: () => "powershell" });
	assert.equal(`${powershell.touch("D:\\w\\a.marker")}${powershell.then}${powershell.echo("ok")}`, "New-Item -ItemType File -Force -Path 'D:\\w\\a.marker' | Out-Null; Write-Output ok");
	assert.equal(powershell.cat("D:\\h\\.ssh\\id_rsa"), "Get-Content -Raw -Path 'D:\\h\\.ssh\\id_rsa'");
	// Claude Code runs its Bash tool through Git Bash on Windows too.
	assert.equal(ADAPTERS["claude-code"].shellDialect, undefined);
	assert.equal(ADAPTERS.codex.shellDialect(), process.platform === "win32" ? "powershell" : "posix");
});
