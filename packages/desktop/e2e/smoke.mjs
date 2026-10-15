#!/usr/bin/env node
// End-to-end smoke test of the desktop app, driven with Playwright's Electron
// support against an isolated, temporary HOME/USERPROFILE (the real user's
// ~/.claude and ~/.singularity-aidr are never read for writing or changed; the
// test fails if the real Claude settings file changes while it runs).
//
//   connect Claude Code -> run the self-test (deny + allow) -> see both verdicts
//   in the live feed -> disconnect -> settings restored
//
// It takes a screenshot of each screen into docs/screenshots/.
//
//   pnpm --filter @singularityrd/aidr-desktop build && pnpm --filter @singularityrd/aidr-desktop build:runtime
//   pnpm --filter @singularityrd/aidr-desktop test:smoke [-- --lang en]

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { _electron as electron } from "playwright-core";
import { electronBinary } from "../scripts/electron-path.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const langIndex = process.argv.indexOf("--lang");
const language = langIndex >= 0 ? process.argv[langIndex + 1] : "tr";
const packagedIndex = process.argv.indexOf("--packaged");
const packagedExe = packagedIndex >= 0 ? resolve(process.argv[packagedIndex + 1]) : null;
const shots = join(root, "docs", "screenshots", language);
mkdirSync(shots, { recursive: true });

for (const required of packagedExe ? [packagedExe] : ["dist/main/main.cjs", "build/runtime/aidr-sea/bin/aidr.exe", "build/runtime/browser-guard/manifest.json"]) {
	if (!existsSync(resolve(root, required))) {
		console.error(`missing ${required}: run the package's build and build:runtime scripts first`);
		process.exit(1);
	}
}

const realSettings = join(homedir(), ".claude", "settings.json");
const digest = (path) => (existsSync(path) ? createHash("sha256").update(readFileSync(path)).digest("hex") : "absent");
const realBefore = digest(realSettings);

const sandbox = mkdtempSync(join(tmpdir(), "aidr-desktop-smoke-"));
const home = join(sandbox, "home");
const userData = join(sandbox, "electron-user-data");
mkdirSync(join(home, ".claude"), { recursive: true });
mkdirSync(userData, { recursive: true });
writeFileSync(
	join(userData, "preferences.json"),
	`${JSON.stringify({ language, theme: "light", notifyOnDeny: true, startAtLogin: false }, null, 2)}\n`,
);

// The user's own settings: an unrelated hook and other keys AIDR must keep.
const settingsPath = join(home, ".claude", "settings.json");
const original = {
	model: "opus",
	permissions: { allow: ["Bash(npm test:*)"] },
	hooks: {
		PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo user-owned-hook" }] }],
	},
};
const originalText = `${JSON.stringify(original, null, 2)}\n`;
writeFileSync(settingsPath, originalText);

const results = [];
function check(name, condition, detail = "") {
	results.push({ name, ok: Boolean(condition), detail });
	console.log(`${condition ? "PASS" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
	if (!condition) throw new Error(`check failed: ${name} ${detail}`);
}

const env = {
	...process.env,
	HOME: home,
	USERPROFILE: home,
	AIDR_DESKTOP_USER_DATA: userData,
};
delete env.ELECTRON_RUN_AS_NODE;

let app;
let page;
let failed = false;
const started = Date.now();
try {
	app = await electron.launch({
		executablePath: packagedExe ?? electronBinary(),
		args: packagedExe ? [] : [root],
		env,
		cwd: sandbox,
		timeout: 60_000,
	});
	page = await app.firstWindow();
	await page.setViewportSize({ width: 1280, height: 860 });
	const shot = async (name) => {
		await page.waitForTimeout(400);
		await page.screenshot({ path: join(shots, `${name}.png`) });
		console.log(`      screenshot docs/screenshots/${language}/${name}.png`);
	};

	// 1. Status home, not connected.
	await page.getByTestId("status-headline").waitFor({ timeout: 60_000 });
	await page.waitForFunction(() => document.querySelector('[data-testid="fact-rules"]')?.textContent?.match(/^\d+$/), null, { timeout: 90_000 });
	const rules = Number(await page.getByTestId("fact-rules").textContent());
	check("engine reports loaded rules", rules > 100, `${rules} rules`);
	check("starts not protected", (await page.getByTestId("protection-badge").getAttribute("class")).includes("warn"));
	check("enforcement mode is shown", ((await page.getByTestId("fact-mode").textContent()) ?? "").length > 0);
	await shot("01-status-not-connected");

	// 2. Connect Claude Code: preview first.
	await page.getByTestId("connect-claude").click();
	await page.getByTestId("connect-modal").waitFor();
	const diffText = await page.getByTestId("connect-diff").textContent();
	check("preview shows the AIDR hook being added", diffText.includes("hook pre-tool-use") && diffText.includes("Singularity AIDR managed installation"));
	check("preview keeps the user's hook", diffText.includes("echo user-owned-hook"));
	await shot("02-connect-preview");
	await page.getByTestId("connect-confirm").click();
	await page.getByTestId("action-banner").waitFor({ timeout: 180_000 });
	const banner = await page.getByTestId("action-banner").getAttribute("class");
	check("connect succeeded", banner.includes("ok"), (await page.getByTestId("action-banner").textContent()).slice(0, 300));
	await page.waitForFunction(() => document.querySelector('[data-testid="protection-badge"]')?.className.includes("ok"), null, { timeout: 60_000 });
	check("status is protected", true);
	const connected = JSON.parse(readFileSync(settingsPath, "utf8"));
	const preCommands = connected.hooks.PreToolUse.flatMap((entry) => entry.hooks.map((hook) => hook.command));
	check("settings keep the user's hook", preCommands.includes("echo user-owned-hook"));
	check(
		"settings run the hook from the per-user runtime",
		preCommands.some((command) => command.includes("/.singularity-aidr/desktop/runtime/") && command.endsWith("hook pre-tool-use")),
		preCommands.join(" | "),
	);
	check("PostToolUse and SessionStart registered", Boolean(connected.hooks.PostToolUse && connected.hooks.SessionStart));
	check("other settings kept", connected.model === "opus" && connected.permissions.allow[0] === "Bash(npm test:*)");
	await shot("03-status-connected");

	// 3. Record allowed calls too, so the self-test's allow shows in the feed.
	await page.getByTestId("nav-activity").click();
	const toggle = page.getByTestId("log-clean-toggle");
	await toggle.waitFor();
	if (!(await toggle.isChecked())) await toggle.check();
	await page.waitForFunction(() => document.querySelector('[data-testid="log-clean-toggle"]')?.checked === true, null, { timeout: 30_000 });
	const config = JSON.parse(readFileSync(join(home, ".singularity-aidr", "config.json"), "utf8"));
	check("logging.log_clean written", config.logging?.log_clean === true);

	// 4. Prove it works.
	await page.getByTestId("nav-selftest").click();
	const selfTestStarted = () =>
		page
			.waitForFunction(
				() =>
					document.querySelector('[data-testid="run-selftest"]')?.disabled ||
					document.querySelector('[data-testid="selftest-summary"], [data-testid="selftest-error"]'),
				null,
				{ timeout: 10_000 },
			)
			.then(() => true, () => false);
	await page.getByTestId("run-selftest").click();
	if (!(await selfTestStarted())) await page.getByTestId("run-selftest").click();
	await page.getByTestId("selftest-summary").waitFor({ timeout: 120_000 });
	const benign = await page.getByTestId("verdict-benign").getAttribute("class");
	const canary = await page.getByTestId("verdict-canary").getAttribute("class");
	const latencyBenign = await page.getByTestId("latency-benign").textContent();
	const latencyCanary = await page.getByTestId("latency-canary").textContent();
	check("benign command allowed by the installed hook", benign.includes("allow"), latencyBenign);
	check("deny canary denied by the installed hook", canary.includes("deny"), latencyCanary);
	check("self-test passed", (await page.getByTestId("selftest-summary").getAttribute("class")).includes("ok"));
	await shot("04-self-test");

	// 5. Live activity shows both verdicts.
	await page.getByTestId("nav-activity").click();
	await page.waitForFunction(
		() => {
			const rows = [...document.querySelectorAll('[data-testid="activity-row"]')];
			return rows.some((row) => row.getAttribute("data-decision") === "deny") && rows.some((row) => row.getAttribute("data-decision") === "allow");
		},
		null,
		{ timeout: 30_000 },
	);
	const feed = await page.getByTestId("activity-table").textContent();
	check("feed shows the denied canary with its rule", feed.includes("CLT-CMD-001") && feed.includes("evil.test"));
	check("feed shows the allowed command", feed.includes("ls -la"));
	await shot("05-live-activity");
	await page.getByTestId("filter-deny").click();
	const denyRows = await page.locator('[data-testid="activity-row"]').evaluateAll((rows) => rows.map((row) => row.getAttribute("data-decision")));
	check("deny filter shows only denies", denyRows.length > 0 && denyRows.every((decision) => decision === "deny"), `${denyRows.length} row(s)`);
	await page.getByTestId("filter-all").click();

	// 6. Browser Guard.
	await page.getByTestId("nav-browserGuard").click();
	await page.getByTestId("bg-install").waitFor({ timeout: 30_000 });
	await page.getByTestId("bg-prepare").click();
	await page.getByTestId("bg-staged-path").waitFor({ timeout: 30_000 });
	const staged = (await page.getByTestId("bg-staged-path").textContent()) ?? "";
	check("Browser Guard staged inside the profile", staged.includes(".singularity-aidr") && existsSync(join(home, ".singularity-aidr", "desktop", "browser-guard")));
	await shot("06-browser-guard");

	// 7. Settings.
	await page.getByTestId("nav-settings").click();
	await page.getByTestId("page-settings").waitFor();
	await shot("07-settings");

	// 8. Disconnect: settings restored.
	await page.getByTestId("nav-status").click();
	await page.getByTestId("disconnect-claude").click();
	await page.getByTestId("disconnect-confirm").click();
	await page.waitForFunction(
		() => document.querySelector('[data-testid="action-banner"]') && !document.querySelector('[data-testid="disconnect-claude"]'),
		null,
		{ timeout: 120_000 },
	);
	check("disconnect succeeded", (await page.getByTestId("action-banner").getAttribute("class")).includes("ok"), (await page.getByTestId("action-banner").textContent()).slice(0, 200));
	const restored = readFileSync(settingsPath, "utf8");
	check("settings restored to the user's original", JSON.stringify(JSON.parse(restored)) === JSON.stringify(original));
	check("settings restored byte for byte", restored === originalText);
	check("status is not protected again", (await page.getByTestId("protection-badge").getAttribute("class")).includes("warn"));
	await shot("08-status-disconnected");
} catch (error) {
	failed = true;
	console.error(error);
	if (page) {
		await page.screenshot({ path: join(sandbox, "failure.png") }).catch(() => undefined);
		console.error((await page.locator("main").innerText().catch(() => "")).slice(0, 3000));
	}
} finally {
	await app?.close().catch(() => undefined);
	const realAfter = digest(realSettings);
	if (realAfter !== realBefore) {
		failed = true;
		console.error("FAIL  the real ~/.claude/settings.json changed during the test");
	} else {
		console.log("PASS  the real ~/.claude/settings.json was not touched");
	}
	if (!process.argv.includes("--keep")) rmSync(sandbox, { recursive: true, force: true, maxRetries: 5 });
	else console.log(`sandbox kept: ${sandbox}`);
}
const passed = results.filter((entry) => entry.ok).length;
console.log(`\n${failed ? "SMOKE FAILED" : "SMOKE PASSED"}: ${passed}/${results.length} checks in ${Math.round((Date.now() - started) / 1000)} s`);
process.exit(failed ? 1 : 0);
