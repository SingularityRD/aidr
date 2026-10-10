/**
 * Terminate a child process together with every process it started.
 *
 * POSIX: the child is spawned `detached`, so it leads its own process group and
 * `process.kill(-pid, signal)` reaches the whole group (bash, pnpm, node,
 * vitest workers, ...). Unrelated processes are never in that group.
 *
 * Windows: there are no process groups and `child.kill()` only ends the outer
 * bash, leaving child/grandchild Node processes alive and holding the stdout
 * pipes open (a 3-minute timeout once took ~5m38s). `taskkill /pid <pid> /T /F`
 * ends the PID-bound tree rooted at the runner's own child - it never matches
 * by image name, so other user or agent processes keep running. Windows console
 * processes ignore the graceful WM_CLOSE that plain `taskkill /T` sends, so both
 * the initial termination and the SIGKILL-equivalent use /F.
 *
 * The platform, spawnSync and process.kill are injectable so the Windows branch
 * is unit-testable on Linux (scripts/ci-local.test.mjs).
 */

import { spawnSync as nodeSpawnSync } from "node:child_process";

/**
 * @param {{ pid?: number, exitCode: number | null, signalCode: string | null, kill(signal?: string): boolean }} child
 * @param {string} signal
 * @param {{ platform?: string, spawnSync?: typeof nodeSpawnSync, processKill?: (pid: number, signal: string) => void }} [deps]
 * @returns {{ method: "none" | "taskkill" | "process-group" | "child", ok: boolean, detail?: string }}
 */
export function terminateProcessTree(child, signal, deps = {}) {
	const platform = deps.platform ?? process.platform;
	const run = deps.spawnSync ?? nodeSpawnSync;
	const processKill = deps.processKill ?? ((pid, sig) => process.kill(pid, sig));
	const pid = child?.pid;
	// Only act on a child we still own: once it has exited its PID may be reused
	// by an unrelated process, which must never be signalled.
	if (!Number.isInteger(pid) || pid <= 0 || child.exitCode !== null || child.signalCode !== null) return { method: "none", ok: true };

	if (platform === "win32") {
		const result = run("taskkill", ["/pid", String(pid), "/T", "/F"], { stdio: "ignore", windowsHide: true, shell: false, timeout: 30_000 });
		if (!result.error && result.status === 0) return { method: "taskkill", ok: true };
		// taskkill missing or failed: still end the direct child so the runner is not left waiting forever.
		const killed = safeKill(child, signal);
		return { method: "child", ok: killed, detail: `taskkill failed (${result.error?.message ?? `exit ${result.status}`})` };
	}

	try {
		processKill(-pid, signal);
		return { method: "process-group", ok: true };
	} catch (error) {
		const killed = safeKill(child, signal);
		return { method: "child", ok: killed, detail: `process group kill failed (${error.message})` };
	}
}

function safeKill(child, signal) {
	try {
		return child.kill(signal);
	} catch {
		return false;
	}
}
