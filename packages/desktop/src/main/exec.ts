import { spawn } from "node:child_process";

interface RunResult {
	exitCode: number | null;
	signal: NodeJS.Signals | null;
	stdout: string;
	stderr: string;
	/** Wall-clock time from spawn to exit, in milliseconds. */
	durationMs: number;
	/** Set when the process could not be started or was killed by the timeout. */
	error: string | null;
}

export interface RunOptions {
	cwd?: string;
	env?: NodeJS.ProcessEnv;
	input?: string;
	timeoutMs?: number;
}

/**
 * Run a program with an argument array and no shell. Arguments are never
 * joined into a command line that a shell parses, so nothing in them is
 * interpreted (no injection through paths, payloads or user input).
 */
export type Runner = (
	file: string,
	args: readonly string[],
	options?: RunOptions,
) => Promise<RunResult>;

export const runFile: Runner = (file, args, options = {}) =>
	new Promise((resolve) => {
		const started = performance.now();
		let stdout = "";
		let stderr = "";
		let settled = false;
		let timedOut = false;
		const finish = (result: Omit<RunResult, "durationMs" | "stdout" | "stderr">) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve({ ...result, stdout, stderr, durationMs: Math.round(performance.now() - started) });
		};
		let child: ReturnType<typeof spawn>;
		try {
			child = spawn(file, [...args], {
				cwd: options.cwd,
				env: options.env ?? process.env,
				shell: false,
				windowsHide: true,
				stdio: ["pipe", "pipe", "pipe"],
			});
		} catch (error) {
			resolve({
				exitCode: null,
				signal: null,
				stdout: "",
				stderr: "",
				durationMs: 0,
				error: error instanceof Error ? error.message : String(error),
			});
			return;
		}
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill();
		}, options.timeoutMs ?? 60_000);
		child.stdout?.setEncoding("utf8");
		child.stderr?.setEncoding("utf8");
		child.stdout?.on("data", (chunk: string) => {
			if (stdout.length < 4 * 1024 * 1024) stdout += chunk;
		});
		child.stderr?.on("data", (chunk: string) => {
			if (stderr.length < 1024 * 1024) stderr += chunk;
		});
		child.on("error", (error) => finish({ exitCode: null, signal: null, error: error.message }));
		child.on("close", (code, signal) =>
			finish({
				exitCode: code,
				signal,
				error: timedOut ? `timed out after ${options.timeoutMs ?? 60_000} ms` : null,
			}),
		);
		child.stdin?.on("error", () => {
			// The program may exit without reading its input; that is reported by its exit.
		});
		child.stdin?.end(options.input ?? "");
	});
