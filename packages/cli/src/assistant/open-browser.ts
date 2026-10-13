import { type SpawnOptions, spawn } from "node:child_process";
import { join } from "node:path";

/**
 * Open the assistant's address in the person's default browser with the
 * platform's own launcher, as an argument vector (never a shell string, so the
 * address cannot be read as a command): `xdg-open <url>` on Linux and
 * `explorer.exe <url>` on Windows, which hands it to the default browser the way
 * `start` does without going through cmd.exe.
 */
export function browserLauncher(
	url: string,
	platform: NodeJS.Platform = process.platform,
	env: NodeJS.ProcessEnv = process.env,
): { command: string; args: string[] } | null {
	if (!/^http:\/\/127\.0\.0\.1:\d{1,5}\/(?:#t=[0-9a-f]{64})?$/u.test(url)) return null;
	if (platform === "win32") {
		const windows = env.SystemRoot ?? env.windir ?? "C:\\Windows";
		return { command: join(windows, "explorer.exe"), args: [url] };
	}
	if (platform === "linux") return { command: "xdg-open", args: [url] };
	return null;
}

type Spawner = (command: string, args: string[], options: SpawnOptions) => ReturnType<typeof spawn>;

/** Resolves with null when the launcher started, else the reason it could not. */
export function openInBrowser(
	url: string,
	options: { platform?: NodeJS.Platform; env?: NodeJS.ProcessEnv; spawner?: Spawner } = {},
): Promise<string | null> {
	const launcher = browserLauncher(url, options.platform, options.env);
	if (!launcher)
		return Promise.resolve(`no browser launcher for ${options.platform ?? process.platform}`);
	const spawner = options.spawner ?? spawn;
	return new Promise((resolve) => {
		try {
			const child = spawner(launcher.command, launcher.args, {
				detached: true,
				stdio: "ignore",
				shell: false,
				windowsHide: true,
			});
			child.once("error", (error) => resolve(error.message));
			child.once("spawn", () => {
				child.unref();
				resolve(null);
			});
		} catch (error) {
			resolve(error instanceof Error ? error.message : String(error));
		}
	});
}
