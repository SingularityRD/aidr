// Historically this used a string-split require() indirection due to a third-party false positive.
// For commercial runtime builds (bundled CJS and Node ESM), we keep it simple and standards-compliant.
import { type ChildProcess, spawn as nodeSpawn, type SpawnOptions } from "node:child_process";

export function spawn(command: string, args: string[], options: SpawnOptions): ChildProcess {
	return nodeSpawn(command, args, options);
}
