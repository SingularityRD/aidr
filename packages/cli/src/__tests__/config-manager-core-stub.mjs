import { homedir } from "node:os";
import { join } from "node:path";

export const VERSION = "test-version";

export function resolvePath(value) {
	if (value === "~" || value.startsWith("~/")) {
		return join(process.env.HOME?.trim() || homedir(), value.slice(1));
	}
	return value;
}
