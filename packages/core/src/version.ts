import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

declare const __AIDR_VERSION__: string;

function moduleDirectory(): string {
	try {
		if (typeof import.meta.dirname === "string") return import.meta.dirname;
	} catch {
		// `import.meta.dirname` is not available on older Node versions.
	}
	try {
		if (typeof import.meta.url === "string") return dirname(fileURLToPath(import.meta.url));
	} catch {
		// CommonJS bundles replace import.meta with an empty object.
	}
	return process.cwd();
}

function resolveVersion(): string {
	if (typeof __AIDR_VERSION__ !== "undefined") return __AIDR_VERSION__;

	try {
		const pkgPath = join(moduleDirectory(), "..", "package.json");
		const pkg = JSON.parse(readFileSync(pkgPath, "utf-8")) as { version?: string };
		if (typeof pkg.version === "string") return pkg.version;
	} catch {
		// package.json not found or unreadable
	}

	return "dev";
}

export const VERSION: string = resolveVersion();

export function getVersion(): string {
	return VERSION;
}
