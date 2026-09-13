const SECRET_PATH = /api[_-]?key|token|secret|password|private[_-]?key/i;
export function configPathParts(path: string): string[] {
	const parts = path.split(".");
	if (parts.some((part) => !/^[A-Za-z][A-Za-z0-9_]*$/.test(part) || ["__proto__", "prototype", "constructor"].includes(part))) throw new Error("Invalid configuration path");
	return parts;
}
export function displayConfigValue(path: string, value: unknown): string {
	if (SECRET_PATH.test(path)) return value ? "[redacted]" : "(not set)";
	return typeof value === "object" ? "[object]" : String(value);
}
export function parseConfigValue(value: string): unknown {
	try { return JSON.parse(value); } catch { return value; }
}
