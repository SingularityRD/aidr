import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { DEFAULT_PREFERENCES, type Preferences } from "../shared/contract.js";

/** Validate an untrusted partial preferences object; unknown keys and bad values throw. */
export function validatePreferencesPatch(value: unknown): Partial<Preferences> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new TypeError("preferences must be an object");
	}
	const patch: Partial<Preferences> = {};
	for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
		switch (key) {
			case "language":
				if (raw !== "auto" && raw !== "tr" && raw !== "en") throw new TypeError("invalid language");
				patch.language = raw;
				break;
			case "theme":
				if (raw !== "system" && raw !== "light" && raw !== "dark") throw new TypeError("invalid theme");
				patch.theme = raw;
				break;
			case "notifyOnDeny":
			case "startAtLogin":
				if (typeof raw !== "boolean") throw new TypeError(`${key} must be a boolean`);
				patch[key] = raw;
				break;
			default:
				throw new TypeError(`unknown preference ${key}`);
		}
	}
	return patch;
}

/** Preferences from disk; a missing or damaged file gives the defaults. */
export function loadPreferences(path: string): Preferences {
	try {
		const stored = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
		const valid: Partial<Preferences> = {};
		for (const [key, value] of Object.entries(stored)) {
			try {
				Object.assign(valid, validatePreferencesPatch({ [key]: value }));
			} catch {
				// A bad or retired key falls back to its default.
			}
		}
		return { ...DEFAULT_PREFERENCES, ...valid };
	} catch {
		return { ...DEFAULT_PREFERENCES };
	}
}

export function savePreferences(path: string, preferences: Preferences): void {
	mkdirSync(dirname(path), { recursive: true });
	const temporary = `${path}.${process.pid}.tmp`;
	writeFileSync(temporary, `${JSON.stringify(preferences, null, 2)}\n`, { mode: 0o600 });
	renameSync(temporary, path);
}
