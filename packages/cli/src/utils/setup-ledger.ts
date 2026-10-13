import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { HostId } from "./connector-install.js";

/**
 * What the most recent `aidr setup` registered, so `aidr status` can tell the
 * user which hosts must be restarted to load AIDR. A running host loads its
 * hooks/plugins at start, so a registration written by setup takes effect only
 * after a restart of a host that was already open at `completed_at`.
 */
export interface SetupLedger {
	schema_version: 1;
	completed_at: string;
	/** Hosts setup installed or updated in that run (not ones already registered). */
	registered: HostId[];
}

const SETUP_LEDGER_RELATIVE = join(".singularity-aidr", "last-setup.json");

export function writeSetupLedger(home: string, registered: HostId[], now = new Date()): void {
	const dir = join(home, ".singularity-aidr");
	mkdirSync(dir, { recursive: true, mode: 0o700 });
	const path = join(home, SETUP_LEDGER_RELATIVE);
	const ledger: SetupLedger = { schema_version: 1, completed_at: now.toISOString(), registered };
	const temporary = `${path}.${process.pid}.tmp`;
	writeFileSync(temporary, `${JSON.stringify(ledger, null, 2)}\n`, { mode: 0o600 });
	renameSync(temporary, path);
}

/** The ledger, or null when absent or not one this version wrote. */
export function readSetupLedger(home: string): SetupLedger | null {
	try {
		const parsed = JSON.parse(readFileSync(join(home, SETUP_LEDGER_RELATIVE), "utf8"));
		if (
			parsed?.schema_version === 1 &&
			typeof parsed.completed_at === "string" &&
			Array.isArray(parsed.registered) &&
			parsed.registered.every((id: unknown) => typeof id === "string")
		) {
			return parsed as SetupLedger;
		}
	} catch {
		// Absent or unreadable: no restart hint, never a false one.
	}
	return null;
}
