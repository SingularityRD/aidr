import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const j = JSON.parse(readFileSync(resolve(root, "READINESS_BACKLOG.json"), "utf8"));
const findings = j.findings ?? j.items ?? [];

const order = { P0: 0, P1: 1, P2: 2 };
const open = findings
	.filter((f) => f.status !== "VERIFIED_CLOSED")
	.sort((a, b) => (order[a.priority] ?? 9) - (order[b.priority] ?? 9) || a.id.localeCompare(b.id));

for (const f of open) {
	console.log(`${f.id} | ${f.priority} | ${f.status} | ${f.feature}`);
}
console.log(`\nopen: ${open.length} / ${findings.length}`);
