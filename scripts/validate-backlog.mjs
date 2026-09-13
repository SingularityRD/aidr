import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const raw = readFileSync(resolve(root, "READINESS_BACKLOG.json"), "utf8");
let j;
try {
  j = JSON.parse(raw);
} catch (err) {
  console.error("PARSE FAILED:", err.message);
  process.exit(1);
}

const findings = j.findings ?? j.items ?? [];
console.log("parsed OK, findings:", findings.length);

const counts = {};
const prio = {};
const missing = [];
for (const f of findings) {
  counts[f.status] = (counts[f.status] ?? 0) + 1;
  prio[f.priority] = (prio[f.priority] ?? 0) + 1;
  for (const k of ["id", "feature", "priority", "status", "evidence", "acceptanceCriteria"]) {
    if (f[k] === undefined) missing.push(`${f.id}: missing ${k}`);
  }
  if (!Array.isArray(f.evidence)) missing.push(`${f.id}: evidence not an array`);
}
console.log("status:", JSON.stringify(counts));
console.log("priority:", JSON.stringify(prio));
console.log("schema problems:", missing.length === 0 ? "none" : missing.join("; "));

const dupes = findings.map((f) => f.id).filter((id, i, a) => a.indexOf(id) !== i);
console.log("duplicate ids:", dupes.length ? dupes.join(", ") : "none");

const p0open = findings.filter((f) => f.priority === "P0" && f.status !== "VERIFIED_CLOSED");
console.log("P0 not verified closed:", p0open.map((f) => `${f.id}(${f.status})`).join(", ") || "none");
