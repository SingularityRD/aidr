#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
const args = process.argv.slice(2), dir = resolve(args[0] || ".aidr-deploy");
const apply = args.includes("--apply");
const manifest = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
const env = Object.fromEntries(readFileSync(join(dir, ".env"), "utf8").split(/\r?\n/).filter(s => s.includes("=")).map(s => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=")+1)]));
const base = new URL(manifest.supabase_url);
if (base.protocol !== "https:" && !(manifest.development && ["localhost", "127.0.0.1"].includes(base.hostname))) throw new Error("Maintenance requires HTTPS or a loopback development deployment");
if (!env.SERVICE_ROLE_KEY) throw new Error("Deployment service credential missing");
async function request(path, method = "GET", body) {
  const response = await fetch(new URL(path, base), { method, headers: { apikey: env.SERVICE_ROLE_KEY, Authorization: `Bearer ${env.SERVICE_ROLE_KEY}`, "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error(`Maintenance request failed (${response.status}); ledger retained for retry`);
  const text = await response.text(); return text ? JSON.parse(text) : null;
}
const cutoff = new Date().toISOString();
let selected = 0, removed = 0, complete = false;
for (let batch = 0; batch < 100; batch++) {
  const rows = await request(`/rest/v1/audit_export_objects?select=path&expires_at=lte.${encodeURIComponent(cutoff)}&order=expires_at.asc,path.asc&limit=100`);
  if (!Array.isArray(rows)) throw new Error("Invalid retention response");
  if (rows.length === 0) { complete = true; break; }
  const paths = rows.map(row => row.path);
  if (paths.some(path => typeof path !== "string" || !/^[a-f0-9-]{36}\/[a-f0-9-]{36}\.(csv|json)$/.test(path))) throw new Error("Invalid export path in retention ledger");
  selected += paths.length;
  if (!apply) break;
  // Storage API deletes file bytes and metadata together. Never delete storage.objects directly.
  await request("/storage/v1/object/aidr-audit-exports", "DELETE", { prefixes: paths });
  for (const path of paths) await request(`/rest/v1/audit_export_objects?path=eq.${encodeURIComponent(path)}&expires_at=lte.${encodeURIComponent(cutoff)}`, "DELETE");
  removed += paths.length;
}
const evidence = { checked_at: new Date().toISOString(), action: "expire-private-audit-exports", applied: apply, selected, removed, complete, cutoff, scope: "Deletes expired temporary export objects only; source audit records remain append-only." };
writeFileSync(join(dir, "maintenance-evidence.json"), JSON.stringify(evidence, null, 2));
console.log(JSON.stringify(evidence));
if (apply && !complete) process.exitCode = 2;
