#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: { deployment: { type: "string", default: ".aidr-deploy" }, email: { type: "string" }, name: { type: "string" }, seats: { type: "string", default: "1" }, resume: { type: "boolean", default: false } } });
const dir = resolve(values.deployment);
const manifest = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
const env = Object.fromEntries(readFileSync(join(dir, ".env"), "utf8").split(/\r?\n/).filter((line) => /^[A-Z][A-Z0-9_]*=/.test(line)).map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));
const base = new URL(manifest.supabase_url);
if (base.protocol !== "https:" && !(manifest.development && ["localhost", "127.0.0.1"].includes(base.hostname))) throw new Error("HTTPS required");
if (!env.SERVICE_ROLE_KEY || env.SERVICE_ROLE_KEY.startsWith("REPLACE_")) throw new Error("Configure the selected project's credentials first");
const email = values.email?.trim().toLowerCase();
const name = values.name?.trim();
const seats = Number(values.seats);
if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !name || name.length > 120 || !Number.isInteger(seats) || seats < 1 || seats > 100000) throw new Error("Valid --email, --name and --seats (1..100000) required");
const receiptPath = join(dir, "bootstrap-receipt.json");
let receipt;
if (existsSync(receiptPath)) {
  if (!values.resume) throw new Error("Bootstrap receipt exists. Use --resume with identical parameters; existing passwords are never reset.");
  receipt = JSON.parse(readFileSync(receiptPath, "utf8"));
  if (receipt.email !== email || receipt.name !== name || receipt.seats !== seats || receipt.supabase_url !== base.origin) throw new Error("Bootstrap resume parameters do not match");
} else {
  if (values.resume) throw new Error("No bootstrap receipt to resume");
  receipt = { bootstrap_id: randomUUID(), email, name, seats, supabase_url: base.origin, state: "reserved" };
  writeFileSync(receiptPath, JSON.stringify(receipt, null, 2), { mode: 0o600, flag: "wx" });
}
const save = () => writeFileSync(receiptPath, JSON.stringify(receipt, null, 2), { mode: 0o600 });
async function request(path, body, method = "POST") {
  const response = await fetch(new URL(path, base), { method, headers: { apikey: env.ANON_KEY, Authorization: `Bearer ${env.SERVICE_ROLE_KEY}`, "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error(`Provisioning failed at ${path.split("?")[0]} (HTTP ${response.status}); review service logs, then resume. No credentials printed.`);
  return response.json();
}
if (values.resume && !receipt.user_id) {
  // Recover an interrupted successful account creation without changing accounts
  // that predate this operation. Bind to server-only app_metadata, never email alone.
  for (let page = 1; page <= 100; page++) {
    const result = await request(`/auth/v1/admin/users?page=${page}&per_page=100`, undefined, "GET");
    const user = result.users?.find((candidate) => candidate.email?.toLowerCase() === email && candidate.app_metadata?.aidr_bootstrap_id === receipt.bootstrap_id);
    if (user) { receipt.user_id = user.id; save(); break; }
    if ((result.users?.length ?? 0) < 100) break;
  }
}
if (!receipt.user_id) {
  if (process.stdin.isTTY) throw new Error("Supply a 16..128 character password on stdin from your secret manager or a hidden prompt. Do not put passwords in command arguments.");
  const chunks = []; let size = 0;
  for await (const chunk of process.stdin) { size += chunk.length; if (size > 1024) throw new Error("Password input too large"); chunks.push(chunk); }
  const password = Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
  if (password.length < 16 || password.length > 128 || /[\r\n\0]/.test(password)) throw new Error("Password must be 16..128 characters on one line");
  const user = await request("/auth/v1/admin/users", { email, password, email_confirm: true, app_metadata: { aidr_bootstrap_id: receipt.bootstrap_id } });
  receipt.user_id = user.id; receipt.state = "account_created"; save();
}
const completed = await request("/rest/v1/rpc/bootstrap_customer", { p_user_id: receipt.user_id, p_bootstrap_id: receipt.bootstrap_id, p_name: name, p_seats: seats });
Object.assign(receipt, completed, { state: "complete", completed_at: new Date().toISOString() }); save();
console.log(`Customer owner and ${seats} agent seats provisioned. Sign in at ${manifest.dashboard_url}/login. Private receipt saved; no password or token was printed.`);
