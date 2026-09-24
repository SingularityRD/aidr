import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";

test("missing capabilities remain implementation-open when mapped in the sales gap report", () => {
  const inventory = JSON.parse(readFileSync(new URL("../FEATURE_INVENTORY.json", import.meta.url), "utf8"));
  const gaps = JSON.parse(readFileSync(new URL("../PRODUCTION_SALES_GAPS.json", import.meta.url), "utf8"));
  const missing = new Set(inventory.features.filter(feature => feature.status === "missing").map(feature => feature.id));
  for (const work of gaps.engineering_and_operations) {
    if (work.feature_ids.some(id => missing.has(id))) {
      assert.equal(work.status, "OPEN", `${work.id} cannot be field-acceptance-only while a mapped feature is missing`);
    }
  }
  assert.match(gaps.engineering_and_operations.find(work => work.id === "T13")?.status ?? "", /OPEN$/);
});

test("behavioral learning and SAML administration remain open; pack offboarding needs field acceptance", () => {
  const gaps = JSON.parse(readFileSync(new URL("../PRODUCTION_SALES_GAPS.json", import.meta.url), "utf8"));
  const byId = new Map(gaps.engineering_and_operations.map(work => [work.id, work]));
  assert.equal(byId.get("T05")?.status, "OPEN");
  assert.match(byId.get("T05")?.implementation_update ?? "", /learningAllowed remains false/i);
  assert.equal(byId.get("T21")?.status, "LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN");
  assert.match(byId.get("T21")?.implementation_update ?? "", /her GET\/HEAD isteğinde/i);
  assert.equal(byId.get("T26")?.status, "LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN");
  assert.match(byId.get("T26")?.implementation_update ?? "", /aidr-packs/);
  assert.equal(byId.get("T18")?.status, "OPEN");
  assert.match(byId.get("T18")?.implementation_update ?? "", /Enterprise SAML policy administration is still absent/i);
  assert.match(byId.get("T23")?.implementation_update ?? "", /private NTFS ACLs/i);
  assert.match(byId.get("T23")?.implementation_update ?? "", /51\.43 seconds/i);
  assert.match(byId.get("T37")?.implementation_update ?? "", /JWT\/credential-shaped/i);
});

test("T28 distinguishes historical migration proof from current candidate acceptance", () => {
  const gaps = JSON.parse(readFileSync(new URL("../PRODUCTION_SALES_GAPS.json", import.meta.url), "utf8"));
  const report = readFileSync(new URL("../PRODUCTION_SALES_GAPS.md", import.meta.url), "utf8");
  const update = gaps.engineering_and_operations.find(work => work.id === "T28")?.implementation_update ?? "";
  const migrationCount = readdirSync(new URL("../supabase/migrations", import.meta.url)).filter(name => /^\d+_.+\.sql$/.test(name)).length;
  assert.match(update, /historical v6 self-hosted install evidence recorded execution of 33 migrations/i);
  assert.match(update, /not proof for the current source tree or candidate/i);
  assert.match(update, new RegExp(`current source tree contains ${migrationCount} canonical migration files`));
  assert.match(update, /no current candidate-bound install\/upgrade acceptance exists/i);
  assert.doesNotMatch(update, /(?:current|latest)\s+(?:self-hosted\s+)?(?:proof|acceptance)[^.]*\b33 migrations\b/i);
  assert.match(report, /Historical v6 self-hosted install evidence recorded execution of 33 migrations/i);
  assert.match(report, /no current candidate-bound install\/upgrade acceptance exists/i);
});
