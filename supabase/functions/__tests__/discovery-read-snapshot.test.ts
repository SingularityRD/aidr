import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const FUNCTIONS_DIR = dirname(dirname(fileURLToPath(import.meta.url)));
const handler = readFileSync(join(FUNCTIONS_DIR, "discovery", "index.ts"), "utf8").split("Deno.serve(")[1] ?? "";

describe("discovery read snapshot", () => {
	it("rechecks the tenant-scoped collector sequence after reading items", () => {
		const firstCollectorRead = handler.indexOf('const collector = await db.from("tenant_discovery_collectors")');
		const itemRead = handler.indexOf("const rows = await query", firstCollectorRead);
		const consistencyRead = handler.indexOf('const latestCollector = await db.from("tenant_discovery_collectors")', itemRead);
		const consistencyCheck = handler.slice(consistencyRead, handler.indexOf("const page = rows.data.slice(0, limit)", consistencyRead));
		expect(firstCollectorRead).toBeGreaterThan(-1);
		expect(itemRead).toBeGreaterThan(firstCollectorRead);
		expect(consistencyRead).toBeGreaterThan(itemRead);
		expect(consistencyCheck).toContain('.eq("tenant_id", tenant).eq("collector_id", input.collector_id)');
		expect(consistencyCheck).toContain("latestCollector.data.cycle_id !== collectorRow.cycle_id");
		expect(consistencyCheck).toContain("latestCollector.data.sequence !== collectorRow.sequence");
		expect(consistencyCheck).toContain("discovery_inventory_changed");
	});
});
