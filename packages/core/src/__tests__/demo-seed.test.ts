import { describe, expect, it } from "vitest";
import { generateDemoData } from "./demo-seed.js";

describe("demo-seed data generator", () => {
	it("generates agents with required fields", () => {
		const data = generateDemoData(3, 0);
		expect(data.agents.length).toBe(3);
		for (const agent of data.agents) {
			expect(agent.id).toBeDefined();
			expect(agent.display_name).toBeDefined();
			expect(agent.agent_runtime).toBeDefined();
			expect(["connected", "disconnected", "pending"]).toContain(agent.status);
		}
	});

	it("generates events with required fields", () => {
		const data = generateDemoData(2, 10);
		expect(data.events.length).toBe(10);
		for (const event of data.events) {
			expect(event.id).toBeDefined();
			expect(["runtime_verdict", "plugin_scan", "incident"]).toContain(event.type);
			expect(event.created_at).toBeDefined();
			expect(event.agent_id).toBeDefined();
			expect(event.payload).toBeDefined();
		}
	});

	it("sorts events by created_at descending", () => {
		const data = generateDemoData(2, 10);
		for (let i = 1; i < data.events.length; i++) {
			const prev = new Date(data.events[i - 1].created_at).getTime();
			const curr = new Date(data.events[i].created_at).getTime();
			expect(prev).toBeGreaterThanOrEqual(curr);
		}
	});

	it("links events to generated agents", () => {
		const data = generateDemoData(2, 10);
		const agentIds = new Set(data.agents.map((a) => a.id));
		for (const event of data.events) {
			expect(agentIds.has(event.agent_id)).toBe(true);
		}
	});

	it("includes synthetic secret markers (not real secrets)", () => {
		const data = generateDemoData(1, 50);
		const allPayloads = data.events.map((e) => JSON.stringify(e.payload));
		const combined = allPayloads.join(" ");
		// Ensure demo data contains synthetic markers
		expect(
			combined.includes("fake-demo-key") ||
				combined.includes("EXAMPLE") ||
				combined.includes("fake_signature"),
		).toBe(true);
	});
});
