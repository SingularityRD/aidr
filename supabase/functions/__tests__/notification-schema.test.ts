// Notification schema revision 1.1 (E8): docs/contracts/notification.v1.1.schema.json
// must accept the body `buildNotification` emits for EVERY event the control
// plane sends, and must keep refusing what the producer never emits. The
// event list is pinned against the producer, the outbox CHECK constraint and
// the contract document so a new event cannot ship without a schema update.
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { buildNotification, type DeliveryRecord } from "../_shared/notification-delivery.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const schema = JSON.parse(readFileSync(join(ROOT, "docs", "contracts", "notification.v1.1.schema.json"), "utf8")) as Schema;
const contract = readFileSync(join(ROOT, "docs", "contracts", "notifications.md"), "utf8");
const producer = readFileSync(join(ROOT, "supabase", "functions", "_shared", "notification-delivery.ts"), "utf8");

type Schema = Record<string, unknown> & { $defs?: Record<string, Schema> };

// ── A minimal draft 2020-12 validator for the keywords the schema uses ──────
const FORMATS: Record<string, RegExp> = {
	uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
	"date-time": /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/,
	uri: /^https?:\/\/\S+$/,
};

function typeOf(value: unknown): string {
	if (value === null) return "null";
	if (Array.isArray(value)) return "array";
	if (typeof value === "number") return Number.isInteger(value) ? "integer" : "number";
	return typeof value;
}

function validate(node: Schema, value: unknown, path = "$"): string[] {
	const errors: string[] = [];
	if (typeof node.$ref === "string") return validate(schema.$defs?.[node.$ref.split("/").at(-1) as string] as Schema, value, path);
	if ("const" in node && JSON.stringify(node.const) !== JSON.stringify(value)) errors.push(`${path}: const`);
	if (Array.isArray(node.enum) && !node.enum.some((item) => JSON.stringify(item) === JSON.stringify(value))) errors.push(`${path}: enum`);
	if (node.type !== undefined) {
		const types = Array.isArray(node.type) ? node.type : [node.type];
		const actual = typeOf(value);
		if (!types.includes(actual) && !(actual === "integer" && types.includes("number"))) {
			return [...errors, `${path}: type ${actual}`];
		}
	}
	if (typeof value === "string") {
		if (typeof node.pattern === "string" && !new RegExp(node.pattern).test(value)) errors.push(`${path}: pattern`);
		if (typeof node.format === "string" && FORMATS[node.format] && !FORMATS[node.format].test(value)) errors.push(`${path}: format`);
	}
	if (typeof value === "number") {
		if (typeof node.minimum === "number" && value < node.minimum) errors.push(`${path}: minimum`);
		if (typeof node.maximum === "number" && value > node.maximum) errors.push(`${path}: maximum`);
	}
	if (typeOf(value) === "object") {
		const object = value as Record<string, unknown>;
		const properties = (node.properties ?? {}) as Record<string, Schema>;
		for (const key of (node.required as string[] | undefined) ?? []) if (!(key in object)) errors.push(`${path}: required ${key}`);
		for (const [key, child] of Object.entries(object)) {
			if (properties[key]) errors.push(...validate(properties[key], child, `${path}.${key}`));
			else if (node.additionalProperties === false) errors.push(`${path}: additional ${key}`);
		}
	}
	for (const part of (node.allOf as Schema[] | undefined) ?? []) errors.push(...validate(part, value, path));
	if (Array.isArray(node.anyOf) && !node.anyOf.some((part) => validate(part as Schema, value, path).length === 0)) errors.push(`${path}: anyOf`);
	if (node.not && validate(node.not as Schema, value, path).length === 0) errors.push(`${path}: not`);
	if (node.if) {
		const branch = validate(node.if as Schema, value, path).length === 0 ? node.then : node.else;
		if (branch) errors.push(...validate(branch as Schema, value, path));
	}
	return errors;
}

// ── Fixtures ───────────────────────────────────────────────────────────────
const EVENTS = (schema.properties as Record<string, Schema>).event.enum as string[];

const FULL_PAYLOAD = {
	occurred_at: "2026-10-14T08:00:00.000Z",
	severity: "critical",
	category: "T01",
	event_row_id: "42",
	agent_id: "66666666-6666-4666-8666-666666666666",
	incident_id: "inc-1",
	request_id: "99999999-9999-4999-8999-999999999999",
	findings_count: 3,
	blocked_count: 12,
	window_minutes: 15,
	items_count: 4,
	window_days: 14,
	offline_minutes: 240,
	connector_state: "hook_disabled",
	period_from: "2026-10-06T00:00:00.000Z",
	period_to: "2026-10-13T00:00:00.000Z",
	digest: { agents_enrolled: 120, decisions_deny: 7, policy_changes_pending: 1 },
	// Never emitted, whatever the database holds.
	prompt: "rm -rf /",
	hostname: "laptop-17.corp.example",
};

function record(event: string, payload: Record<string, unknown> = FULL_PAYLOAD): DeliveryRecord {
	return {
		deliveryId: "7c1f0a52-3a8e-4b8e-9d6c-2f7b8a1e4c90",
		tenantId: "1f6b1b0e-0c4f-4a53-9b7e-6d0f3f9a2c11",
		eventType: event as DeliveryRecord["eventType"],
		payload,
		createdAt: "2026-10-14T08:00:01.000Z",
	};
}

describe("notification schema v1.1", () => {
	it("covers exactly the events the producer, the outbox and the contract know", () => {
		const produced = /NOTIFICATION_EVENT_TYPES = \[([\s\S]*?)\] as const/.exec(producer)?.[1].match(/"([a-z_.]+)"/g)?.map((item) => item.slice(1, -1));
		expect(new Set(produced)).toEqual(new Set(EVENTS));
		expect(EVENTS).toHaveLength(13);
		for (const event of EVENTS) expect(contract, event).toContain(`\`${event}\``);
		// The newest CHECK constraint on notification_deliveries.event_type lists the same events.
		const migrations = readdirSync(join(ROOT, "supabase", "migrations")).filter((name) => name.endsWith(".sql")).sort();
		const constraints = migrations
			.map((name) => readFileSync(join(ROOT, "supabase", "migrations", name), "utf8"))
			.flatMap((sql) => [...sql.matchAll(/event_type in \(([^)]*'notification\.test'[^)]*)\)/g)].map((match) => match[1]));
		const latest = (constraints.at(-1) ?? "").match(/'([a-z_.]+)'/g)?.map((item) => item.slice(1, -1));
		expect(new Set(latest)).toEqual(new Set(EVENTS));
	});

	it.each(EVENTS)("accepts the body emitted for %s (full and empty payloads)", (event) => {
		const full = buildNotification(record(event), "https://aidr.example.com");
		expect(validate(schema, full)).toEqual([]);
		expect(JSON.stringify(full)).not.toMatch(/rm -rf|laptop-17/);
		const empty = buildNotification(record(event, {}), null);
		expect(validate(schema, empty)).toEqual([]);
	});

	it("keeps the 1.0 body for the original events and refuses what the producer never sends", () => {
		const original = buildNotification(record("incident.created"), null);
		expect(validate(schema, { ...original, period: null })).not.toEqual([]);
		expect(validate(schema, { ...original, subject: { ...original.subject, request_id: null } })).not.toEqual([]);
		expect(validate(schema, { ...original, event: "incident.updated" })).not.toEqual([]);
		expect(validate(schema, { ...original, test: true })).not.toEqual([]);
		expect(validate(schema, { ...original, prompt: "x" })).not.toEqual([]);
		const governance = buildNotification(record("governance.change_pending"), null);
		const { request_id: _drop, ...subject } = governance.subject;
		expect(validate(schema, { ...governance, subject })).not.toEqual([]);
		expect(validate(schema, { ...governance, digest: { agents_enrolled: 1 } })).not.toEqual([]);
		const digest = buildNotification(record("governance.digest"), null);
		expect(validate(schema, { ...digest, digest: { ...digest.digest, unknown_count: 1 } })).not.toEqual([]);
	});
});
