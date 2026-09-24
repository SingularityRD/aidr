// The dashboard ships a static mirror of the public.plans seed so the public
// pricing page needs no database access. This test parses the seed block in the
// migration and fails on any difference, so a price or term can never change
// on one side only.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { PLAN_CATALOG, type PlanDefinition } from "../billing/plans";

const MIGRATION = new URL(
	"../../../../supabase/migrations/20260925000010_plan_catalog.sql",
	import.meta.url,
);

type SqlValue = string | number | boolean | null | string[];

/** Tokenize one SQL VALUES tuple: quoted strings, numbers, null, booleans, array[...] and ::casts. */
function parseTuple(source: string): SqlValue[] {
	const values: SqlValue[] = [];
	let index = 0;
	const skipSpace = () => {
		while (index < source.length && /\s/.test(source[index] ?? "")) index += 1;
	};
	const readString = (): string => {
		if (source[index] !== "'") throw new Error(`expected string at ${index}: ${source}`);
		index += 1;
		let out = "";
		while (index < source.length) {
			const char = source[index];
			if (char === "'") {
				if (source[index + 1] === "'") {
					out += "'";
					index += 2;
					continue;
				}
				index += 1;
				return out;
			}
			out += char;
			index += 1;
		}
		throw new Error("unterminated string");
	};
	while (index < source.length) {
		skipSpace();
		let value: SqlValue;
		if (source[index] === "'") {
			value = readString();
		} else if (source.startsWith("array[", index)) {
			index += "array[".length;
			const items: string[] = [];
			for (;;) {
				skipSpace();
				if (source[index] === "]") {
					index += 1;
					break;
				}
				items.push(readString());
				skipSpace();
				if (source[index] === ",") index += 1;
			}
			value = items;
		} else {
			const match = /^(null|true|false|-?\d+)/.exec(source.slice(index));
			if (!match?.[1]) throw new Error(`unexpected token at ${index}: ${source.slice(index)}`);
			index += match[1].length;
			value =
				match[1] === "null"
					? null
					: match[1] === "true"
						? true
						: match[1] === "false"
							? false
							: Number(match[1]);
		}
		const cast = /^::[a-z]+/.exec(source.slice(index));
		if (cast) index += cast[0].length;
		values.push(value);
		skipSpace();
		if (source[index] === ",") index += 1;
	}
	return values;
}

function seedRows(): PlanDefinition[] {
	const sql = readFileSync(MIGRATION, "utf8");
	const block = sql.split("-- catalog-seed:begin")[1]?.split("-- catalog-seed:end")[0];
	if (!block) throw new Error("catalog seed markers not found");
	const columns = /insert into public\.plans\s*\(([^)]*)\)/
		.exec(block)?.[1]
		?.split(",")
		.map((c) => c.trim());
	expect(columns).toEqual([
		"id",
		"display_name",
		"included_agents",
		"min_seats",
		"price_monthly_cents",
		"price_yearly_cents",
		"currency",
		"features",
		"self_serve",
		"deployment",
		"retention_days",
		"active",
		"sort_order",
	]);
	const tuples = block
		.split("\n")
		.map((line) => line.trim())
		.filter((line) => line.startsWith("('"))
		.map((line) => line.replace(/^\(/, "").replace(/\),?$/, ""));
	return tuples.map((tuple) => {
		const [
			id,
			displayName,
			includedAgents,
			minSeats,
			priceMonthlyCents,
			priceYearlyCents,
			currency,
			features,
			selfServe,
			deployment,
			retentionDays,
			active,
			sortOrder,
		] = parseTuple(tuple);
		return {
			id,
			displayName,
			includedAgents,
			minSeats,
			priceMonthlyCents,
			priceYearlyCents,
			currency,
			features: JSON.parse(features as string),
			selfServe,
			deployment,
			retentionDays,
			active,
			sortOrder,
		} as PlanDefinition;
	});
}

describe("plan catalog mirror", () => {
	it("matches the migration seed exactly", () => {
		expect(seedRows()).toEqual([...PLAN_CATALOG]);
	});

	it("keeps the approved list-price shape", () => {
		const byId = Object.fromEntries(PLAN_CATALOG.map((plan) => [plan.id, plan]));
		expect(byId.free).toMatchObject({ includedAgents: 1, priceMonthlyCents: 0, retentionDays: 7 });
		expect(byId.team).toMatchObject({
			priceMonthlyCents: 2400,
			priceYearlyCents: 24000,
			minSeats: 3,
			retentionDays: 90,
		});
		expect(byId.business).toMatchObject({
			priceMonthlyCents: null,
			priceYearlyCents: 54000,
			minSeats: 25,
			retentionDays: 365,
		});
		expect(byId.enterprise).toMatchObject({
			priceMonthlyCents: null,
			priceYearlyCents: null,
			selfServe: false,
		});
		expect(byId.enterprise?.deployment).toEqual(["onprem", "air-gapped"]);
	});
});
