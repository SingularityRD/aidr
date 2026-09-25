// The dashboard ships a price-free static mirror of the public.plans seed so the
// public Editions page needs no database access. This test parses the seed block
// in the migration and fails on any difference, so a term can never change on one
// side only. The seed's price columns stay server-side: the mirror carries only
// which billing intervals are offered (a non-null price column), never an amount.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { type BillingInterval, PLAN_CATALOG, type PlanDefinition } from "../billing/plans";

const MIGRATION = new URL(
	"../../../../supabase/migrations/20260925000010_plan_catalog.sql",
	import.meta.url,
);

type SqlValue = string | number | boolean | null | string[];

/** A cursor over one SQL VALUES tuple. */
class TupleReader {
	index = 0;

	constructor(readonly source: string) {}

	get done(): boolean {
		return this.index >= this.source.length;
	}

	skipSpace(): void {
		while (!this.done && /\s/.test(this.source[this.index] ?? "")) this.index += 1;
	}

	/** Skips `char` if it is next. */
	skip(char: string): boolean {
		if (this.source[this.index] !== char) return false;
		this.index += 1;
		return true;
	}

	/** A single-quoted string; `''` is an escaped quote. */
	readString(): string {
		if (!this.skip("'")) throw new Error(`expected string at ${this.index}: ${this.source}`);
		let out = "";
		while (!this.done) {
			const char = this.source[this.index];
			this.index += 1;
			if (char !== "'") out += char;
			else if (this.skip("'")) out += "'";
			else return out;
		}
		throw new Error("unterminated string");
	}

	/** `array['a', 'b']`, positioned just after `array[`. */
	readArrayItems(): string[] {
		const items: string[] = [];
		for (;;) {
			this.skipSpace();
			if (this.skip("]")) return items;
			items.push(this.readString());
			this.skipSpace();
			this.skip(",");
		}
	}

	/** null, true, false or an integer. */
	readScalar(): SqlValue {
		const match = /^(null|true|false|-?\d+)/.exec(this.source.slice(this.index));
		if (!match?.[1]) {
			throw new Error(`unexpected token at ${this.index}: ${this.source.slice(this.index)}`);
		}
		this.index += match[1].length;
		const literals: Record<string, SqlValue> = { null: null, true: true, false: false };
		return match[1] in literals ? (literals[match[1]] as SqlValue) : Number(match[1]);
	}

	readValue(): SqlValue {
		if (this.source[this.index] === "'") return this.readString();
		if (this.source.startsWith("array[", this.index)) {
			this.index += "array[".length;
			return this.readArrayItems();
		}
		return this.readScalar();
	}

	skipCast(): void {
		const cast = /^::[a-z]+/.exec(this.source.slice(this.index));
		if (cast) this.index += cast[0].length;
	}
}

/** Tokenize one SQL VALUES tuple: quoted strings, numbers, null, booleans, array[...] and ::casts. */
function parseTuple(source: string): SqlValue[] {
	const values: SqlValue[] = [];
	const reader = new TupleReader(source);
	while (!reader.done) {
		reader.skipSpace();
		const value = reader.readValue();
		reader.skipCast();
		values.push(value);
		reader.skipSpace();
		reader.skip(",");
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
		expect(currency).toBe("USD");
		const billingIntervals: BillingInterval[] = [];
		if (priceMonthlyCents !== null) billingIntervals.push("monthly");
		if (priceYearlyCents !== null) billingIntervals.push("yearly");
		return {
			id,
			displayName,
			includedAgents,
			minSeats,
			billingIntervals,
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

	it("keeps the catalog terms and offered billing intervals", () => {
		const byId = Object.fromEntries(PLAN_CATALOG.map((plan) => [plan.id, plan]));
		expect(byId.free).toMatchObject({ includedAgents: 1, retentionDays: 7 });
		expect(byId.team).toMatchObject({
			billingIntervals: ["monthly", "yearly"],
			minSeats: 3,
			retentionDays: 90,
		});
		expect(byId.business).toMatchObject({
			billingIntervals: ["yearly"],
			minSeats: 25,
			retentionDays: 365,
		});
		expect(byId.enterprise).toMatchObject({ billingIntervals: [], selfServe: false });
		expect(byId.enterprise?.deployment).toEqual(["onprem", "air-gapped"]);
	});

	it("never ships a price, amount or currency in the browser mirror", () => {
		for (const plan of PLAN_CATALOG) {
			expect(Object.keys(plan).filter((key) => /price|cents|amount|currency/i.test(key))).toEqual(
				[],
			);
		}
		const source = readFileSync(new URL("../billing/plans.ts", import.meta.url), "utf8");
		expect(source).not.toMatch(/priceMonthlyCents|priceYearlyCents|currency:|\$\d|\bUSD\b/);
	});
});
