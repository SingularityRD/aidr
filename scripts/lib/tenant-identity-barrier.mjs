// Static replay of the canonical migrations that answers one question: after
// every migration has run, does each exposed tenant table (public schema, RLS
// enabled, `tenant_id` column) carry the restrictive identity barrier
// `public.tenant_identity_access_allowed(tenant_id)`?
//
// The permissive membership policies (`app.is_tenant_member(tenant_id)`) decide
// which rows a member may see; the restrictive barrier additionally enforces the
// tenant identity policy (MFA/AAL2, required SAML provider, global session
// revocation). A tenant table that forgets the barrier lets a member whose
// session no longer satisfies the tenant's identity policy keep reading it.
//
// The barrier is applied two ways in this repository:
//   1. A `do $$ … $$` sweep over information_schema that creates
//      `tenant_identity_access_restrict` on every RLS tenant table existing at
//      that point (20260912000013, 20260923000021).
//   2. An explicit per-table `create policy … as restrictive … using
//      (public.tenant_identity_access_allowed(tenant_id))` in later migrations.
//
// Only top-level statements are interpreted (comments, string literals and
// dollar-quoted function bodies are masked first), except that a top-level DO
// block is recognised as a sweep by its raw body.
import { maskNonExecutableSql } from "./migration-contract.mjs";

const IDENTITY_BARRIER_POLICY = "tenant_identity_access_restrict";

/**
 * Tenant RLS tables that intentionally carry no identity barrier. Every entry
 * must say why; the check fails if an entry stops being needed so the list
 * cannot silently rot.
 */
export const IDENTITY_BARRIER_EXCEPTIONS = Object.freeze({});

/**
 * Tables that are keyed by the tenant id itself rather than a `tenant_id`
 * column, mapped to that key column. They need the same barrier on it.
 */
const TENANT_ROOT_TABLES = Object.freeze({ tenants: "id" });

const SWEEP_SIGNATURE = [
	/pc\.relrowsecurity/i,
	/c\.column_name\s*=\s*'tenant_id'/i,
	/create\s+policy\s+tenant_identity_access_restrict\s+on\s+public\.%I\s+as\s+restrictive\s+for\s+all\s+to\s+authenticated\s+using\s*\(\s*public\.tenant_identity_access_allowed\s*\(\s*tenant_id\s*\)\s*\)/i,
];

const IDENT = "([a-z_][a-z0-9_]*)";
const PUBLIC_TABLE = `(?:public\\.)?${IDENT}(?![.a-z0-9_$])`;

/**
 * The column a policy applies the identity barrier to, or null when the policy
 * is not a restrictive, all-command, authenticated-reaching barrier.
 */
function barrierColumn(rest) {
	const text = rest.replace(/\s+/g, " ").toLowerCase();
	if (!/\bas restrictive\b/.test(text)) return null;
	const command = /\bfor (all|select|insert|update|delete)\b/.exec(text)?.[1] ?? "all";
	if (command !== "all") return null;
	const roles = /\bto ([a-z_, ]+?)(?: using| with check|$)/.exec(text)?.[1];
	if (roles && !/\b(authenticated|public)\b/.test(roles)) return null;
	return /\busing \( ?(?:public\.)?tenant_identity_access_allowed\( ?([a-z_]+) ?\) ?\)/.exec(text)?.[1] ?? null;
}

function columnListHasTenantId(body) {
	// Top-level column definitions only: split on commas outside parentheses.
	let depth = 0;
	let current = "";
	const parts = [];
	for (const char of body) {
		if (char === "(") depth += 1;
		if (char === ")") depth -= 1;
		if (char === "," && depth === 0) {
			parts.push(current);
			current = "";
		} else {
			current += char;
		}
	}
	parts.push(current);
	return parts.some((part) => /^\s*tenant_id\s+[a-z]/i.test(part));
}

function statementsOf(sql) {
	const { masked } = maskNonExecutableSql(sql);
	const statements = [];
	let offset = 0;
	for (const chunk of masked.split(";")) {
		const raw = sql.slice(offset, offset + chunk.length);
		const text = chunk.trim();
		if (text) {
			const start = offset + chunk.search(/\S/);
			statements.push({ text, raw, line: sql.slice(0, start).split("\n").length });
		}
		offset += chunk.length + 1;
	}
	return statements;
}

/**
 * Replay `migrations` ([{ name, sql }] in apply order) and return the final
 * table state plus the list of exposed tenant tables lacking the barrier.
 */
export function analyzeIdentityBarrier(migrations, exceptions = IDENTITY_BARRIER_EXCEPTIONS) {
	const tables = new Map();
	const table = (name) => {
		if (!tables.has(name)) tables.set(name, { tenantId: false, rls: false, policies: new Map(), createdIn: null });
		return tables.get(name);
	};

	for (const { name: file, sql } of migrations) {
		for (const { text, raw, line } of statementsOf(sql)) {
			const where = `${file}:${line}`;
			let match;
			if ((match = new RegExp(`^create\\s+table\\s+(if\\s+not\\s+exists\\s+)?${PUBLIC_TABLE}\\s*\\(([\\s\\S]*)\\)`, "i").exec(text))) {
				const [, ifNotExists, rawName, body] = match;
				const tableName = rawName.toLowerCase();
				if (ifNotExists && tables.has(tableName)) continue;
				tables.set(tableName, {
					tenantId: columnListHasTenantId(body),
					rls: false,
					policies: new Map(),
					createdIn: where,
				});
				continue;
			}
			if ((match = new RegExp(`^alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?${PUBLIC_TABLE}\\s+([\\s\\S]*)$`, "i").exec(text))) {
				const [, rawName, clauses] = match;
				const tableName = rawName.toLowerCase();
				const state = table(tableName);
				if (/\badd\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?tenant_id\s+[a-z]/i.test(clauses)) state.tenantId = true;
				if (/\bdrop\s+(?:column\s+)?(?:if\s+exists\s+)?tenant_id\b/i.test(clauses)) state.tenantId = false;
				if (/\benable\s+row\s+level\s+security\b/i.test(clauses)) state.rls = true;
				if (/\bdisable\s+row\s+level\s+security\b/i.test(clauses)) state.rls = false;
				const rename = new RegExp(`\\brename\\s+to\\s+${IDENT}`, "i").exec(clauses);
				if (rename) {
					tables.delete(tableName);
					tables.set(rename[1].toLowerCase(), state);
				}
				continue;
			}
			if ((match = /^drop\s+table\s+(?:if\s+exists\s+)?([\s\S]+?)(?:\s+(?:cascade|restrict))?$/i.exec(text))) {
				for (const target of match[1].split(",")) {
					const tableName = new RegExp(`^\\s*${PUBLIC_TABLE}\\s*$`, "i").exec(target)?.[1];
					if (tableName) tables.delete(tableName.toLowerCase());
				}
				continue;
			}
			if ((match = new RegExp(`^create\\s+policy\\s+${IDENT}\\s+on\\s+${PUBLIC_TABLE}\\b([\\s\\S]*)$`, "i").exec(text))) {
				const [, policy, rawName, rest] = match;
				table(rawName.toLowerCase()).policies.set(policy.toLowerCase(), { column: barrierColumn(rest), where });
				continue;
			}
			if ((match = new RegExp(`^drop\\s+policy\\s+(?:if\\s+exists\\s+)?${IDENT}\\s+on\\s+${PUBLIC_TABLE}\\b`, "i").exec(text))) {
				tables.get(match[2].toLowerCase())?.policies.delete(match[1].toLowerCase());
				continue;
			}
			if (/^do\b/i.test(text) && SWEEP_SIGNATURE.every((pattern) => pattern.test(raw))) {
				for (const state of tables.values()) {
					if (state.tenantId && state.rls) state.policies.set(IDENTITY_BARRIER_POLICY, { column: "tenant_id", where });
				}
			}
		}
	}

	const missing = [];
	const excepted = [];
	for (const [tableName, state] of [...tables.entries()].sort(([left], [right]) => left.localeCompare(right))) {
		const column = Object.hasOwn(TENANT_ROOT_TABLES, tableName)
			? TENANT_ROOT_TABLES[tableName]
			: state.tenantId && "tenant_id";
		if (!column || !state.rls) continue;
		const covered = [...state.policies.values()].some((policy) => policy.column === column);
		if (covered) continue;
		if (Object.hasOwn(exceptions, tableName)) excepted.push(tableName);
		else missing.push({ table: tableName, createdIn: state.createdIn });
	}
	const staleExceptions = Object.keys(exceptions).filter((tableName) => !excepted.includes(tableName));
	return { tables, missing, excepted, staleExceptions };
}
