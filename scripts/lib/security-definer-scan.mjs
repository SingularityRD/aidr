// Static scan of CREATE FUNCTION statements in migration SQL.
//
// The authoritative guard is the live-catalog test (every SECURITY DEFINER
// function in public/app after the full chain). This scan is the cheap
// pre-merge guard that keeps new migrations from reintroducing the gap: a
// SECURITY DEFINER function must pin `search_path` with an explicit `pg_temp`.

/** Version of the forward migration that backfilled pg_temp onto older functions. */
export const SEARCH_PATH_HARDENING_VERSION = "20261005101001";

/**
 * Split SQL into top-level statements, respecting -- and block comments, single
 * and double quotes and dollar quoting. Comments are replaced by spaces so text
 * inside them is never matched.
 */
export function splitStatements(sql) {
	const statements = [];
	let current = "";
	let line = 1;
	let startLine = 1;
	for (let i = 0; i < sql.length; i += 1) {
		const char = sql[i];
		const next = sql[i + 1];
		if (char === "-" && next === "-") {
			while (i < sql.length && sql[i] !== "\n") i += 1;
			i -= 1;
			continue;
		}
		if (char === "/" && next === "*") {
			let depth = 1;
			i += 2;
			while (i < sql.length && depth > 0) {
				if (sql[i] === "/" && sql[i + 1] === "*") { depth += 1; i += 2; continue; }
				if (sql[i] === "*" && sql[i + 1] === "/") { depth -= 1; i += 2; continue; }
				if (sql[i] === "\n") { line += 1; current += "\n"; }
				i += 1;
			}
			i -= 1;
			current += " ";
			continue;
		}
		if (char === "'" || char === '"') {
			const start = i;
			i += 1;
			while (i < sql.length) {
				if (sql[i] === char && sql[i + 1] === char) { i += 2; continue; }
				if (sql[i] === char) break;
				i += 1;
			}
			const text = sql.slice(start, i + 1);
			current += text;
			line += text.split("\n").length - 1;
			continue;
		}
		if (char === "$") {
			const tag = /^\$[A-Za-z_]*\$/.exec(sql.slice(i))?.[0];
			if (tag) {
				const end = sql.indexOf(tag, i + tag.length);
				const stop = end < 0 ? sql.length : end + tag.length;
				const text = sql.slice(i, stop);
				current += text;
				line += text.split("\n").length - 1;
				i = stop - 1;
				continue;
			}
		}
		if (char === ";") {
			if (current.trim()) statements.push({ text: current.trim(), line: startLine });
			current = "";
			startLine = line;
			continue;
		}
		if (char === "\n") line += 1;
		if (!current.trim()) startLine = line;
		current += char;
	}
	if (current.trim()) statements.push({ text: current.trim(), line: startLine });
	return statements;
}

const CREATE_FUNCTION = /^create\s+(?:or\s+replace\s+)?function\s+([\w."]+)/i;

/**
 * Header = everything outside dollar-quoted / single-quoted bodies, so a
 * `security definer` or `pg_temp` mention inside a function body or string does
 * not count.
 */
function headerOf(statement) {
	let out = "";
	for (let i = 0; i < statement.length; i += 1) {
		const tag = statement[i] === "$" ? /^\$[A-Za-z_]*\$/.exec(statement.slice(i))?.[0] : null;
		if (tag) {
			const end = statement.indexOf(tag, i + tag.length);
			i = end < 0 ? statement.length : end + tag.length - 1;
			out += " ";
			continue;
		}
		if (statement[i] === "'") {
			i += 1;
			while (i < statement.length && !(statement[i] === "'" && statement[i + 1] !== "'")) i += statement[i] === "'" ? 2 : 1;
			out += " ";
			continue;
		}
		out += statement[i];
	}
	return out;
}

/** SECURITY DEFINER functions created by `sql` that lack `search_path ... pg_temp`. */
export function securityDefinerWithoutPgTemp(sql) {
	const findings = [];
	for (const statement of splitStatements(sql)) {
		const create = CREATE_FUNCTION.exec(statement.text);
		if (!create) continue;
		const header = headerOf(statement.text);
		if (!/\bsecurity\s+definer\b/i.test(header)) continue;
		if (/\bset\s+search_path\s*(?:=|to)\s*[^\n]*\bpg_temp\b/i.test(header)) continue;
		findings.push({ name: create[1], line: statement.line });
	}
	return findings;
}
