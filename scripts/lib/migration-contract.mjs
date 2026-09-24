import { createHash } from "node:crypto";

export const MIGRATION_FILENAME_PATTERN =/^\d{14}_[a-z0-9][a-z0-9_]*\.sql$/;

const lineNumberAt = (text, offset) => 1 + text.slice(0, offset).split("\n").length - 1;

function maskNonExecutableSql(sql) {
	const masked = sql.split("");
	let state = "normal";
	let blockDepth = 0;
	let dollarTag = "";
	let singleBackslashEscapes = false;
	const psqlOffsets = [];
	const mask = (index) => {
		if (index < masked.length && masked[index] !== "\n" && masked[index] !== "\r") masked[index] = " ";
	};

	for (let index = 0; index < sql.length; index += 1) {
		const char = sql[index];
		const next = sql[index + 1];

		if (state === "line-comment") {
			mask(index);
			if (char === "\n") state = "normal";
			continue;
		}
		if (state === "block-comment") {
			mask(index);
			if (char === "/" && next === "*") {
				mask(index + 1);
				blockDepth += 1;
				index += 1;
			} else if (char === "*" && next === "/") {
				mask(index + 1);
				blockDepth -= 1;
				index += 1;
				if (blockDepth === 0) state = "normal";
			}
			continue;
		}
		if (state === "single-quote") {
			mask(index);
			if (char === "\\" && singleBackslashEscapes) {
				mask(index + 1);
				index += 1;
			} else if (char === "'" && next === "'") {
				mask(index + 1);
				index += 1;
			} else if (char === "'") {
				state = "normal";
			}
			continue;
		}
		if (state === "double-quote") {
			mask(index);
			if (char === '"' && next === '"') {
				mask(index + 1);
				index += 1;
			} else if (char === '"') {
				state = "normal";
			}
			continue;
		}
		if (state === "dollar-quote") {
			if (sql.startsWith(dollarTag, index)) {
				for (let cursor = index; cursor < index + dollarTag.length; cursor += 1) mask(cursor);
				index += dollarTag.length - 1;
				state = "normal";
			} else {
				mask(index);
			}
			continue;
		}

		if (char === "-" && next === "-") {
			mask(index);
			mask(index + 1);
			index += 1;
			state = "line-comment";
		} else if (char === "/" && next === "*") {
			mask(index);
			mask(index + 1);
			index += 1;
			blockDepth = 1;
			state = "block-comment";
		} else if (char === "'") {
			mask(index);
			singleBackslashEscapes = /[eE]/.test(sql[index - 1] ?? "") && !/[A-Za-z0-9_$]/.test(sql[index - 2] ?? "");
			state = "single-quote";
		} else if (char === '"') {
			mask(index);
			state = "double-quote";
		} else if (char === "$") {
			const match = !/[A-Za-z0-9_$]/.test(sql[index - 1] ?? "") &&
				/^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(index));
			if (match) {
				dollarTag = match[0];
				for (let cursor = index; cursor < index + dollarTag.length; cursor += 1) mask(cursor);
				index += dollarTag.length - 1;
				state = "dollar-quote";
			}
		} else if (char === "\\") {
			psqlOffsets.push(index);
		}
	}

	const unterminated = state === "normal" || state === "line-comment" ? null : state;
	return { masked: masked.join(""), psqlOffsets, unterminated };
}

export function forbiddenMigrationControls(sql) {
	const { masked, psqlOffsets, unterminated } = maskNonExecutableSql(sql);
	const findings = psqlOffsets.map((offset) => ({
		line: lineNumberAt(sql, offset),
		control: "psql meta-command or execution escape",
	}));
	let statementOffset = 0;
	for (const statement of masked.split(";")) {
		const leading = statement.match(/^\s*/)?.[0].length ?? 0;
		const words = statement.slice(leading).match(/^([A-Za-z]+)(?:\s+([A-Za-z]+))?/);
		if (words) {
			const first = words[1].toUpperCase();
			const second = words[2]?.toUpperCase();
			const forbidden = ["BEGIN", "COMMIT", "END", "ROLLBACK", "ABORT"].includes(first) ||
				(first === "START" && second === "TRANSACTION") ||
				(first === "PREPARE" && second === "TRANSACTION");
			if (forbidden) {
				findings.push({
					line: lineNumberAt(sql, statementOffset + leading),
					control: second && ["START", "PREPARE"].includes(first) ? `${first} ${second}` : first,
				});
			}
		}
		statementOffset += statement.length + 1;
	}
	if (unterminated) findings.push({ line: lineNumberAt(sql, sql.length), control: `unterminated ${unterminated}` });
	return findings.sort((left, right) => left.line - right.line);
}

export function migrationOrderError(entries) {
	if (!Array.isArray(entries)) return "migration inventory must be an array";
	let previousName = null;
	let previousVersion = null;
	for (const entry of entries) {
		const name = entry?.name;
		if (typeof name !== "string") return "migration inventory contains an invalid entry";
		const version = name.slice(0, 14);
		if (previousVersion !== null && version <= previousVersion) {
			return `migration inventory is not strictly chronological: ${name} follows ${previousName}`;
		}
		previousName = name;
		previousVersion = version;
	}
	return null;
}

/**
 * Validate a migration plan and build the single psql script that applies it
 * atomically. `migrations` is the ordered manifest inventory, each entry
 * `{ name, sha256, sql }`. The script takes an advisory lock inside one
 * transaction, refuses a ledger row absent from the plan or a changed checksum,
 * skips files already recorded in public.aidr_schema_migrations and records the
 * rest. It uses psql meta-commands (\gset, \if), so run it through psql with
 * ON_ERROR_STOP=1. Shared by scripts/deployment-migrate.mjs (Compose) and the
 * Kubernetes migrations image (deploy/helm/build-images.mjs).
 */
export function buildAtomicMigrationSql(migrations, compatibleHashesFor) {
	const orderError = migrationOrderError(migrations);
	if (orderError) throw new Error(`Invalid migration manifest: ${orderError}`);
	if (migrations.length === 0) throw new Error("Invalid migration manifest: migration inventory must not be empty");
	for (const entry of migrations) {
		if (!MIGRATION_FILENAME_PATTERN.test(entry.name) || !/^[a-f0-9]{64}$/.test(entry.sha256)) throw new Error("Invalid migration manifest");
		if (typeof entry.sql !== "string" || createHash("sha256").update(entry.sql).digest("hex") !== entry.sha256) {
			throw new Error(`Migration changed since preparation: ${entry.name}`);
		}
		const forbidden = forbiddenMigrationControls(entry.sql);
		if (forbidden.length) throw new Error(`${entry.name}:${forbidden[0].line}: forbidden ${forbidden[0].control}`);
	}
	let sql = "BEGIN;\nSELECT pg_advisory_xact_lock(9112026);\nCREATE TABLE IF NOT EXISTS public.aidr_schema_migrations(name text PRIMARY KEY, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());\nREVOKE ALL ON public.aidr_schema_migrations FROM anon, authenticated;\n";
	const manifestNames = migrations.map(({ name }) => `'${name}'`).join(",");
	sql += `DO $check$ BEGIN IF EXISTS(SELECT 1 FROM public.aidr_schema_migrations WHERE name NOT IN (${manifestNames})) THEN RAISE EXCEPTION 'database contains a migration absent from the deployment manifest'; END IF; END $check$;\n`;
	for (const entry of migrations) {
		const compatibleHashes = compatibleHashesFor(entry.name, entry.sha256, entry.sql);
		const allowed = compatibleHashes.map((hash) => `'${hash}'`).join(",");
		sql += `DO $check$ BEGIN IF EXISTS(SELECT 1 FROM public.aidr_schema_migrations WHERE name='${entry.name}' AND sha256 NOT IN (${allowed})) THEN RAISE EXCEPTION 'migration checksum mismatch'; END IF; END $check$;\n`;
		for (const installedHash of compatibleHashes.slice(1)) {
			sql += `UPDATE public.aidr_schema_migrations SET sha256='${entry.sha256}' WHERE name='${entry.name}' AND sha256='${installedHash}';\n`;
		}
		sql += `SELECT NOT EXISTS(SELECT 1 FROM public.aidr_schema_migrations WHERE name='${entry.name}') AS apply_migration \\gset\n\\if :apply_migration\n${entry.sql}\nINSERT INTO public.aidr_schema_migrations(name,sha256) VALUES('${entry.name}','${entry.sha256}');\n\\endif\n`;
	}
	sql += "NOTIFY pgrst, 'reload schema';\nCOMMIT;\n";
	return sql;
}
