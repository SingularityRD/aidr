import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

// The compliance-report Edge Function embeds the privacy data-flow matrix at
// build time: a deployed function bundle contains supabase/functions/ only, not
// docs/. This keeps one source of truth (the matrix JSON) and a drift check.
//
//   node scripts/sync-compliance-data-flows.mjs          fail on drift
//   node scripts/sync-compliance-data-flows.mjs --write  regenerate

const matrixPath = new URL(
	"../docs/production-readiness/privacy-data-flow-matrix.json",
	import.meta.url,
);
const edgeDataFlowsPath = new URL(
	"../supabase/functions/_shared/compliance-data-flows.ts",
	import.meta.url,
);

// Only the descriptive columns reach the report. `source` (repository paths)
// and `evidence` (internal record ids) stay in the engineering matrix.
const FLOW_FIELDS = [
	"flow_id",
	"data_class",
	"fields",
	"purpose",
	"trigger",
	"destination",
	"destination_domain",
	"region",
	"subprocessor",
	"lawful_basis",
	"retention",
	"deletion",
	"access",
	"transfer_mechanism",
	"status",
	"unknowns",
];

function isStringList(value) {
	return Array.isArray(value) && value.every((item) => typeof item === "string");
}

export function complianceDataFlowsSource() {
	const raw = readFileSync(matrixPath, "utf8").replaceAll("\r\n", "\n");
	const matrix = JSON.parse(raw);
	if (!Array.isArray(matrix.flows) || matrix.flows.length === 0) {
		throw new Error("privacy data-flow matrix has no flows");
	}
	const flows = matrix.flows.map((flow) => {
		const projected = {};
		for (const field of FLOW_FIELDS) {
			const value = flow[field];
			const ok = field === "fields" || field === "unknowns" ? isStringList(value) : typeof value === "string";
			if (!ok) throw new Error(`${flow.flow_id ?? "flow"}.${field} has an unexpected shape`);
			projected[field] = value;
		}
		return projected;
	});
	for (const field of ["matrix_id", "status", "updated_at", "deployment_scope"]) {
		if (typeof matrix[field] !== "string") throw new Error(`matrix.${field} must be a string`);
	}
	if (!isStringList(matrix.limitations)) throw new Error("matrix.limitations must be strings");
	const embedded = {
		source: "docs/production-readiness/privacy-data-flow-matrix.json",
		source_sha256: createHash("sha256").update(raw, "utf8").digest("hex"),
		matrix_id: matrix.matrix_id,
		matrix_status: matrix.status,
		matrix_updated_at: matrix.updated_at,
		deployment_scope: matrix.deployment_scope,
		flows,
		limitations: matrix.limitations,
	};
	return [
		"// Generated from docs/production-readiness/privacy-data-flow-matrix.json; do not edit.",
		"// Regenerate: node scripts/sync-compliance-data-flows.mjs --write",
		"",
		"export interface ComplianceDataFlow {",
		...FLOW_FIELDS.map((field) =>
			field === "fields" || field === "unknowns"
				? `\treadonly ${field}: readonly string[];`
				: `\treadonly ${field}: string;`,
		),
		"}",
		"",
		"export const COMPLIANCE_DATA_FLOW_MATRIX: {",
		"\treadonly source: string;",
		"\treadonly source_sha256: string;",
		"\treadonly matrix_id: string;",
		"\treadonly matrix_status: string;",
		"\treadonly matrix_updated_at: string;",
		"\treadonly deployment_scope: string;",
		"\treadonly flows: readonly ComplianceDataFlow[];",
		"\treadonly limitations: readonly string[];",
		`} = ${JSON.stringify(embedded, null, "\t")};`,
		"",
	].join("\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	const expected = complianceDataFlowsSource();
	if (process.argv.includes("--write")) {
		writeFileSync(edgeDataFlowsPath, expected);
	} else {
		let current = "";
		try {
			current = readFileSync(edgeDataFlowsPath, "utf8").replaceAll("\r\n", "\n");
		} catch {
			// Missing counts as drift.
		}
		if (current !== expected) {
			console.error("Compliance data-flow drift: run node scripts/sync-compliance-data-flows.mjs --write");
			process.exitCode = 1;
		} else {
			console.log("Compliance data-flow embed matches the privacy data-flow matrix.");
		}
	}
}
