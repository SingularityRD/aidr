#!/usr/bin/env node
// Local receipt validation only. No ticket, network request or approval is created.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PHASES = ["submitted", "acknowledged", "escalated", "updated", "closed"];
const ROUTES = ["support", "status", "security", "privacy", "terms"];
const HEX = /^[a-f0-9]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const known = value => typeof value === "string" && value.trim().length > 0 && value.length <= 200 && !/^(required|unknown|tbd|not held|fixture|example)$/i.test(value.trim());
const utc = value => typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;

export function validateTicketDrill(record, candidateDigest, { now = Date.now() } = {}) {
	const errors = [];
	const require = (condition, message) => { if (!condition) errors.push(message); };
	if (!record || typeof record !== "object" || Array.isArray(record)) return ["receipt must be an object"];
	require(record.kind === "aidr_support_ticket_drill_receipt" && record.schema_version === 1, "unsupported receipt schema");
	require(HEX.test(candidateDigest ?? "") && record.candidate_digest === candidateDigest, "candidate digest must match the independently supplied inventory SHA-256");
	require(record.environment === "operated" && record.synthetic_ticket === true, "require a benign drill in an operated ticket system; local fixtures are not field evidence");
	require(typeof record.case_id === "string" && ID.test(record.case_id) && ["P0", "P1", "P2", "P3"].includes(record.severity), "opaque case ID and P0-P3 severity required");
	require(known(record.primary_operator) && known(record.backup_operator) && record.primary_operator.trim().toLowerCase() !== record.backup_operator.trim().toLowerCase(), "distinct named primary and backup operators required");
	require(known(record.reviewer), "named reviewer required");
	require(Array.isArray(record.events) && record.events.length === PHASES.length, "five ticket lifecycle events required");
	let previous = -Infinity;
	for (const [index, phase] of PHASES.entries()) {
		const event = Array.isArray(record.events) ? record.events[index] : undefined;
		require(event?.phase === phase && utc(event?.at_utc) && known(event?.actor), `valid ${phase} event and actor required`);
		const time = Date.parse(event?.at_utc);
		require(Number.isFinite(time) && time >= previous && time <= now, "event times must be chronological and not in the future");
		previous = time;
	}
	require(Array.isArray(record.channels) && record.channels.length === ROUTES.length, "five rendered customer-channel reviews required");
	for (const route of ROUTES) {
		const matches = Array.isArray(record.channels) ? record.channels.filter(channel => channel?.route === route) : [];
		const channel = matches[0];
		let url;
		try { url = new URL(channel?.final_url); } catch { /* reported below */ }
		require(matches.length === 1 && channel?.reached === true && utc(channel?.reviewed_at_utc) && Date.parse(channel.reviewed_at_utc) <= now && known(channel.owner) && url?.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash, `operated ${route} destination and reviewer evidence required`);
	}
	require(["published", "not_required"].includes(record.status_update) && known(record.status_update_reference_or_reason), "status update reference or documented no-update reason required");
	require(["not_requested", "separate_consent_record"].includes(record.diagnostics) && known(record.diagnostic_reference_or_reason), "diagnostic consent reference or no-collection reason required");
	require(Array.isArray(record.evidence) && record.evidence.length > 0 && record.evidence.length <= 10, "redacted operated-system evidence required");
	for (const evidence of Array.isArray(record.evidence) ? record.evidence : []) require(typeof evidence?.path === "string" && evidence.path.length > 0 && evidence.path.length <= 300 && HEX.test(evidence.sha256 ?? ""), "evidence path and SHA-256 required");
	return errors;
}

function readBounded(path) {
	const stat = lstatSync(path);
	if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024 * 1024) throw new Error("receipt/evidence must be a regular file of at most 1 MiB");
	return readFileSync(path);
}

function selfTest() {
	const digest = "a".repeat(64);
	const record = { schema_version: 1, kind: "aidr_support_ticket_drill_receipt", candidate_digest: digest, environment: "operated", synthetic_ticket: true, case_id: "CASE-123", severity: "P0", primary_operator: "Primary person", backup_operator: "Backup person", reviewer: "Review person", events: PHASES.map((phase, index) => ({ phase, actor: "Drill operator", at_utc: `2026-10-06T10:0${index}:00.000Z` })), channels: ROUTES.map(route => ({ route, final_url: `https://test.invalid/${route}`, owner: "Channel owner", reached: true, reviewed_at_utc: "2026-10-06T10:00:00.000Z" })), status_update: "not_required", status_update_reference_or_reason: "Synthetic ticket did not affect service", diagnostics: "not_requested", diagnostic_reference_or_reason: "No diagnostic collection", evidence: [{ path: "redacted-system-export.json", sha256: digest }] };
	const clock = { now: Date.parse("2026-10-07T00:00:00.000Z") };
	assert.deepEqual(validateTicketDrill(record, digest, clock), []);
	for (const change of [{ environment: "fixture" }, { candidate_digest: "b".repeat(64) }, { backup_operator: record.primary_operator }, { events: [...record.events].reverse() }, { events: {} }, { channels: record.channels.slice(1) }, { evidence: [] }]) assert.ok(validateTicketDrill({ ...record, ...change }, digest, clock).length > 0);
	assert.ok(validateTicketDrill({ ...record, events: [{ ...record.events[0], at_utc: "2026-02-31T10:00:00.000Z" }, ...record.events.slice(1)] }, digest, clock).length > 0);
	assert.ok(validateTicketDrill(record, digest, { now: Date.parse("2026-10-05T00:00:00.000Z") }).length > 0);
	console.log("LOCAL_SELF_TEST_PASS: 10 receipt checks; no operated ticket or customer acceptance");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		const args = process.argv.slice(2);
		if (args.length === 1 && args[0] === "--self-test") selfTest();
		else {
			if (args.length !== 3 || args[1] !== "--candidate") throw new Error("Usage: node scripts/verify-support-ticket-drill.mjs RECEIPT.json --candidate SHA256 | --self-test");
			const receiptPath = resolve(args[0]);
			const record = JSON.parse(readBounded(receiptPath).toString("utf8"));
			const errors = validateTicketDrill(record, args[2]);
			if (errors.length) throw new Error(errors.join("; "));
			const root = realpathSync(dirname(receiptPath));
			for (const evidence of record.evidence) {
				const target = resolve(root, evidence.path);
				const rel = relative(root, realpathSync(target));
				if (isAbsolute(evidence.path) || rel.startsWith("..") || isAbsolute(rel)) throw new Error("evidence must stay inside the receipt's restricted directory");
				if (createHash("sha256").update(readBounded(target)).digest("hex") !== evidence.sha256) throw new Error("redacted evidence digest mismatch");
			}
			console.log("STRUCTURALLY_VALID_OPERATOR_RECEIPT: matching candidate and evidence bytes; human authenticity, route reachability, support clocks and gate approval still require reviewer verification");
		}
	} catch (error) { console.error(error.message); process.exitCode = 1; }
}
