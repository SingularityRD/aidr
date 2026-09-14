import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const defaultRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Fallback vocabulary, used only when the record does not declare one. The
 * record's own `statusVocabulary` is authoritative for a given backlog.
 */
export const DEFAULT_STATUS_VOCABULARY = [
  "DISCOVERED",
  "CONFIRMED",
  "IN_PROGRESS",
  "IMPLEMENTED_UNVERIFIED",
  "VERIFIED_CLOSED",
  "BLOCKED_EXTERNAL",
  "REOPENED",
];

/**
 * Findings that were still open when this machine-checked review was written.
 *
 * None of them may silently disappear from the backlog, and each one must carry
 * the honesty fields (`localEvidence`, plus `remainingExternal` while it is not
 * VERIFIED_CLOSED). A finding may only leave this list by being closed with real
 * evidence or by an explicit, recorded decision - never by deletion.
 */
export const PREVIOUSLY_OPEN_FINDINGS = [
  "AIDR-012",
  "AIDR-016",
  "AIDR-019",
  "AIDR-044",
  "AIDR-049",
  "AIDR-050",
  "AIDR-051",
  "AIDR-052",
];

const EVIDENCE_FIELDS = ["claim", "evidencePath", "command", "verifiedBy"];
const SCRIPT_FILE = /\.(mjs|cjs|js|ts)$/;

function readPackageScripts(repoRoot) {
  try {
    const parsed = JSON.parse(readFileSync(resolve(repoRoot, "package.json"), "utf8"));
    return parsed.scripts ?? {};
  } catch {
    return {};
  }
}

/**
 * A recorded command has to be runnable from the repository root. Exactly two
 * forms are accepted, because "a command that does not exist" is the failure
 * mode this gate exists to prevent:
 *
 *   - `pnpm <script> [args]` / `pnpm run <script> [args]`: `<script>` must be a
 *     package.json script.
 *   - `node [--flags] <script-file> [args]`: every referenced script file must
 *     exist on disk. Arguments may be placeholders (`<source-installation>`).
 *
 * Returns `{ ok: true, kind }` or `{ ok: false, reason }`.
 */
export function resolveCommand(repoRoot, command) {
  if (typeof command !== "string" || command.trim() === "") {
    return { ok: false, reason: "command is empty" };
  }
  const tokens = command.trim().split(/\s+/);
  const binary = tokens[0];

  if (["pnpm", "pnpm.cmd", "npm", "npm.cmd", "yarn"].includes(binary)) {
    const script = tokens[1] === "run" ? tokens[2] : tokens[1];
    if (!script) return { ok: false, reason: `no package.json script named in "${command}"` };
    const scripts = readPackageScripts(repoRoot);
    if (Object.hasOwn(scripts, script)) return { ok: true, kind: `package.json#scripts.${script}` };
    return { ok: false, reason: `package.json has no "${script}" script` };
  }

  if (binary === "node" || binary === "node.exe") {
    const files = tokens
      .slice(1)
      .filter((token) => !token.startsWith("-") && !token.startsWith("<"))
      .filter((token) => SCRIPT_FILE.test(token));
    if (files.length === 0) return { ok: false, reason: `"${command}" names no script file` };
    for (const file of files) {
      if (!existsSync(resolve(repoRoot, file))) {
        return { ok: false, reason: `script file does not exist: ${file}` };
      }
    }
    return { ok: true, kind: "node script" };
  }

  return {
    ok: false,
    reason: `unsupported command form "${binary}" (use "pnpm <script>" or "node <script-file>")`,
  };
}

/**
 * Enforce the backlog's honesty invariants.
 *
 * 1. Every finding's `status` is in the declared vocabulary.
 * 2. A `VERIFIED_CLOSED` finding must carry at least one valid `localEvidence`
 *    entry, unless it is explicitly declared in `closedWithoutLocalEvidence`
 *    (a pre-`localEvidence` closure whose prose evidence cannot be turned into a
 *    machine-checkable command without inventing one). Declaring debt that is no
 *    longer true also fails.
 * 3. A finding that is not `VERIFIED_CLOSED` must explain its residual in a
 *    non-empty `remainingExternal`.
 * 4. Every `localEvidence` entry must be complete, point at a file that exists
 *    on disk, and name a command that resolves (see `resolveCommand`).
 * 5. Every previously-open finding must still be present with its honesty
 *    fields.
 *
 * `options.root` overrides the repository root (used by the tests).
 * `options.strictClosedEvidence` ignores the declared debt list, i.e. it demands
 * machine evidence for every closure. The shipped record predates the field for
 * its 60 legacy closures, so the CLI runs without it; the tests exercise it.
 */
export function validateBacklog(backlog, options = {}) {
  const repoRoot = options.root ?? defaultRoot;
  const strictClosedEvidence = options.strictClosedEvidence === true;
  const errors = [];
  const fail = (code, findingId, message) => errors.push({ code, findingId, message });

  const vocabulary =
    Array.isArray(backlog?.statusVocabulary) && backlog.statusVocabulary.length > 0
      ? backlog.statusVocabulary
      : DEFAULT_STATUS_VOCABULARY;

  const findings = Array.isArray(backlog?.findings) ? backlog.findings : [];
  if (findings.length === 0) {
    fail("FINDINGS_MISSING", null, "record declares no findings array");
  }

  const debtDeclaration = backlog?.closedWithoutLocalEvidence;
  let declaredDebt = new Set();
  if (debtDeclaration !== undefined) {
    if (!Array.isArray(debtDeclaration?.findings)) {
      fail(
        "DEBT_DECLARATION_INVALID",
        null,
        "closedWithoutLocalEvidence must declare a findings array",
      );
    } else {
      declaredDebt = new Set(debtDeclaration.findings);
    }
  }

  const seen = new Set();
  let evidenceEntries = 0;
  let findingsWithEvidence = 0;

  for (const finding of findings) {
    const id = typeof finding?.id === "string" && finding.id !== "" ? finding.id : "<missing-id>";
    if (seen.has(id)) fail("DUPLICATE_ID", id, "finding id appears more than once");
    seen.add(id);

    const status = finding?.status;
    const known = vocabulary.includes(status);
    if (!known) {
      fail("STATUS_UNKNOWN", id, `status ${JSON.stringify(status)} is not in the declared vocabulary`);
    }
    const closed = status === "VERIFIED_CLOSED";

    let validEvidence = 0;
    if (finding?.localEvidence !== undefined) {
      if (!Array.isArray(finding.localEvidence)) {
        fail("EVIDENCE_ENTRY_INVALID", id, "localEvidence must be an array");
      } else {
        finding.localEvidence.forEach((entry, index) => {
          const label = `localEvidence[${index}]`;
          if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
            fail("EVIDENCE_ENTRY_INVALID", id, `${label} must be an object`);
            return;
          }
          let complete = true;
          for (const field of EVIDENCE_FIELDS) {
            if (typeof entry[field] !== "string" || entry[field].trim() === "") {
              fail("EVIDENCE_ENTRY_INVALID", id, `${label}.${field} must be a non-empty string`);
              complete = false;
            }
          }
          if (!complete) return;
          let valid = true;
          if (!existsSync(resolve(repoRoot, entry.evidencePath))) {
            fail(
              "EVIDENCE_PATH_MISSING",
              id,
              `${label}.evidencePath does not exist: ${entry.evidencePath}`,
            );
            valid = false;
          }
          const resolved = resolveCommand(repoRoot, entry.command);
          if (!resolved.ok) {
            fail("COMMAND_UNRESOLVED", id, `${label}.command is not runnable (${resolved.reason}): ${entry.command}`);
            valid = false;
          }
          if (valid) validEvidence += 1;
        });
        evidenceEntries += finding.localEvidence.length;
        if (finding.localEvidence.length > 0) findingsWithEvidence += 1;
      }
    }

    if (closed) {
      const declared = declaredDebt.has(id);
      if (strictClosedEvidence || !declared) {
        if (validEvidence === 0) {
          fail(
            "CLOSED_WITHOUT_EVIDENCE",
            id,
            "VERIFIED_CLOSED requires at least one localEvidence entry with an existing evidencePath and a resolvable command",
          );
        }
      } else if (validEvidence > 0) {
        fail(
          "CLOSED_DEBT_STALE",
          id,
          "declared in closedWithoutLocalEvidence but now carries localEvidence; remove it from that list",
        );
      }
    } else if (typeof finding?.remainingExternal !== "string" || finding.remainingExternal.trim() === "") {
      fail(
        "REMAINING_EXTERNAL_MISSING",
        id,
        "a finding that is not VERIFIED_CLOSED must explain the residual in a non-empty remainingExternal",
      );
    }
  }

  for (const id of PREVIOUSLY_OPEN_FINDINGS) {
    const finding = findings.find((item) => item?.id === id);
    if (!finding) {
      fail("TRACKED_FINDING_MISSING", id, "previously-open finding is no longer present in the backlog");
      continue;
    }
    if (!Array.isArray(finding.localEvidence)) {
      fail("TRACKED_FINDING_FIELD_MISSING", id, "previously-open finding must carry a localEvidence array");
    }
  }

  return {
    ok: errors.length === 0,
    errors,
    findings,
    vocabulary,
    declaredDebt,
    evidenceEntries,
    findingsWithEvidence,
  };
}

function run() {
  const raw = readFileSync(resolve(defaultRoot, "READINESS_BACKLOG.json"), "utf8");
  let j;
  try {
    j = JSON.parse(raw);
  } catch (err) {
    console.error("PARSE FAILED:", err.message);
    process.exit(1);
  }

  const findings = j.findings ?? j.items ?? [];
  console.log("parsed OK, findings:", findings.length);

  const counts = {};
  const prio = {};
  const missing = [];
  for (const f of findings) {
    counts[f.status] = (counts[f.status] ?? 0) + 1;
    prio[f.priority] = (prio[f.priority] ?? 0) + 1;
    for (const k of ["id", "feature", "priority", "status", "evidence", "acceptanceCriteria"]) {
      if (f[k] === undefined) missing.push(`${f.id}: missing ${k}`);
    }
    if (!Array.isArray(f.evidence)) missing.push(`${f.id}: evidence not an array`);
  }
  console.log("status:", JSON.stringify(counts));
  console.log("priority:", JSON.stringify(prio));
  console.log("schema problems:", missing.length === 0 ? "none" : missing.join("; "));

  const dupes = findings.map((f) => f.id).filter((id, i, a) => a.indexOf(id) !== i);
  console.log("duplicate ids:", dupes.length ? dupes.join(", ") : "none");

  const p0open = findings.filter((f) => f.priority === "P0" && f.status !== "VERIFIED_CLOSED");
  console.log("P0 not verified closed:", p0open.map((f) => `${f.id}(${f.status})`).join(", ") || "none");

  const result = validateBacklog(j);
  console.log(
    "local evidence:",
    `${result.evidenceEntries} entries across ${result.findingsWithEvidence} findings`,
  );
  console.log("closed without local evidence (declared debt):", result.declaredDebt.size);

  if (result.ok) {
    console.log("backlog invariants: PASS");
    return;
  }
  console.error("backlog invariants: FAIL");
  for (const error of result.errors) {
    console.error(`- [${error.code}] ${error.findingId ?? "<record>"}: ${error.message}`);
  }
  process.exitCode = 1;
}

const invokedDirectly =
  process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) run();
