#!/usr/bin/env node
/**
 * AIG Data Compiler — build-time indexer for AI-Infra-Guard dataset.
 *
 * Compiles three indexes from vendor/ai-infra-guard/data/ into
 * packages/core/src/generated/ as minified JSON for runtime use.
 *
 * Zero external dependencies — runs on plain Node.js.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, createSign } from "node:crypto";
import { execFileSync } from "node:child_process";

// ─── Paths ───────────────────────────────────────────────────────────────────
const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const AIG = join(ROOT, "vendor", "ai-infra-guard");
const OUT = join(ROOT, "packages", "core", "src", "generated");
const AIG_MANIFEST_FILE = "aig-data-manifest.json";
const DATA_SCHEMA_VERSION = 2;

const CVE_DIRS = [
  join(AIG, "data", "vuln_en"),
  join(AIG, "data", "vuln"),
];
const FP_DIR = join(AIG, "data", "fingerprints");

/** Return a stable source revision.  The compiler is deterministic for a
 * pinned checkout; wall-clock time must never enter a generated artefact. */
function sourceRevision() {
  try {
    return execFileSync("git", ["-C", AIG, "rev-parse", "HEAD"], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return process.env.AIG_SOURCE_COMMIT || "unknown";
  }
}

function sourceDate() {
  const epoch = Number(process.env.SOURCE_DATE_EPOCH || "");
  if (Number.isFinite(epoch) && epoch > 0) return new Date(epoch * 1000).toISOString();
  const explicit = process.env.AIG_SOURCE_DATE;
  if (explicit) {
    const parsed = new Date(explicit);
    if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
  }
  try {
    return execFileSync("git", ["-C", AIG, "show", "-s", "--format=%cI", "HEAD"], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return "1970-01-01T00:00:00.000Z";
  }
}

const SOURCE_COMMIT = sourceRevision();
const GENERATED_AT = sourceDate();

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
  return JSON.stringify(value);
}

function sourceTreeDigest() {
  const files = [
    ...walkYaml(join(AIG, "data", "vuln")),
    ...walkYaml(join(AIG, "data", "vuln_en")),
    ...walkYaml(FP_DIR),
  ].sort((a, b) => a.path.localeCompare(b.path));
  const digestInput = files
    .map(({ path }) => `${path.slice(AIG.length + 1).replaceAll("\\", "/")}\n${sha256(readFileSync(path))}`)
    .join("\n");
  return sha256(digestInput);
}

function signManifest(payload) {
  const privateKeyPath = process.env.AIG_SIGNING_PRIVATE_KEY_PATH;
  const privateKey = process.env.AIG_SIGNING_PRIVATE_KEY ||
    (privateKeyPath && existsSync(privateKeyPath) ? readFileSync(privateKeyPath, "utf8") : "");
  if (!privateKey) return null;
  const signer = createSign("RSA-SHA256");
  signer.update(canonicalJson(payload));
  signer.end();
  return {
    algorithm: "RSA-SHA256",
    key_id: process.env.AIG_SIGNING_KEY_ID || "unspecified",
    value: signer.sign(privateKey, "base64"),
  };
}

function buildManifest(artifacts) {
  const artifactHashes = Object.fromEntries(
    Object.entries(artifacts).map(([name, data]) => [name, {
      sha256: sha256(data),
      bytes: Buffer.byteLength(data),
    }]),
  );
  const bundleId = sha256(canonicalJson(artifactHashes));
  const payload = {
    schema: "aig-data-manifest/v1",
    generated: GENERATED_AT,
    source: {
      repository: "https://github.com/tencent/AI-Infra-Guard",
      commit: SOURCE_COMMIT,
      tree_sha256: sourceTreeDigest(),
    },
    bundle_id: bundleId,
    artifacts: artifactHashes,
    counts: {
      cves: JSON.parse(artifacts["aig-cve-index.json"]).cves.length,
      fingerprints: JSON.parse(artifacts["aig-fingerprints.json"]).fingerprints.length,
      mcp_categories: JSON.parse(artifacts["aig-mcp-categories.json"]).categories.length,
    },
  };
  return {
    ...payload,
    signature: signManifest(payload),
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Check if a line is a top-level key (no leading whitespace) */
function isTopLevel(line) {
  return line.length > 0 && !line[0].match(/\s/);
}

/** Parse an AIG YAML file (simplified — handles the known schema).
 *
 *  Schema:
 *    info:          # container with name, cve, summary, details, cvss, severity, security_advise
 *      name: ...
 *      cve: ...
 *      ...
 *    rule: "..."    # version constraint string
 *    references:    # list of URLs
 *      - ...
 *
 *  Keys under `info` are promoted to the top-level result.
 */
function parseSimpleYaml(text) {
  // Normalise line endings
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const result = {};

  // State machine
  let scanningInfo = false;    // currently scanning keys under `info:`
  let inBlockScalar = null;    // key whose value is a block-scalar (|)
  let blockScalarIndent = 0;   // indent level of the block scalar start
  let blockLines = [];
  let inRefs = false;
  let refs = [];

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trimEnd();
    const indent = trimmed.length - trimmed.trimStart().length;

    // ── Handle block-scalar continuation ──
    if (inBlockScalar) {
      // Block scalar lines are indented MORE than the scalar start line
      if (indent > blockScalarIndent) {
        // Still in block scalar — strip `blockScalarIndent` spaces
        const content = trimmed.slice(blockScalarIndent);
        // If there are empty lines within the block, preserve them
        blockLines.push(content);
        continue;
      } else {
        // Block scalar ended (indent <= scalar start indent)
        result[inBlockScalar] = blockLines.join("\n").replace(/\n+$/, "").trimEnd();
        inBlockScalar = null;
        blockScalarIndent = 0;
        blockLines = [];
        // Fall through to process current line
      }
    }

    // ── Handle references list ──
    if (inRefs) {
      const listMatch = trimmed.match(/^\s*-\s+(.*)$/);
      if (listMatch) {
        refs.push(listMatch[1].trim());
        continue;
      } else {
        inRefs = false;
        result.references = refs;
        refs = [];
        // Fall through
      }
    }

    // Skip empty and comments
    if (trimmed === "" || trimmed.startsWith("#")) continue;

    // ── Top-level `info:` — begin scanning info block ──
    if (trimmed === "info:" || trimmed.startsWith("info:")) {
      scanningInfo = true;
      continue;
    }

    // ── Top-level keys ──
    if (isTopLevel(trimmed)) {
      // We're leaving the info block (if we were in it)
      scanningInfo = false;

      const kv = trimmed.match(/^([\w-]+):\s*(.*)$/);
      if (kv) {
        const key = kv[1];
        let val = kv[2].trim();

        if (key === "references") {
          if (val && val !== "" && val !== "-") {
            refs = [val.replace(/^-\s*/, "").trim()];
            result.references = refs;
            refs = [];
          } else {
            inRefs = true;
            refs = [];
          }
          continue;
        }
        if (key === "rule") {
          // Only remove quotes around the complete scalar.  A rule such as
          // `version < "1.2.3"` starts with the word `version`; stripping its
          // trailing quote corrupts the source expression and provenance.
          if ((val.startsWith('"') && val.endsWith('"')) ||
              (val.startsWith("'") && val.endsWith("'"))) {
            val = val.slice(1, -1);
          }
          result.rule = val;
          continue;
        }
        result[key] = val;
      }
      continue;
    }

    // ── Indented line — must be inside info block ──
    if (scanningInfo) {
      // Strip 2-space indent
      const content = trimmed.replace(/^ {2}/, "");
      if (content === "") continue;

      // Check for block-scalar start: `key: |`
      const bsStart = content.match(/^([\w-]+):\s*\|\s*$/);
      if (bsStart) {
        inBlockScalar = bsStart[1];
        blockScalarIndent = indent;
        blockLines = [];
        continue;
      }

      // Regular key: value
      const kv = content.match(/^([\w-]+):\s*(.*)$/);
      if (kv) {
        const key = kv[1];
        let val = kv[2].trim();
        // Strip surrounding quotes
        val = val.replace(/^["']|["']$/g, "");
        // Handle `key: |` (inline)
        if (val === "|") {
          inBlockScalar = key;
          blockScalarIndent = indent;
          blockLines = [];
          continue;
        }
        result[key] = val;
        continue;
      }

      // Fallback: continuation line (shouldn't normally reach here)
      if (inBlockScalar) {
        blockLines.push(content);
      }
    }
  }

  // Flush remaining state
  if (inBlockScalar) {
    result[inBlockScalar] = blockLines.join("\n").replace(/\n+$/, "").trimEnd();
    inBlockScalar = null;
  }
  if (inRefs) {
    result.references = refs;
  }

  return result;
}

/** Parse CVSS vector string to extract base score.
 *  Returns null if unparseable. */
function parseCvssScore(cvssStr) {
  if (!cvssStr || cvssStr.trim() === "") return null;
  const s = cvssStr.trim();

  // Try direct float
  const floatMatch = s.match(/^(\d+\.\d+)$/);
  if (floatMatch) return parseFloat(floatMatch[1]);

  // Try CVSS vector
  const vMatch = s.match(/CVSS:[34]\.[01]/);
  if (!vMatch) return null;

  // Extract AV, AC, PR, UI, S, C, I, A
  const av = s.match(/AV:([NALP])/);
  const ac = s.match(/AC:([LH])/);
  const pr = s.match(/PR:([NLH])/);
  const ui = s.match(/UI:([NR])/);
  const scope = s.match(/S:([UC])/);
  const c = s.match(/C:([NLH])/);
  const i = s.match(/I:([NLH])/);
  const a = s.match(/A:([NLH])/);

  if (!av || !ac || !c) return null;

  // CVSS v3.1 base score calculation
  const avVal = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[av[1]] ?? 0.85;
  const acVal = { L: 0.77, H: 0.44 }[ac[1]] ?? 0.77;
  const prVal = scope
    ? scope[1] === "U"
      ? { N: 0.85, L: 0.62, H: 0.27 }[pr?.[1]] ?? 0.85
      : { N: 0.85, L: 0.68, H: 0.5 }[pr?.[1]] ?? 0.85
    : 0.85;
  const uiVal = { N: 0.85, R: 0.62 }[ui?.[1]] ?? 0.85;
  const cVal = { N: 0, L: 0.22, H: 0.56 }[c?.[1]] ?? 0;
  const iVal = { N: 0, L: 0.22, H: 0.56 }[i?.[1]] ?? 0;
  const aVal = { N: 0, L: 0.22, H: 0.56 }[a?.[1]] ?? 0;

  const iss = 1 - (1 - cVal) * (1 - iVal) * (1 - aVal);
  const impact = scope?.[1] === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const exploitability = 8.22 * avVal * acVal * prVal * uiVal;

  let score;
  if (impact <= 0) {
    score = 0;
  } else if (scope?.[1] === "U") {
    score = Math.min(impact + exploitability, 10);
  } else {
    const fImpact = scope?.[1] === "U" ? impact : 1.176 * impact;
    score = Math.min(fImpact + exploitability, 10);
  }

  return Math.round(score * 10) / 10;
}

/**
 * Translate the small version subset of AIG's rule DSL into a semver range.
 *
 * The upstream parser also supports non-version predicates (`body=`,
 * `is_internal==`, regexes, ...).  Those rules are deliberately retained as
 * opaque source text and marked `unsupported`; an empty semver range is not a
 * safe fallback because semver treats it as matching every version.
 */
function parseRule(ruleStr) {
  const raw = String(ruleStr || "").trim();
  if (!raw || raw === "null" || raw === "~") {
    return { raw, status: "unscoped", semver: null };
  }

  // The YAML source occasionally wraps the entire expression in single
  // quotes. Strip only that outer pair; quoted versions must remain intact.
  const unwrapped = raw.replace(/^'(.*)'$/s, "$1").replace(/^"(.*)"$/s, "$1").trim();
  const withoutComments = unwrapped.replace(/\s+#.*$/, "").trim();
  const branches = withoutComments.split(/\s*\|\|\s*/).map((branch) => branch.trim());
  const ranges = [];

  for (const branch of branches) {
    const expression = branch.replace(/^\(\s*/, "").replace(/\s*\)$/, "").trim();
    const comparisons = expression.split(/\s*&&\s*/).map((part) => part.trim());
    const branchRanges = [];
    for (const comparison of comparisons) {
      const match = comparison.match(/^version\s*(<=|>=|<|>|==|=)\s*["']?([^"']+?)["']?$/i);
      if (!match) return { raw, status: "unsupported", semver: null };
      let [, operator, version] = match;
      version = version.trim().replace(/^v(?=\d)/i, "");
      // semver cannot compare date strings, git revisions, package-qualified
      // versions, or other upstream build identifiers. Keep these opaque.
      if (!/^\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version)) {
        return { raw, status: "unsupported", semver: null };
      }
      if (/^\d+$/.test(version) && version.length > 2) {
        return { raw, status: "unsupported", semver: null };
      }
      if (/^\d+$/.test(version)) version = `${version}.0.0`;
      else if (/^\d+\.\d+$/.test(version)) version = `${version}.0`;
      if (operator === "=" || operator === "==") operator = "=";
      branchRanges.push(`${operator}${version}`);
    }
    ranges.push(branchRanges.join(" "));
  }

  if (ranges.length === 0) return { raw, status: "unscoped", semver: null };
  return { raw, status: "semver", semver: ranges.join(" || ") };
}

function normalizeProductName(value) {
  return String(value || "").trim().replace(/\s+/g, " ");
}

function productAliases(product, framework) {
  const values = new Set();
  for (const value of [product, framework]) {
    const normalized = normalizeProductName(value);
    if (!normalized) continue;
    values.add(normalized);
    values.add(normalized.toLowerCase());
    values.add(normalized.replace(/[\s_]+/g, "-"));
    values.add(normalized.toLowerCase().replace(/[\s_]+/g, "-"));
  }
  values.delete(normalizeProductName(product));
  return [...values].sort((a, b) => a.localeCompare(b));
}

/** Walk directory recursively for *.yaml files, returning {path, relDir} */
function walkYaml(dir) {
  if (!existsSync(dir)) return [];
  const results = [];
  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkYaml(full));
    } else if (entry.isFile() && entry.name.endsWith(".yaml")) {
      results.push({ path: full, relDir: dir });
    }
  }
  return results;
}

/** Normalize severity string to lowercase English */
function normalizeSeverity(s) {
  if (!s) return "unknown";
  let v = s.trim().toLowerCase();
  // Strip inline comments
  const hashIdx = v.indexOf("#");
  if (hashIdx >= 0) v = v.slice(0, hashIdx).trim();
  // Chinese → English mapping
  const chineseMap = {
    "严重": "critical",
    "危急": "critical",
    "高": "high",
    "高危": "high",
    "中": "medium",
    "中危": "medium",
    "中等": "medium",
    "低": "low",
    "低危": "low",
  };
  if (chineseMap[v]) return chineseMap[v];
  if (["critical", "high", "medium", "low", "info", "none"].includes(v)) return v;
  return "unknown";
}

/** Read YAML file and return parsed object */
function readYaml(filePath) {
  try {
    const text = readFileSync(filePath, "utf-8");
    return parseSimpleYaml(text);
  } catch {
    return null;
  }
}

// ─── 1. CVE Index Compiler ──────────────────────────────────────────────────

function compileCveIndex() {
  console.log("[aig] Compiling CVE index...");

  // Collect all entries, keyed by "cveId:framework" to de-duplicate
  const entryMap = new Map();
  const frameworks = {};

  // Priority: vuln_en (English) before vuln/ (Chinese)
  const orderedDirs = [
    { dir: join(AIG, "data", "vuln_en"), lang: "en" },
    { dir: join(AIG, "data", "vuln"), lang: "zh" },
  ];

  for (const { dir: cveDir, lang } of orderedDirs) {
    if (!existsSync(cveDir)) {
      console.log(`[aig]   Skipping (not found): ${cveDir}`);
      continue;
    }

    const frameworkDirs = readdirSync(cveDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .sort((a, b) => a.name.localeCompare(b.name));

    for (const fwDir of frameworkDirs) {
      const fwPath = join(cveDir, fwDir.name);
      const yamlFiles = walkYaml(fwPath).sort((a, b) => a.path.localeCompare(b.path));

      for (const { path: yamlFile } of yamlFiles) {
        const data = readYaml(yamlFile);
        if (!data) continue;

        const cveId = (data.cve || "").trim();
        if (!cveId) continue;

        const framework = fwDir.name;
        const dedupKey = `${cveId}:${framework}`;

        // Skip if already processed from a higher-priority source
        if (lang === "zh" && entryMap.has(dedupKey)) continue;

        const severity = normalizeSeverity(data.severity || "");
        const rule = parseRule(data.rule || "");
        const cvssStr = data.cvss || "";
        const product = normalizeProductName(data.name || fwDir.name);

        const entry = {
          id: cveId,
          // `p` is the canonical product/service identifier from AIG.  AIG's
          // vulnerability corpus is not an npm/PyPI package database, so `e`
          // is explicitly `product` and never fabricated as a package
          // ecosystem.  Consumers that need package ecosystems must provide a
          // separately signed mapping.
          p: product,
          e: "product",
          k: "product",
          a: productAliases(product, framework),
          s: severity,
          r: rule.semver,
          u: rule.status,
          o: rule.raw,
          f: framework,
        };

        // Parse CVSS score
        const cvssScore = parseCvssScore(cvssStr);
        if (cvssScore !== null) {
          entry.c = cvssScore;
        }

        entryMap.set(dedupKey, entry);
      }
    }
  }

  // Convert to array and build indices
  const cves = [];
  for (const entry of [...entryMap.values()].sort((a, b) =>
    `${a.p}\u0000${a.id}\u0000${a.f}`.localeCompare(`${b.p}\u0000${b.id}\u0000${b.f}`),
  )) {
    cves.push(entry);

    const { f: framework, id: cveId } = entry;
    if (!frameworks[framework]) frameworks[framework] = [];
    frameworks[framework].push(cveId);
  }

  console.log(`[aig]   Found ${cves.length} CVEs across ${Object.keys(frameworks).length} frameworks`);

  const productNames = [...new Set(cves.map((entry) => entry.p))].sort((a, b) => a.localeCompare(b));
  return {
    schema: "aig-cve-index/v2",
    version: DATA_SCHEMA_VERSION,
    generated: GENERATED_AT,
    source_commit: SOURCE_COMMIT,
    cves,
    frameworks,
    // Retain the field for backwards-compatible status consumers while
    // making the product-only semantics explicit.
    ecosystems: { product: productNames },
    products: productNames,
  };
}

// ─── 2. Framework Fingerprint Compiler ──────────────────────────────────────

function compileFingerprintIndex() {
  console.log("[aig] Compiling fingerprint index...");

  if (!existsSync(FP_DIR)) {
    console.log("[aig]   Skipping (fingerprints directory not found)");
    return { version: 1, generated: new Date().toISOString().slice(0, 10), fingerprints: [] };
  }

  const files = walkYaml(FP_DIR).sort((a, b) => a.path.localeCompare(b.path));
  const fingerprints = [];

  for (const { path: file } of files) {
    const text = readFileSync(file, "utf-8");
    const data = parseSimpleYaml(text) || {};
    const info = data;
    if (info && info.name) {
      fingerprints.push({
        n: info.name,
        a: info.author || "",
        sev: info.severity || "info",
        desc: (info.desc || "").slice(0, 120),
      });
    }
  }

  console.log(`[aig]   Found ${fingerprints.length} fingerprints`);

  fingerprints.sort((a, b) => `${a.n}\u0000${a.a}`.localeCompare(`${b.n}\u0000${b.a}`));
  return {
    schema: "aig-fingerprint-index/v2",
    version: DATA_SCHEMA_VERSION,
    generated: GENERATED_AT,
    source_commit: SOURCE_COMMIT,
    fingerprints,
  };
}

// ─── 3. MCP Risk Category Compiler ─────────────────────────────────────────

function compileMcpCategories() {
  console.log("[aig] Compiling MCP risk categories...");

  // These are the OWASP MCP risk categories documented in AIG's vuln_review.md
  const categories = [
    {
      id: "mcp-01",
      name: "Token Mismanagement & Secret Exposure",
      description: "Hardcoded keys, env var leaks, and sensitive credential theft from .cursor/mcp.json and similar configs",
      risk: "critical",
      detection_patterns: ["api_key", "secret", "token", "password", ".env", "mcp.json"],
      aidr_policy_action: "deny",
    },
    {
      id: "mcp-02",
      name: "Privilege Escalation via Scope Creep",
      description: "Overly broad tool permission definitions allowing agents to gain unnecessary system control or data access",
      risk: "high",
      detection_patterns: ["full_access", "admin", "wildcard", "root", "sudo"],
      aidr_policy_action: "restrict",
    },
    {
      id: "mcp-03",
      name: "Tool Poisoning",
      description: "Legitimate MCP tools tampered with or injected with malicious logic returning falsified results to manipulate the model",
      risk: "critical",
      detection_patterns: ["override", "inject", "malicious", "backdoor", "trojan"],
      aidr_policy_action: "deny",
    },
    {
      id: "mcp-04",
      name: "Software Supply Chain Attacks",
      description: "Dependency tampering, malicious third-party MCP servers, or backdoors in build scripts",
      risk: "critical",
      detection_patterns: ["postinstall", "preinstall", "download", "curl", "wget", "npm install"],
      aidr_policy_action: "deny",
    },
    {
      id: "mcp-05",
      name: "Command Injection & Execution",
      description: "Agent constructs and executes system commands, shell scripts, or API calls based on untrusted input",
      risk: "critical",
      detection_patterns: ["exec", "spawn", "shell", "eval", "subprocess", "child_process"],
      aidr_policy_action: "deny",
    },
    {
      id: "mcp-06",
      name: "Prompt Injection via Contextual Payloads",
      description: "Malicious instructions injected through context (OCR, web content) hijacking model control flow",
      risk: "high",
      detection_patterns: ["ignore instructions", "system prompt", "you are now", "do not"],
      aidr_policy_action: "monitor",
    },
    {
      id: "mcp-07",
      name: "Insufficient Auth & Authorization",
      description: "MCP servers or tools failing to verify identity, leading to cross-agent or cross-user privilege escalation",
      risk: "high",
      detection_patterns: ["no_auth", "skip_auth", "public", "unauthorized", "bypass"],
      aidr_policy_action: "deny",
    },
    {
      id: "mcp-08",
      name: "Lack of Audit and Telemetry",
      description: "Missing tamper-proof logging of tool calls and context changes, hindering security forensics",
      risk: "medium",
      detection_patterns: ["no_log", "disable_logging", "quiet", "silent"],
      aidr_policy_action: "monitor",
    },
    {
      id: "mcp-09",
      name: "Shadow MCP Servers",
      description: "Unauthorized MCP instances deployed with default configurations, lacking security compliance",
      risk: "high",
      detection_patterns: ["default_config", "unsecured", "shadow", "unauthorized"],
      aidr_policy_action: "deny",
    },
    {
      id: "mcp-10",
      name: "Context Injection & Over-Sharing",
      description: "Sensitive context shared across sessions or agents, leading to information disclosure or logic interference",
      risk: "high",
      detection_patterns: ["shared_context", "global_state", "cross_session", "broadcast"],
      aidr_policy_action: "restrict",
    },
    {
      id: "mcp-11",
      name: "Name Confusion Attack",
      description: "Malicious tools registered with names similar to legitimate tools to trick agents into calling the wrong one",
      risk: "high",
      detection_patterns: ["typosquat", "lookalike", "similar_name", "confusion"],
      aidr_policy_action: "deny",
    },
    {
      id: "mcp-12",
      name: "Rug Pull Attack",
      description: "Malicious MCP service that suddenly terminates or changes behavior after gaining trust, causing DoS or data loss",
      risk: "high",
      detection_patterns: ["rate_limit", "kill", "shutdown", "terminate", "revoke"],
      aidr_policy_action: "deny",
    },
    {
      id: "mcp-13",
      name: "Tool Shadowing Attack",
      description: "Overriding legitimate tool behavior by redefining tools with the same name",
      risk: "high",
      detection_patterns: ["override", "redefine", "shadow", "duplicate"],
      aidr_policy_action: "deny",
    },
    {
      id: "mcp-14",
      name: "CORS Misconfiguration",
      description: "Misconfigured Cross-Origin Resource Sharing policies that could allow unauthorized cross-domain access to MCP servers",
      risk: "medium",
      detection_patterns: ["Access-Control-Allow-Origin: *", "credentials: true", "wildcard_origin"],
      aidr_policy_action: "restrict",
    },
  ];

  console.log(`[aig]   Compiled ${categories.length} MCP risk categories`);

  return {
    schema: "aig-mcp-categories/v2",
    version: DATA_SCHEMA_VERSION,
    generated: GENERATED_AT,
    source_commit: SOURCE_COMMIT,
    categories,
  };
}

// ─── Main ────────────────────────────────────────────────────────────────────

function main() {
  const start = Date.now();

  // Ensure output directory exists
  if (!existsSync(OUT)) {
    mkdirSync(OUT, { recursive: true });
  }

  // Compile all three indexes
  const cveIndex = compileCveIndex();
  const fingerprintIndex = compileFingerprintIndex();
  const mcpCategories = compileMcpCategories();

  // Write output files. JSON serialization order is intentional and stable;
  // the manifest hashes these exact bytes for promotion/rollback checks.
  const artifacts = {
    "aig-cve-index.json": JSON.stringify(cveIndex),
    "aig-fingerprints.json": JSON.stringify(fingerprintIndex),
    "aig-mcp-categories.json": JSON.stringify(mcpCategories),
  };
  for (const [name, contents] of Object.entries(artifacts)) {
    writeFileSync(join(OUT, name), contents);
  }
  const manifest = buildManifest(artifacts);
  writeFileSync(join(OUT, AIG_MANIFEST_FILE), JSON.stringify(manifest));

  const elapsed = Date.now() - start;

  console.log(`\n[aig] Done in ${elapsed}ms`);
  console.log(`[aig]   aig-cve-index.json       ${(Buffer.byteLength(JSON.stringify(cveIndex)) / 1024).toFixed(1)} KB (${cveIndex.cves.length} CVEs)`);
  console.log(`[aig]   aig-fingerprints.json     ${(Buffer.byteLength(JSON.stringify(fingerprintIndex)) / 1024).toFixed(1)} KB (${fingerprintIndex.fingerprints.length} fingerprints)`);
  console.log(`[aig]   aig-mcp-categories.json   ${(Buffer.byteLength(JSON.stringify(mcpCategories)) / 1024).toFixed(1)} KB (${mcpCategories.categories.length} categories)`);
  console.log(`[aig]   ${AIG_MANIFEST_FILE}       bundle=${manifest.bundle_id} signed=${Boolean(manifest.signature)}`);
}

main();
