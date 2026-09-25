/**
 * Secure-code guardrails (threats/secure-code.yaml + SCG-SECRET-001): every
 * rule with a benign twin, language gating, diff-only inspection across the
 * Write/Edit/MultiEdit/apply_patch/NotebookEdit/heredoc shapes, the warn/ask
 * folding into verdicts, audit counting, and bounded matching time.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { loadTrustedModelSources, type TrustedModelSources } from "../ai-supply-chain.js";
import {
	applySecureCodeWarnings,
	CodeRuleSet,
	codeBlocksForToolCall,
	codeLanguageForPath,
	describeSecureCodeWarnings,
	inspectToolCallCode,
	matchCodeBlock,
	SECURE_CODE_WARNING_CATEGORY,
} from "../code-guard.js";
import { allowVerdict, evaluateToolCall } from "../evaluator.js";
import { extractFromToolCall } from "../extractors.js";
import { loadThreats } from "../threat-loader.js";
import type { Threat, Verdict, VerdictWarning } from "../types.js";
import { makeTmpDir } from "./test-utils.js";

const THREATS_DIR = resolve(__dirname, "..", "..", "..", "..", "threats");
const ALLOWLISTS_DIR = resolve(__dirname, "..", "..", "..", "..", "allowlists");
/** A GitHub-token-shaped value, assembled so the source file carries no credential literal. */
const FAKE_GITHUB_TOKEN = `ghp_${"A1b2C3d4".repeat(4)}E5f6`;

let threats: Threat[];
let rules: CodeRuleSet;
let sources: TrustedModelSources;

beforeAll(async () => {
	threats = await loadThreats(THREATS_DIR);
	rules = new CodeRuleSet(threats);
	sources = await loadTrustedModelSources(ALLOWLISTS_DIR);
});

/** Secure-code rule ids reported for `text` in a file of `language`. */
function hits(language: string, text: string): string[] {
	const found = matchCodeBlock({ filePath: "f", language, text }, rules, {
		allMatches: true,
		includeSecrets: true,
	})
		.filter((item) => item.ruleId.startsWith("SCG-"))
		.map((item) => item.ruleId);
	return [...new Set(found)].sort();
}

const CASES: ReadonlyArray<{
	rule: string;
	language: string;
	bad: string[];
	good: string[];
}> = [
	{
		rule: "SCG-TLS-001",
		language: "python",
		bad: [
			"r = requests.get(url, verify=False)",
			"ctx = ssl._create_unverified_context()",
			"ctx.check_hostname = False",
		],
		good: ["r = requests.get(url, verify=True)", 'r = requests.get(url, verify="/etc/ssl/ca.pem")'],
	},
	{
		rule: "SCG-TLS-002",
		language: "javascript",
		bad: ["https.request({ host, rejectUnauthorized: false })"],
		good: ["https.request({ host, rejectUnauthorized: true, ca })"],
	},
	{
		rule: "SCG-TLS-003",
		language: "dockerfile",
		bad: ["ENV NODE_TLS_REJECT_UNAUTHORIZED=0"],
		good: ["ENV NODE_TLS_REJECT_UNAUTHORIZED=1"],
	},
	{
		rule: "SCG-TLS-003",
		language: "typescript",
		bad: ['process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";'],
		good: ['process.env.NODE_EXTRA_CA_CERTS = "/etc/ssl/corp.pem";'],
	},
	{
		rule: "SCG-TLS-003",
		language: "python",
		bad: ['os.environ["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"'],
		good: ['os.environ["REQUESTS_CA_BUNDLE"] = "/etc/ssl/corp.pem"'],
	},
	{
		rule: "SCG-TLS-004",
		language: "go",
		bad: ["cfg := &tls.Config{InsecureSkipVerify: true}"],
		good: ["cfg := &tls.Config{InsecureSkipVerify: false, RootCAs: pool}"],
	},
	{
		rule: "SCG-TLS-005",
		language: "shell",
		bad: [
			"curl -fsSLk https://internal.example/setup.sh -o setup.sh",
			"curl --insecure https://internal.example/x",
			"wget --no-check-certificate https://internal.example/x",
			"git config --global http.sslVerify false",
		],
		good: [
			"curl -fsSL https://internal.example/setup.sh -o setup.sh",
			"curl -K curl.cfg https://internal.example/x",
			"curl --cacert corp.pem https://internal.example/x",
		],
	},
	{
		rule: "SCG-TLS-006",
		language: "java",
		bad: [
			"client = HttpClients.custom().setSSLHostnameVerifier(new NoopHostnameVerifier()).build();",
		],
		good: [
			"client = HttpClients.custom().setSSLHostnameVerifier(new DefaultHostnameVerifier()).build();",
		],
	},
	{
		rule: "SCG-EVAL-001",
		language: "python",
		bad: ['result = eval(request.args.get("expr"))', "exec(input())"],
		good: ['result = ast.literal_eval(request.args.get("expr"))', "model.eval()", 'eval("1 + 2")'],
	},
	{
		rule: "SCG-EVAL-002",
		language: "javascript",
		bad: ["const out = eval(req.query.code);", "const fn = new Function(req.body.src);"],
		good: ["const data = JSON.parse(req.body);", 'const four = eval("2 + 2");'],
	},
	{
		rule: "SCG-SQLI-001",
		language: "python",
		bad: [
			'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
			"cursor.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)",
			'cursor.execute("SELECT * FROM t WHERE id = " + uid)',
			'q = f"SELECT * FROM users WHERE name = \'{request.args["name"]}\'"',
		],
		good: [
			'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
			'cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})',
		],
	},
	{
		rule: "SCG-SQLI-002",
		language: "typescript",
		bad: [
			"const rows = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
			'const rows = await db.query("SELECT * FROM users WHERE id = " + id);',
		],
		good: [
			'const rows = await db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);',
			"const rows = await db.query(sql`SELECT * FROM users WHERE id = ${id}`);",
		],
	},
	{
		rule: "SCG-SQLI-003",
		language: "go",
		bad: ['rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))'],
		good: ['rows, err := db.Query("SELECT * FROM users WHERE id = ?", id)'],
	},
	{
		rule: "SCG-SQLI-004",
		language: "java",
		bad: ['ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + id);'],
		good: ['PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");'],
	},
	{
		rule: "SCG-SQLI-005",
		language: "php",
		bad: ['$r = mysqli_query($db, "SELECT * FROM users WHERE id = " . $_GET["id"]);'],
		good: ['$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");'],
	},
	{
		rule: "SCG-CMDI-001",
		language: "python",
		bad: [
			'subprocess.run(f"convert {name} out.png", shell=True)',
			'os.system("ping -c 1 " + host)',
		],
		good: [
			'subprocess.run(["convert", name, "out.png"])',
			'subprocess.run("ls -la", shell=True)',
			'os.system("clear")',
		],
	},
	{
		rule: "SCG-CMDI-002",
		language: "javascript",
		bad: ["exec(`convert ${req.query.file} out.png`);"],
		good: ['execFile("convert", [file, "out.png"]);'],
	},
	{
		rule: "SCG-PERM-001",
		language: "shell",
		bad: ["chmod 777 /srv/app", "chmod -R 777 uploads", "chmod a+rwx shared"],
		good: ["chmod 755 /srv/app", "chmod +x build.sh"],
	},
	{
		rule: "SCG-PERM-002",
		language: "python",
		bad: ["os.chmod(path, 0o777)", "os.makedirs(cache, mode=0o777)"],
		good: ["os.chmod(path, 0o600)", "os.makedirs(cache, exist_ok=True)"],
	},
	{
		rule: "SCG-PERM-002",
		language: "go",
		bad: ["err := os.MkdirAll(dir, 0777)"],
		good: ["err := os.MkdirAll(dir, 0750)"],
	},
	{
		rule: "SCG-CORS-001",
		language: "python",
		bad: [
			'app.add_middleware(\n    CORSMiddleware,\n    allow_origins=["*"],\n    allow_credentials=True,\n)',
			"CORS(app, supports_credentials=True)",
			'CORS(app, origins="*", supports_credentials=True)',
		],
		good: [
			'app.add_middleware(\n    CORSMiddleware,\n    allow_origins=["https://app.example.com"],\n    allow_credentials=True,\n)',
			'CORS(app, origins=["https://app.example.com"], supports_credentials=True)',
			'app.add_middleware(CORSMiddleware, allow_origins=["*"])',
		],
	},
	{
		rule: "SCG-CORS-002",
		language: "javascript",
		bad: [
			'app.use(cors({ origin: "*", credentials: true }));',
			"app.use(cors({ credentials: true, origin: true }));",
		],
		good: ['app.use(cors({ origin: ["https://app.example.com"], credentials: true }));'],
	},
	{
		rule: "SCG-CORS-003",
		language: "javascript",
		bad: [
			'res.setHeader("Access-Control-Allow-Origin", "*");\nres.setHeader("Access-Control-Allow-Credentials", "true");',
		],
		good: ['res.setHeader("Access-Control-Allow-Origin", "*");'],
	},
	{
		rule: "SCG-DEBUG-001",
		language: "python",
		bad: ['app.run(host="0.0.0.0", port=5000, debug=True)'],
		good: ['app.run(host="127.0.0.1", debug=True)', 'app.run(host="0.0.0.0", debug=False)'],
	},
	{
		rule: "SCG-DEBUG-002",
		language: "json",
		bad: ['"dev": "node --inspect=0.0.0.0:9229 server.js"'],
		good: ['"dev": "node --inspect=127.0.0.1:9229 server.js"'],
	},
	{
		rule: "SCG-DEBUG-002",
		language: "shell",
		bad: ["flask run --host=0.0.0.0 --debug"],
		good: ["flask run --host=127.0.0.1 --debug"],
	},
	{
		rule: "SCG-CSRF-001",
		language: "python",
		bad: ["@csrf_exempt\ndef webhook(request):", 'app.config["WTF_CSRF_ENABLED"] = False'],
		good: ["@csrf_protect\ndef webhook(request):"],
	},
	{
		rule: "SCG-CSRF-001",
		language: "java",
		bad: ["http.csrf().disable();", "http.csrf(csrf -> csrf.disable());"],
		good: ["http.csrf(Customizer.withDefaults());"],
	},
	{
		rule: "SCG-CSRF-001",
		language: "ruby",
		bad: ["skip_before_action :verify_authenticity_token"],
		good: ["protect_from_forgery with: :exception"],
	},
	{
		rule: "SCG-CRYPTO-001",
		language: "python",
		bad: ["digest = hashlib.md5(password.encode()).hexdigest()"],
		good: [
			"digest = hashlib.md5(file_bytes).hexdigest()",
			"hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
		],
	},
	{
		rule: "SCG-CRYPTO-002",
		language: "python",
		bad: ["cipher = AES.new(key, AES.MODE_ECB)"],
		good: ["cipher = AES.new(key, AES.MODE_GCM)"],
	},
	{
		rule: "SCG-CRYPTO-002",
		language: "java",
		bad: [
			'Cipher c = Cipher.getInstance("AES");',
			'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");',
		],
		good: ['Cipher c = Cipher.getInstance("AES/GCM/NoPadding");'],
	},
	{
		rule: "SCG-CRYPTO-002",
		language: "javascript",
		bad: ['const c = crypto.createCipheriv("aes-128-ecb", key, null);'],
		good: ['const c = crypto.createCipheriv("aes-256-gcm", key, iv);'],
	},
	{
		rule: "SCG-CRYPTO-003",
		language: "javascript",
		bad: ["const token = Math.random().toString(36).slice(2);"],
		good: [
			'const token = crypto.randomBytes(32).toString("hex");',
			"const jitter = Math.random() * 100;",
		],
	},
	{
		rule: "SCG-CRYPTO-004",
		language: "python",
		bad: ['reset_token = "".join(random.choice(alphabet) for _ in range(32))'],
		good: ["reset_token = secrets.token_urlsafe(32)", "delay = random.random()"],
	},
	{
		rule: "SCG-SECRET-001",
		language: "python",
		bad: [`GITHUB_TOKEN = "${FAKE_GITHUB_TOKEN}"`],
		good: ['GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]'],
	},
];

describe("secure-code rules and their benign twins", () => {
	for (const { rule, language, bad, good } of CASES) {
		it(`${rule} (${language}) flags the insecure form`, () => {
			for (const text of bad) expect(hits(language, text), text).toContain(rule);
		});
		it(`${rule} (${language}) leaves the secure twin alone`, () => {
			for (const text of good) expect(hits(language, text), text).not.toContain(rule);
		});
	}

	it("every shipped secure-code rule is covered by a case above", () => {
		const shipped = threats
			.filter((threat) => threat.id.startsWith("SCG-"))
			.map((threat) => threat.id);
		const covered = new Set(CASES.map((entry) => entry.rule));
		expect(shipped.filter((id) => !covered.has(id))).toEqual([]);
	});
});

describe("language gating", () => {
	it("maps file names to languages", () => {
		expect(codeLanguageForPath("src/app.py")).toBe("python");
		expect(codeLanguageForPath("src/app.tsx")).toBe("typescript");
		expect(codeLanguageForPath("deploy/Dockerfile")).toBe("dockerfile");
		expect(codeLanguageForPath("Dockerfile.prod")).toBe("dockerfile");
		expect(codeLanguageForPath(".env.production")).toBe("dotenv");
		expect(codeLanguageForPath("C:\\work\\Makefile")).toBe("makefile");
		expect(codeLanguageForPath("README.md")).toBeNull();
		expect(codeLanguageForPath("notes.txt")).toBeNull();
	});

	it("does not apply a rule to a language it is not written for", () => {
		expect(hits("javascript", "requests.get(url, verify=False)")).toEqual([]);
		expect(hits("python", "https.request({ rejectUnauthorized: false })")).toEqual([]);
	});

	it("keeps credentials in .env files out of the hard-coded credential rule", () => {
		expect(hits("dotenv", `GITHUB_TOKEN=${FAKE_GITHUB_TOKEN}`)).toEqual([]);
	});
});

/** Warnings the runtime leg reports for a (normalized) tool call. */
function warningsFor(toolName: string, toolInput: Record<string, unknown>): VerdictWarning[] {
	return inspectToolCallCode(toolName, toolInput, rules, sources, { enabled: true, action: "warn" })
		.warnings;
}

describe("only added code is inspected", () => {
	it("Write inspects the whole file and reports the file line", () => {
		const warnings = warningsFor("Write", {
			file_path: "/w/client.py",
			content: "import requests\n\nr = requests.get(url, verify=False)\n",
		});
		expect(warnings).toEqual([
			expect.objectContaining({ ruleId: "SCG-TLS-001", filePath: "/w/client.py", line: 3 }),
		]);
		expect(warningsFor("Write", { file_path: "/w/README.md", content: "verify=False" })).toEqual(
			[],
		);
	});

	it("Edit reports only lines new_string adds", () => {
		const existing = "r = requests.get(url, verify=False)";
		expect(
			warningsFor("Edit", {
				file_path: "/w/client.py",
				old_string: `# fetch\n${existing}`,
				new_string: `# fetch the index\n${existing}`,
			}),
		).toEqual([]);
		expect(
			warningsFor("Edit", {
				file_path: "/w/client.py",
				old_string: "r = requests.get(url)",
				new_string: existing,
			}).map((warning) => warning.ruleId),
		).toEqual(["SCG-TLS-001"]);
	});

	it("MultiEdit inspects each edit's added lines", () => {
		const warnings = warningsFor("MultiEdit", {
			file_path: "/w/app.js",
			edits: [
				{ old_string: "const a = 1;", new_string: "const a = 2;" },
				{ old_string: "agent()", new_string: "agent({ rejectUnauthorized: false })" },
			],
		});
		expect(warnings.map((warning) => warning.ruleId)).toEqual(["SCG-TLS-002"]);
	});

	it("apply_patch (unified diff) reports added lines with their new-file line", () => {
		const patch = [
			"--- a/client.py",
			"+++ b/client.py",
			"@@ -1,3 +1,3 @@",
			" import requests",
			"-r = requests.get(url, verify=True)",
			"+r = requests.get(url, verify=False)",
			" print(r)",
		].join("\n");
		expect(warningsFor("Edit", { patch })).toEqual([
			expect.objectContaining({ ruleId: "SCG-TLS-001", filePath: "client.py", line: 2 }),
		]);
		// Removing the insecure line is not a finding.
		const removal = patch.replace(
			"-r = requests.get(url, verify=True)",
			"-r = requests.get(url, verify=False)",
		);
		expect(
			warningsFor("Edit", {
				patch: removal.replace("+r = requests.get(url, verify=False)", "+r = requests.get(url)"),
			}),
		).toEqual([]);
	});

	it("apply_patch (Codex format) inspects Add File bodies and Update hunks", () => {
		const patch = [
			"*** Begin Patch",
			"*** Add File: scripts/fetch.sh",
			"+#!/bin/sh",
			"+curl -k https://internal.example/data -o data.json",
			"*** Update File: src/server.py",
			"@@ def main():",
			"-    app.run()",
			'+    app.run(host="0.0.0.0", debug=True)',
			"*** End Patch",
		].join("\n");
		const warnings = warningsFor("Edit", { patch });
		expect(warnings).toEqual([
			expect.objectContaining({ ruleId: "SCG-TLS-005", filePath: "scripts/fetch.sh", line: 2 }),
			expect.objectContaining({ ruleId: "SCG-DEBUG-001", filePath: "src/server.py" }),
		]);
		expect(warnings[1]?.line).toBeUndefined();
	});

	it("NotebookEdit and notebook Writes inspect code cells only", () => {
		expect(
			warningsFor("NotebookEdit", {
				notebook_path: "/w/nb.ipynb",
				new_source: "r = requests.get(url, verify=False)",
			}).map((warning) => warning.ruleId),
		).toEqual(["SCG-TLS-001"]);
		const notebook = JSON.stringify({
			cells: [
				{ cell_type: "markdown", source: ["Never use `verify=False`"] },
				{
					cell_type: "code",
					source: ["import requests\n", "r = requests.get(url, verify=False)\n"],
				},
			],
		});
		const warnings = warningsFor("Write", { file_path: "/w/nb.ipynb", content: notebook });
		expect(warnings.map((warning) => warning.ruleId)).toEqual(["SCG-TLS-001"]);
	});

	it("heredoc writes through Bash are inspected by their target file", () => {
		const command = "cat > app.py <<'EOF'\nimport requests\nrequests.get(url, verify=False)\nEOF";
		expect(warningsFor("Bash", { command })).toEqual([
			expect.objectContaining({ ruleId: "SCG-TLS-001", filePath: "app.py", line: 2 }),
		]);
		// A heredoc that is only a commit message is not code.
		expect(
			codeBlocksForToolCall("Bash", {
				command: "git commit -m \"$(cat <<'EOF'\nverify=False removed\nEOF\n)\"",
			}),
		).toEqual([]);
	});

	it("never copies a credential into a warning", () => {
		const warnings = warningsFor("Write", {
			file_path: "/w/settings.py",
			content: `GITHUB_TOKEN = "${FAKE_GITHUB_TOKEN}"\n`,
		});
		expect(warnings.map((warning) => warning.ruleId)).toEqual(["SCG-SECRET-001"]);
		expect(JSON.stringify(warnings)).not.toContain(FAKE_GITHUB_TOKEN);
		expect(JSON.stringify(describeSecureCodeWarnings(warnings))).not.toContain(FAKE_GITHUB_TOKEN);
	});

	it("disabled secure-code produces no warnings (supply-chain rules still apply)", () => {
		const result = inspectToolCallCode(
			"Write",
			{ file_path: "/w/a.py", content: 'requests.get(u, verify=False)\ntorch.load("m.pt")' },
			rules,
			sources,
			{ enabled: false, action: "warn" },
		);
		expect(result.warnings).toEqual([]);
		expect(result.heuristicMatches.map((match) => match.threat.id)).toEqual(["AISC-001"]);
	});
});

describe("folding warnings into a verdict", () => {
	const warning: VerdictWarning = {
		source: "secure_code",
		ruleId: "SCG-TLS-001",
		title: "TLS certificate verification disabled",
		category: "secure_code_tls",
		severity: "high",
		filePath: "/w/a.py",
		language: "python",
		line: 3,
	};

	it("warn keeps the call allowed and marks it for the audit log", () => {
		const verdict = applySecureCodeWarnings(allowVerdict(), [warning], {
			enabled: true,
			action: "warn",
		});
		expect(verdict.decision).toBe("allow");
		expect(verdict.category).toBe(SECURE_CODE_WARNING_CATEGORY);
		expect(verdict.warnings).toEqual([warning]);
	});

	it("ask holds the call for review", () => {
		const verdict = applySecureCodeWarnings(allowVerdict(), [warning], {
			enabled: true,
			action: "ask",
		});
		expect(verdict).toMatchObject({
			decision: "ask",
			category: "secure_code",
			matchedThreatId: "SCG-TLS-001",
			artifacts: ["/w/a.py"],
		});
	});

	it("never turns a DLP-redacted allow into an ask that would run the original input", () => {
		const redacted: Verdict = {
			...allowVerdict("dlp"),
			transformedInput: { content: "[REDACTED]" },
		};
		const verdict = applySecureCodeWarnings(redacted, [warning], { enabled: true, action: "ask" });
		expect(verdict.decision).toBe("allow");
		expect(verdict.transformedInput).toEqual({ content: "[REDACTED]" });
		expect(verdict.warnings).toEqual([warning]);
	});

	it("keeps a deny a deny", () => {
		const deny: Verdict = { ...allowVerdict(), decision: "deny", category: "tool" };
		const verdict = applySecureCodeWarnings(deny, [warning], { enabled: true, action: "ask" });
		expect(verdict.decision).toBe("deny");
		expect(verdict.warnings).toHaveLength(1);
	});

	it("describes warnings for the user and the model", () => {
		const text = describeSecureCodeWarnings([warning, { ...warning, line: 9 }]);
		expect(text.userMessage).toContain("2 issues");
		expect(text.userMessage).toContain("/w/a.py:3");
		expect(text.userMessage).toContain("The change was allowed.");
		expect(describeSecureCodeWarnings([warning], false).userMessage).not.toContain("allowed");
		expect(text.modelContext).toContain("Fix these");
	});
});

describe("runtime verdicts and audit", () => {
	afterEach(() => {
		vi.unstubAllEnvs();
	});

	async function setup(extra: Record<string, unknown> = {}) {
		// State files (the audit log included) are confined to ~/.singularity-aidr,
		// so each test gets its own home.
		const dir = await makeTmpDir();
		vi.stubEnv("HOME", dir);
		const configPath = join(dir, "config.json");
		const auditPath = join(dir, ".singularity-aidr", "audit.jsonl");
		await writeFile(
			configPath,
			JSON.stringify({
				mode: "local",
				control_plane: { enabled: false },
				url_check: { enabled: false },
				package_check: { enabled: false },
				cache: { enabled: false },
				logging: { enabled: true },
				...extra,
			}),
		);
		const userThreatsDir = join(dir, "user-threats");
		await mkdir(userThreatsDir, { recursive: true });
		const evaluate = (toolName: string, toolInput: Record<string, unknown>) =>
			evaluateToolCall(
				{
					sessionId: "secure-code",
					toolName,
					toolInput,
					artifacts: extractFromToolCall(toolName, toolInput),
				},
				{ threatsDir: THREATS_DIR, allowlistsDir: ALLOWLISTS_DIR, configPath, userThreatsDir },
			);
		return { evaluate, auditPath };
	}

	const insecureWrite = {
		file_path: "/work/client.py",
		content: "import requests\nr = requests.get(url, verify=False)\n",
	};

	it("warns by default, allows the write, and counts it in the audit log", async () => {
		const { evaluate, auditPath } = await setup();
		const verdict = await evaluate("Write", insecureWrite);
		expect(verdict.decision).toBe("allow");
		expect(verdict.category).toBe(SECURE_CODE_WARNING_CATEGORY);
		expect(verdict.warnings?.map((warning) => warning.ruleId)).toEqual(["SCG-TLS-001"]);

		// Incident correlation shares the file; only the verdict entry matters here.
		const entries = (await readFile(auditPath, "utf8"))
			.trim()
			.split("\n")
			.map((line) => JSON.parse(line) as Record<string, unknown>)
			.filter((entry) => entry.type === "runtime_verdict");
		expect(entries).toHaveLength(1);
		expect(entries[0]).toMatchObject({
			verdict: "allow",
			category: SECURE_CODE_WARNING_CATEGORY,
			secure_code: { findings: 1, rule_ids: ["SCG-TLS-001"] },
		});
	});

	it("holds the write for review with secure_code.action = ask", async () => {
		const { evaluate } = await setup({ secure_code: { action: "ask" } });
		const verdict = await evaluate("Write", insecureWrite);
		expect(verdict.decision).toBe("ask");
		expect(verdict.source).toBe("secure_code");
	});

	it("is silent when disabled, or when the rule is disabled", async () => {
		const off = await setup({ secure_code: { enabled: false } });
		expect((await off.evaluate("Write", insecureWrite)).warnings).toBeUndefined();
		const ruleOff = await setup({ disabled_threats: ["SCG-TLS-001"] });
		const verdict = await ruleOff.evaluate("Write", insecureWrite);
		expect(verdict.decision).toBe("allow");
		expect(verdict.warnings).toBeUndefined();
	});

	it("leaves the secure twin with a plain allow", async () => {
		const { evaluate } = await setup();
		const verdict = await evaluate("Write", {
			file_path: "/work/client.py",
			content: "import requests\nr = requests.get(url, verify=True)\n",
		});
		expect(verdict.decision).toBe("allow");
		expect(verdict.category).toBe("none");
		expect(verdict.warnings).toBeUndefined();
	});
});

describe("bounded matching time", () => {
	it("every code rule stays fast on adversarial 64 KiB inputs", () => {
		const fillers = [
			"a".repeat(64 * 1024),
			"torch.load(".repeat(6000),
			"(((((((((((".repeat(6000),
			'execute("'.repeat(7000),
			"token = x ".repeat(6500),
			'from_pretrained("a/b", '.repeat(3000),
		];
		const languages = [...new Set(threats.flatMap((threat) => [...threat.matchOn]))]
			.filter((value) => value.startsWith("code:"))
			.map((value) => value.slice("code:".length));
		for (const filler of fillers) {
			for (const language of languages) {
				const started = performance.now();
				matchCodeBlock({ filePath: "f", language, text: filler }, rules, { allMatches: true });
				const elapsed = performance.now() - started;
				expect(elapsed, `${language} on ${filler.slice(0, 12)}`).toBeLessThan(3000);
			}
		}
	});
});
