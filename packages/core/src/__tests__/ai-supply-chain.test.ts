/**
 * AI model supply-chain rules (threats/ai-supply-chain.yaml): unsafe model
 * loading and unvetted model sources, each with a benign twin, plus the
 * trusted-source suppression and the runtime verdicts they produce.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
	isTrustedModelSourceMatch,
	loadTrustedModelSources,
	modelRepoOrgs,
	type TrustedModelSources,
} from "../ai-supply-chain.js";
import {
	CodeRuleSet,
	codeBlocksForToolCall,
	isReportableFinding,
	matchCodeBlock,
} from "../code-guard.js";
import { evaluateToolCall } from "../evaluator.js";
import { extractFromToolCall } from "../extractors.js";
import { HeuristicsEngine } from "../heuristics.js";
import { loadThreats } from "../threat-loader.js";
import type { Threat } from "../types.js";
import { makeTmpDir } from "./test-utils.js";

const THREATS_DIR = resolve(__dirname, "..", "..", "..", "..", "threats");
const ALLOWLISTS_DIR = resolve(__dirname, "..", "..", "..", "..", "allowlists");

let threats: Threat[];
let rules: CodeRuleSet;
let sources: TrustedModelSources;
let engine: HeuristicsEngine;

beforeAll(async () => {
	threats = await loadThreats(THREATS_DIR);
	rules = new CodeRuleSet(threats);
	sources = await loadTrustedModelSources(ALLOWLISTS_DIR);
	engine = new HeuristicsEngine(threats, [], sources);
});

/** AISC rule ids reported for `text` as code in `language`. */
function codeHits(text: string, language = "python", trusted = sources): string[] {
	const found = matchCodeBlock({ filePath: "x", language, text }, rules, { allMatches: true })
		.filter((item) => item.ruleId.startsWith("AISC-") && isReportableFinding(item, trusted))
		.map((item) => item.ruleId);
	return [...new Set(found)].sort();
}

/** AISC rule ids the runtime engine reports for a Bash command. */
function commandHits(command: string): string[] {
	const found = engine
		.match(extractFromToolCall("Bash", { command }))
		.map((match) => match.threat.id)
		.filter((id) => id.startsWith("AISC-"));
	return [...new Set(found)].sort();
}

describe("unsafe model deserialization", () => {
	it("AISC-001 flags torch.load without weights_only=True", () => {
		expect(codeHits('model = torch.load("model.pt")')).toEqual(["AISC-001"]);
		expect(codeHits('sd = torch.load(path, map_location="cpu")')).toEqual(["AISC-001"]);
		expect(codeHits("sd = torch.load(path, weights_only=False)")).toEqual(["AISC-001"]);
		// A safe call later in the file does not excuse an unsafe one before it.
		expect(codeHits("a = torch.load(p1)\nb = torch.load(p2, weights_only=True)")).toEqual([
			"AISC-001",
		]);
	});

	it("AISC-001 benign twins: weights_only=True (also multi-line) and safetensors", () => {
		expect(codeHits("sd = torch.load(path, weights_only=True)")).toEqual([]);
		expect(
			codeHits(
				'sd = torch.load(\n    os.path.join(root, "m.pt"),\n    map_location="cpu",\n    weights_only=True,\n)',
			),
		).toEqual([]);
		expect(
			codeHits('from safetensors.torch import load_file\nsd = load_file("m.safetensors")'),
		).toEqual([]);
	});

	it("AISC-001 is not applied to documentation or to a grep command", () => {
		expect(
			codeBlocksForToolCall("Write", { file_path: "README.md", content: "torch.load(p)" }),
		).toEqual([]);
		expect(commandHits('grep -rn "torch.load(" src/')).toEqual([]);
	});

	it("AISC-001 inspects Python that a Bash command runs", () => {
		const blocks = codeBlocksForToolCall("Bash", {
			command: `python3 -c "import torch; torch.load('m.pt')"`,
		});
		expect(blocks).toHaveLength(1);
		expect(blocks[0]?.language).toBe("python");
		const heredoc = codeBlocksForToolCall("Bash", {
			command: "python - <<'EOF'\nimport torch\nsd = torch.load('m.pt')\nEOF",
		});
		expect(heredoc.map((block) => block.text)).toEqual(["import torch\nsd = torch.load('m.pt')"]);
	});

	it("AISC-002 flags pickle-family loaders on downloaded or remote files", () => {
		expect(
			codeHits('obj = pickle.load(open(hf_hub_download("acme/model", "model.pkl"), "rb"))'),
		).toEqual(["AISC-002", "AISC-012"]);
		expect(codeHits("clf = joblib.load(urlretrieve(url)[0])")).toEqual(["AISC-002"]);
		expect(codeHits("obj = pickle.loads(resp.content)")).toEqual(["AISC-002"]);
		expect(codeHits("df = pd.read_pickle(downloaded_path)")).toEqual(["AISC-002"]);
		expect(codeHits('obj = dill.load(open("downloads/model.pkl", "rb"))')).toEqual(["AISC-002"]);
	});

	it("AISC-002 benign twins: local artifacts and data-only formats", () => {
		expect(codeHits('clf = joblib.load("model.joblib")')).toEqual([]);
		expect(codeHits("cfg = json.load(open(download_path))")).toEqual([]);
	});

	it("AISC-003 flags unpickling straight from a network response", () => {
		expect(codeHits("obj = pickle.loads(requests.get(url).content)")).toEqual(["AISC-003"]);
		expect(codeHits("sd = torch.load(io.BytesIO(urlopen(url).read()))")).toContain("AISC-003");
		// A URL literal is both "remote" (AISC-002) and a direct network read (AISC-003).
		expect(codeHits('df = pd.read_pickle("https://example.com/data.pkl")')).toEqual([
			"AISC-002",
			"AISC-003",
		]);
	});

	it("AISC-003 benign twins: weights_only=True and JSON from the network", () => {
		expect(
			codeHits("sd = torch.load(io.BytesIO(requests.get(url).content), weights_only=True)"),
		).toEqual([]);
		expect(codeHits("data = json.loads(requests.get(url).content)")).toEqual([]);
	});

	it("AISC-004 flags a command that downloads and unpickles in one step", () => {
		expect(
			commandHits(
				`curl -sL https://files.example/m.pkl -o m.pkl && python -c "import pickle; pickle.load(open('m.pkl','rb'))"`,
			),
		).toContain("AISC-004");
		expect(
			commandHits(
				`wget https://files.example/model.pt; python3 -c "import torch; torch.load('model.pt')"`,
			),
		).toContain("AISC-004");
	});

	it("AISC-004 benign twin: weights_only=True after the download", () => {
		expect(
			commandHits(
				`wget https://files.example/model.pt && python3 -c "import torch; torch.load('model.pt', weights_only=True)"`,
			),
		).not.toContain("AISC-004");
	});

	it("AISC-009 flags Keras safe_mode=False and unsafe deserialization", () => {
		expect(codeHits('m = keras.models.load_model("m.keras", safe_mode=False)')).toEqual([
			"AISC-009",
		]);
		expect(codeHits("keras.config.enable_unsafe_deserialization()")).toEqual(["AISC-009"]);
		expect(codeHits('m = keras.models.load_model("m.keras")')).toEqual([]);
	});

	it("AISC-010 flags numpy allow_pickle=True", () => {
		expect(codeHits('a = np.load("x.npy", allow_pickle=True)')).toEqual(["AISC-010"]);
		expect(codeHits('a = np.load("x.npy")')).toEqual([]);
		expect(codeHits('a = numpy.load("x.npy", allow_pickle=False)')).toEqual([]);
	});

	it("AISC-011 flags unsafe YAML loaders but not safe ones", () => {
		expect(codeHits("cfg = yaml.load(f, Loader=yaml.Loader)")).toEqual(["AISC-011"]);
		expect(codeHits("cfg = yaml.unsafe_load(f)")).toEqual(["AISC-011"]);
		expect(codeHits("cfg = yaml.load(f, yaml.UnsafeLoader)")).toEqual(["AISC-011"]);
		expect(codeHits("cfg = yaml.safe_load(f)")).toEqual([]);
		expect(codeHits("cfg = yaml.load(f, Loader=yaml.SafeLoader)")).toEqual([]);
		expect(codeHits("cfg = yaml.load(f, Loader=yaml.CSafeLoader)")).toEqual([]);
	});
});

describe("remote code in model repositories", () => {
	it("AISC-005 flags trust_remote_code=True even for a trusted publisher", () => {
		expect(
			codeHits('m = AutoModel.from_pretrained("microsoft/phi-2", trust_remote_code=True)'),
		).toEqual(["AISC-005"]);
		expect(codeHits('kwargs = {"trust_remote_code": True}')).toEqual(["AISC-005"]);
	});

	it("AISC-005 benign twins", () => {
		expect(codeHits('m = AutoModel.from_pretrained("bert-base-uncased")')).toEqual([]);
		expect(codeHits('m = AutoModel.from_pretrained("acme/x", trust_remote_code=False)')).toEqual(
			[],
		);
	});

	it("AISC-007 blocks trust_remote_code=True from an unvetted publisher", () => {
		expect(
			codeHits(
				'm = AutoModelForCausalLM.from_pretrained("randomuser/cool-model", trust_remote_code=True)',
			),
		).toEqual(["AISC-005", "AISC-007"]);
		expect(
			codeHits(
				'm = AutoModel.from_pretrained(\n    "randomuser/cool-model",\n    revision="main",\n    trust_remote_code=True,\n)',
			),
		).toEqual(["AISC-005", "AISC-007"]);
		expect(
			codeHits('p = pipeline("text-generation", model="randomuser/x", trust_remote_code=True)'),
		).toEqual(["AISC-005", "AISC-007"]);
	});

	it("AISC-007 is suppressed for a trusted or operator-trusted organisation", async () => {
		expect(
			codeHits('m = AutoModel.from_pretrained("Qwen/Qwen2-7B", trust_remote_code=True)'),
		).toEqual(["AISC-005"]);
		const extended = await loadTrustedModelSources(ALLOWLISTS_DIR, {
			trusted_model_orgs: ["RandomUser"],
		});
		expect(
			codeHits(
				'm = AutoModel.from_pretrained("randomuser/cool-model", trust_remote_code=True)',
				"python",
				extended,
			),
		).toEqual(["AISC-005"]);
	});

	it("AISC-006 / AISC-008 flag --trust-remote-code on the command line", () => {
		expect(commandHits("vllm serve microsoft/phi-2 --trust-remote-code")).toEqual(["AISC-006"]);
		expect(commandHits("vllm serve randomuser/model --trust-remote-code")).toEqual([
			"AISC-006",
			"AISC-008",
		]);
		expect(
			commandHits("lm_eval --model hf --model_args pretrained=acme/x,trust_remote_code=True"),
		).toEqual(["AISC-006", "AISC-008"]);
		expect(commandHits("vllm serve meta-llama/Llama-3.1-8B-Instruct")).toEqual([]);
	});
});

describe("unvetted model sources", () => {
	it("AISC-012 flags hub downloads from organisations outside the trusted list", () => {
		expect(commandHits("huggingface-cli download randomuser/model --local-dir ./m")).toEqual([
			"AISC-012",
		]);
		expect(commandHits("hf download randomuser/model")).toEqual(["AISC-012"]);
		expect(
			codeHits('p = hf_hub_download(repo_id="randomuser/model", filename="model.safetensors")'),
		).toEqual(["AISC-012"]);
	});

	it("AISC-012 benign twins: trusted organisations", () => {
		expect(commandHits("huggingface-cli download meta-llama/Llama-3.1-8B-Instruct")).toEqual([]);
		expect(commandHits("huggingface-cli download --repo-type model Qwen/Qwen2-7B")).toEqual([]);
		expect(codeHits('snapshot_download("google/gemma-2b")')).toEqual([]);
	});

	it("AISC-012: a trusted download listed first does not hide an untrusted one", () => {
		expect(
			commandHits(
				"huggingface-cli download meta-llama/Llama-3.1-8B && huggingface-cli download randomuser/evil",
			),
		).toEqual(["AISC-012"]);
		expect(
			codeHits('snapshot_download("google/gemma-2b")\nsnapshot_download("randomuser/evil")'),
		).toEqual(["AISC-012"]);
	});

	it("AISC-013 flags weight files from hosts outside the trusted hubs", () => {
		expect(commandHits("curl -L -o model.pt https://files.example/models/model.pt")).toEqual([
			"AISC-013",
		]);
		// A trusted hub host is only as trusted as the repository on it.
		expect(
			commandHits("wget https://huggingface.co/randomuser/x/resolve/main/pytorch_model.bin"),
		).toEqual(["AISC-013"]);
		expect(codeHits('urlretrieve("https://files.example/m.ckpt", "m.ckpt")')).toEqual(["AISC-013"]);
	});

	it("AISC-013 benign twins: trusted hubs, safetensors and non-model binaries", () => {
		expect(
			commandHits("curl -L -o model.pt https://huggingface.co/meta-llama/x/resolve/main/model.pt"),
		).toEqual([]);
		expect(
			commandHits("curl -O https://download.pytorch.org/models/resnet50-0676ba61.pth"),
		).toEqual([]);
		expect(commandHits("curl -O https://files.example/model.safetensors")).toEqual([]);
		expect(commandHits("curl -O https://files.example/firmware.bin")).toEqual([]);
	});

	it("AISC-014 flags plain-HTTP weight downloads even from a trusted host", () => {
		expect(commandHits("wget http://download.pytorch.org/models/resnet.pth")).toEqual(["AISC-014"]);
		expect(commandHits("wget https://download.pytorch.org/models/resnet.pth")).toEqual([]);
	});
});

describe("trusted model sources", () => {
	it("loads the shipped hubs and organisations plus configured additions", async () => {
		expect(sources.orgs.has("meta-llama")).toBe(true);
		expect(sources.orgs.has("qwen")).toBe(true);
		expect(sources.hosts).toContain("huggingface.co");
		const extended = await loadTrustedModelSources(ALLOWLISTS_DIR, {
			trusted_model_orgs: ["my-org", "not a valid org!"],
			trusted_model_hosts: ["*.models.example.com", "bad host"],
		});
		expect(extended.orgs.has("my-org")).toBe(true);
		expect(extended.orgs.has("not a valid org!")).toBe(false);
		expect(extended.hosts).toContain("models.example.com");
	});

	it("trusts nothing when the list is missing (the conservative direction)", async () => {
		const empty = await loadTrustedModelSources(await makeTmpDir());
		expect(empty.orgs.size).toBe(0);
		expect(isTrustedModelSourceMatch("AISC-012", "hf download meta-llama/x", empty)).toBe(false);
	});

	it("does not let model hubs suppress pipe-to-shell installer rules", async () => {
		const { loadTrustedDomains } = await import("../trusted-domains.js");
		const domains = await loadTrustedDomains(ALLOWLISTS_DIR);
		expect(domains.map((entry) => entry.domain)).not.toContain("huggingface.co");
	});

	it("reads publishers only from repository slots, never from other paths", () => {
		expect(
			modelRepoOrgs(
				'from_pretrained("randomuser/x", cache_dir="models/cache", trust_remote_code=True)',
			),
		).toEqual(["randomuser"]);
		expect(modelRepoOrgs("huggingface-cli download --repo-type model Qwen/Qwen2-7B")).toEqual([
			"qwen",
		]);
		expect(isTrustedModelSourceMatch("AISC-001", "torch.load(", sources)).toBe(false);
	});
});

describe("runtime verdicts", () => {
	afterEach(() => {
		vi.unstubAllEnvs();
	});

	async function configFor(
		extra: Record<string, unknown> = {},
	): Promise<{ dir: string; path: string }> {
		// State files (the audit log included) are confined to ~/.singularity-aidr,
		// so each configuration gets its own home.
		const dir = await makeTmpDir();
		vi.stubEnv("HOME", dir);
		const path = join(dir, "config.json");
		await writeFile(
			path,
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
		return { dir, path };
	}

	async function evaluate(
		toolName: string,
		toolInput: Record<string, unknown>,
		configPath: string,
	) {
		const userThreatsDir = join(await makeTmpDir(), "threats");
		await mkdir(userThreatsDir, { recursive: true });
		return evaluateToolCall(
			{
				sessionId: "ai-supply-chain",
				toolName,
				toolInput,
				artifacts: extractFromToolCall(toolName, toolInput),
			},
			{ threatsDir: THREATS_DIR, allowlistsDir: ALLOWLISTS_DIR, configPath, userThreatsDir },
		);
	}

	it("asks before an agent writes torch.load without weights_only=True", async () => {
		const { path } = await configFor();
		const verdict = await evaluate(
			"Write",
			{ file_path: "/work/train.py", content: 'import torch\nmodel = torch.load("model.pt")\n' },
			path,
		);
		expect(verdict.decision).toBe("ask");
		expect(verdict.matchedThreatId).toBe("AISC-001");
		expect(verdict.reasons.join(" ")).toMatch(/safetensors/);
		expect(verdict.artifacts[0]).toContain("/work/train.py");
	});

	it("allows the safe twin", async () => {
		const { path } = await configFor();
		const verdict = await evaluate(
			"Write",
			{
				file_path: "/work/train.py",
				content: 'import torch\nmodel = torch.load("model.pt", weights_only=True)\n',
			},
			path,
		);
		expect(verdict.decision).toBe("allow");
	});

	it("denies unpickling a network response", async () => {
		const { path } = await configFor();
		const verdict = await evaluate(
			"Write",
			{ file_path: "/work/load.py", content: "obj = pickle.loads(requests.get(url).content)\n" },
			path,
		);
		expect(verdict.decision).toBe("deny");
		expect(verdict.matchedThreatId).toBe("AISC-003");
	});

	it("denies trust_remote_code from an unvetted publisher, asks for a trusted one", async () => {
		const { path } = await configFor();
		const untrusted = await evaluate(
			"Edit",
			{
				file_path: "/work/model.py",
				old_string: "model = None",
				new_string: 'model = AutoModel.from_pretrained("randomuser/x", trust_remote_code=True)',
			},
			path,
		);
		expect(untrusted.decision).toBe("deny");
		expect(untrusted.matchedThreatId).toBe("AISC-007");
		const trusted = await evaluate(
			"Edit",
			{
				file_path: "/work/model.py",
				old_string: "model = None",
				new_string: 'model = AutoModel.from_pretrained("microsoft/phi-2", trust_remote_code=True)',
			},
			path,
		);
		expect(trusted.decision).toBe("ask");
		expect(trusted.matchedThreatId).toBe("AISC-005");
	});

	it("asks for a hub download from an unvetted organisation unless the operator trusts it", async () => {
		const { path } = await configFor();
		const command = "huggingface-cli download randomuser/model --local-dir ./models";
		const asked = await evaluate("Bash", { command }, path);
		expect(asked.decision).toBe("ask");
		expect(asked.matchedThreatId).toBe("AISC-012");

		expect(
			(
				await evaluate(
					"Bash",
					{ command: "huggingface-cli download meta-llama/Llama-3.1-8B" },
					path,
				)
			).decision,
		).toBe("allow");

		const trusted = await configFor({ ai_supply_chain: { trusted_model_orgs: ["randomuser"] } });
		expect((await evaluate("Bash", { command }, trusted.path)).decision).toBe("allow");
	});

	it("honours disabled_threats for code rules", async () => {
		const { path, dir } = await configFor({ disabled_threats: ["AISC-001"] });
		const verdict = await evaluate(
			"Write",
			{ file_path: "/work/train.py", content: 'model = torch.load("model.pt")\n' },
			path,
		);
		expect(verdict.decision).toBe("allow");
		// An allowed call with no findings is not written to the audit log.
		await expect(readFile(join(dir, ".singularity-aidr", "audit.jsonl"), "utf8")).rejects.toThrow();
	});
});
