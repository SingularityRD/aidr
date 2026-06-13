import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { parse as parseYaml } from "yaml";

async function test() {
  const tmpDir = await mkdtemp(join(tmpdir(), "aidr-test-"));
  const threatsDir = join(tmpDir, "threats");
  await mkdir(threatsDir);

  const threatsYaml = [
    "- id: CLT-TEST-001",
    "  category: command",
    "  severity: critical",
    "  confidence: 0.95",
    "  action: block",
    '  pattern: "rm -rf /"',
    "  match_on: [command]",
    '  title: "Destructive filesystem deletion"',
    "",
    "- id: CLT-TEST-002",
    "  category: network_egress",
    "  severity: high",
    "  confidence: 0.9",
    "  action: require_approval",
    '  pattern: "malicious\\.test"',
    "  match_on: [url]",
    '  title: "Known malicious domain"',
  ].join("\n");

  await writeFile(join(threatsDir, "test-threats.yaml"), threatsYaml);

  const files = await readdir(threatsDir);
  console.log("Files:", files);

  const content = await readFile(join(threatsDir, "test-threats.yaml"), "utf-8");
  console.log("Content:", JSON.stringify(content));

  const parsed = parseYaml(content);
  console.log("Parsed:", JSON.stringify(parsed, null, 2));

  // Now try with the actual load function
  try {
    // Dynamically import
    const loader = await import("./packages/core/src/threat-loader.ts");
    const threats = await loader.loadThreats(threatsDir);
    console.log("Loaded threats:", threats.length);
    if (threats.length > 0) {
      console.log("First threat:", JSON.stringify(threats[0], (key, val) => {
        if (key === "compiledPattern") return val ? val.toString() : val;
        return val;
      }, 2));
    }
  } catch (e) {
    console.error("Loader error:", e.message);
  }

  await rm(tmpDir, { recursive: true, force: true });
}

test().catch(console.error);
