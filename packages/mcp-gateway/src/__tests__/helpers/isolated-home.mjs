import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Import this module first: the core evaluator reads ~/.singularity-aidr for
// its agent config and writes its audit log there, so tests must not touch the
// developer's real home directory.
const home = mkdtempSync(join(tmpdir(), "aidr-mcp-gateway-home-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.once("exit", () => rmSync(home, { recursive: true, force: true }));
